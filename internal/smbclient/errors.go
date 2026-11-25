package smbclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/cloudsoda/go-smb2"
)

// Sentinel errors returned by this package.
var (
	ErrSessionClosed  = errors.New("the SMB session is closed")
	ErrConnectionLost = errors.New("the connection to the server was lost")
)

// NT status codes used for friendly error messages. Values are from [MS-ERREF].
const (
	statusAccessDenied        = 0xC0000022
	statusNoSuchUser          = 0xC0000064
	statusWrongPassword       = 0xC000006A
	statusLogonFailure        = 0xC000006D
	statusAccountRestriction  = 0xC000006E
	statusInvalidLogonHours   = 0xC000006F
	statusInvalidWorkstation  = 0xC0000070
	statusPasswordExpired     = 0xC0000071
	statusAccountDisabled     = 0xC0000072
	statusDiskFull            = 0xC000007F
	statusMediaWriteProtected = 0xC00000A2
	statusFileIsDirectory     = 0xC00000BA
	statusNotSupported        = 0xC00000BB
	statusBadNetworkName      = 0xC00000CC
	statusNetworkNameDeleted  = 0xC00000C9
	statusSharingViolation    = 0xC0000043
	statusDeletePending       = 0xC0000056
	statusCannotDelete        = 0xC0000121
	statusLogonTypeNotGranted = 0xC000015B
	statusAccountExpired      = 0xC0000193
	statusUserSessionDeleted  = 0xC0000203
	statusConnectionDropped   = 0xC000020C
	statusPasswordMustChange  = 0xC0000224
	statusAccountLockedOut    = 0xC0000234
	statusObjectNameNotFound  = 0xC0000034
	statusObjectNameCollision = 0xC0000035
	statusObjectPathNotFound  = 0xC000003A
	statusObjectNameInvalid   = 0xC0000033
	statusDirectoryNotEmpty   = 0xC0000101
	statusNotADirectory       = 0xC0000103
)

// ntStatusMessages maps an NTSTATUS to a user-facing explanation. The wording
// avoids jargon where the plain meaning is obvious, but keeps the status name
// in the details view.
var ntStatusMessages = map[uint32]string{
	statusAccessDenied:        "Access denied: this account does not have the required permission.",
	statusNoSuchUser:          "Authentication failed: no such user.",
	statusWrongPassword:       "Authentication failed: wrong password.",
	statusLogonFailure:        "Authentication failed: wrong username, password or domain.",
	statusAccountRestriction:  "Authentication failed: the account is restricted (for example, it may be disabled for network logon).",
	statusInvalidLogonHours:   "Authentication failed: this account is not allowed to log on at this time.",
	statusInvalidWorkstation:  "Authentication failed: this account is not allowed to log on from this computer.",
	statusPasswordExpired:     "Authentication failed: the password has expired.",
	statusAccountDisabled:     "Authentication failed: the account is disabled.",
	statusDiskFull:            "The server volume is full.",
	statusMediaWriteProtected: "The target is write-protected.",
	statusFileIsDirectory:     "That path is a folder, not a file.",
	statusNotSupported:        "The server does not support this operation.",
	statusBadNetworkName:      "The share does not exist on this server.",
	statusNetworkNameDeleted:  "The share has been deleted on the server.",
	statusSharingViolation:    "The file is in use by another program.",
	statusDeletePending:       "The file is pending deletion and cannot be opened yet.",
	statusCannotDelete:        "The file cannot be deleted; it may be read-only or locked.",
	statusLogonTypeNotGranted: "Authentication failed: the account is not granted the requested logon type.",
	statusAccountExpired:      "Authentication failed: the account has expired.",
	statusUserSessionDeleted:  "The SMB session is no longer valid. Reconnect to continue.",
	statusConnectionDropped:   "The server closed the connection.",
	statusPasswordMustChange:  "Authentication failed: the password must be changed before logging on.",
	statusAccountLockedOut:    "Authentication failed: the account is locked out.",
	statusObjectNameNotFound:  "The file or folder does not exist.",
	statusObjectPathNotFound:  "The folder in that path does not exist.",
	statusObjectNameCollision: "An item with that name already exists.",
	statusObjectNameInvalid:   "The name is not valid on this server.",
	statusDirectoryNotEmpty:   "The folder is not empty. Delete its contents first.",
	statusNotADirectory:       "That path is not a folder.",
}

// statusOf extracts an SMB NTSTATUS from err, if there is one.
func statusOf(err error) (uint32, bool) {
	var resp *smb2.ResponseError
	if errors.As(err, &resp) {
		return resp.Code, true
	}
	return 0, false
}

// hasStatus reports whether err carries the given NTSTATUS code.
func hasStatus(err error, code uint32) bool {
	got, ok := statusOf(err)
	return ok && got == code
}

// IsPermission reports whether err is an access-denied error, from either the
// SMB layer or the standard library's os.ErrPermission translation.
func IsPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || hasStatus(err, statusAccessDenied)
}

// IsAuthError reports whether err looks like an authentication or account
// problem, as opposed to a network or permission problem.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	if isKerberosError(err) {
		return true
	}
	code, ok := statusOf(err)
	if !ok {
		return false
	}
	switch code {
	case statusNoSuchUser, statusWrongPassword, statusLogonFailure,
		statusAccountRestriction, statusInvalidLogonHours, statusInvalidWorkstation,
		statusPasswordExpired, statusAccountDisabled, statusLogonTypeNotGranted,
		statusAccountExpired, statusPasswordMustChange, statusAccountLockedOut:
		return true
	}
	return false
}

// IsNotFound reports whether err means a file, folder or share is missing.
func IsNotFound(err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	code, ok := statusOf(err)
	return ok && (code == statusObjectNameNotFound || code == statusObjectPathNotFound || code == statusBadNetworkName)
}

// IsConnectionLost reports whether err means the underlying session is gone
// and a reconnect is required.
func IsConnectionLost(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrConnectionLost) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	var transport *smb2.TransportError
	if errors.As(err, &transport) {
		return true
	}
	code, ok := statusOf(err)
	return ok && (code == statusConnectionDropped || code == statusUserSessionDeleted || code == statusNetworkNameDeleted)
}

// Describe renders err as a short, human sentence suitable for a status line.
func Describe(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "Operation cancelled."
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "Timed out waiting for the server."
	}
	if isKerberosError(err) {
		return describeKerberos(err)
	}
	if code, ok := statusOf(err); ok {
		if msg, ok := ntStatusMessages[code]; ok {
			return msg
		}
		return fmt.Sprintf("The server returned an error (NTSTATUS 0x%08X).", code)
	}
	if errors.Is(err, os.ErrPermission) {
		return ntStatusMessages[statusAccessDenied]
	}
	if errors.Is(err, os.ErrNotExist) {
		return ntStatusMessages[statusObjectNameNotFound]
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Sprintf("Could not resolve %q: %s.", dnsErr.Name, dnsErr.Err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return "Connection refused. Is SMB running on that port, and is a firewall in the way?"
		}
		if errors.Is(opErr.Err, syscall.EHOSTUNREACH) || errors.Is(opErr.Err, syscall.ENETUNREACH) {
			return "The server is unreachable from this machine."
		}
		return fmt.Sprintf("Network error: %v.", opErr.Err)
	}
	if errors.Is(err, ErrSessionClosed) || errors.Is(err, ErrConnectionLost) {
		return "The connection to the server was lost. Reconnect to continue."
	}

	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "Unknown error."
	}
	// Wrapped errors read better with the first letter capitalised.
	first, size := utf8.DecodeRuneInString(msg)
	return string(unicode.ToUpper(first)) + msg[size:]
}

// Details renders err as a multi-line technical description, including the
// NTSTATUS name and a remediation hint when one is known.
func Details(err error) string {
	if err == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(err.Error())
	if code, ok := statusOf(err); ok {
		b.WriteString(fmt.Sprintf("\n\nNTSTATUS: 0x%08X", code))
		if name := ntStatusName(code); name != "" {
			b.WriteString(" (" + name + ")")
		}
	}
	if hint := Hint(err); hint != "" {
		b.WriteString("\n\nHint: " + hint)
	}
	return b.String()
}

// Hint returns a remediation suggestion for common failures, or "".
func Hint(err error) string {
	if err == nil {
		return ""
	}
	if isKerberosError(err) {
		if hint := kerberosHint(err); hint != "" {
			return hint
		}
	}
	switch code, _ := statusOf(err); code {
	case statusLogonFailure, statusWrongPassword, statusNoSuchUser:
		return "Check the username, domain and password. For AD accounts, the domain is usually the NetBIOS name (for example CORP) or the DNS name (corp.example.com)."
	case statusAccountLockedOut:
		return "Wait for the lockout to expire, or ask an administrator to unlock the account. Repeated attempts will extend the lockout."
	case statusAccountDisabled, statusAccountExpired, statusPasswordExpired, statusPasswordMustChange:
		return "The account's state prevents network logon. Ask an administrator to update it."
	case statusAccessDenied:
		return "Share permissions and the NTFS ACL both apply. Try another account, or check the share's ACL with the permissions view (p)."
	case statusBadNetworkName:
		return "The share name may be mistyped, or it may have been removed. Refresh the share list."
	case statusDirectoryNotEmpty:
		return "Remove the files and subfolders inside it first, then delete the folder."
	case statusObjectNameCollision:
		return "Choose another name, or delete the existing item first."
	case statusNotSupported:
		return "The server may require a newer SMB dialect, signing or encryption that this client could not negotiate."
	case statusUserSessionDeleted, statusConnectionDropped:
		return "Press esc to return to the connection screen, then reconnect."
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "The server did not answer in time. It may be offline, overloaded, or blocked by a firewall."
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "Use an IP address, a hostname resolvable through DNS, or add an entry to /etc/hosts."
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && errors.Is(opErr.Err, syscall.ECONNREFUSED) {
		return "Confirm the server is up and SMB (TCP 445) is reachable from this host."
	}
	return ""
}

// ntStatusName returns the symbolic NTSTATUS name used in technical error details.
func ntStatusName(code uint32) string {
	switch code {
	case statusAccessDenied:
		return "STATUS_ACCESS_DENIED"
	case statusNoSuchUser:
		return "STATUS_NO_SUCH_USER"
	case statusWrongPassword:
		return "STATUS_WRONG_PASSWORD"
	case statusLogonFailure:
		return "STATUS_LOGON_FAILURE"
	case statusAccountDisabled:
		return "STATUS_ACCOUNT_DISABLED"
	case statusAccountLockedOut:
		return "STATUS_ACCOUNT_LOCKED_OUT"
	case statusPasswordExpired:
		return "STATUS_PASSWORD_EXPIRED"
	case statusPasswordMustChange:
		return "STATUS_PASSWORD_MUST_CHANGE"
	case statusBadNetworkName:
		return "STATUS_BAD_NETWORK_NAME"
	case statusObjectNameNotFound:
		return "STATUS_OBJECT_NAME_NOT_FOUND"
	case statusObjectPathNotFound:
		return "STATUS_OBJECT_PATH_NOT_FOUND"
	case statusObjectNameCollision:
		return "STATUS_OBJECT_NAME_COLLISION"
	case statusObjectNameInvalid:
		return "STATUS_OBJECT_NAME_INVALID"
	case statusDirectoryNotEmpty:
		return "STATUS_DIRECTORY_NOT_EMPTY"
	case statusNotADirectory:
		return "STATUS_NOT_A_DIRECTORY"
	case statusFileIsDirectory:
		return "STATUS_FILE_IS_A_DIRECTORY"
	case statusSharingViolation:
		return "STATUS_SHARING_VIOLATION"
	case statusDiskFull:
		return "STATUS_DISK_FULL"
	case statusMediaWriteProtected:
		return "STATUS_MEDIA_WRITE_PROTECTED"
	case statusNotSupported:
		return "STATUS_NOT_SUPPORTED"
	case statusConnectionDropped:
		return "STATUS_CONNECTION_DISCONNECTED"
	case statusUserSessionDeleted:
		return "STATUS_USER_SESSION_DELETED"
	}
	return ""
}

// kerberosErrorHints maps fragments of gokrb5 error messages to advice.
var kerberosErrorHints = []struct {
	match string
	hint  string
}{
	{"KRB_AP_ERR_SKEW", "The client clock and the KDC clock differ by more than five minutes. Sync the clock (for example with NTP) and retry."},
	{"clock skew", "The client clock and the KDC clock differ by more than five minutes. Sync the clock (for example with NTP) and retry."},
	{"KDC_ERR_C_PRINCIPAL_UNKNOWN", "The KDC does not know this principal. Check the username, the realm (--realm), and that the account exists."},
	{"KDC_ERR_PREAUTH_FAILED", "Kerberos rejected the password during pre-authentication. Check the password."},
	{"KDC_ERR_S_PRINCIPAL_UNKNOWN", "The KDC does not have a service ticket for this server. Use the server's fully qualified DNS name, or set --spn explicitly (normally cifs/<server-fqdn>)."},
	{"KDC_ERR_ETYPE_NOSUPP", "The KDC does not support the encryption types requested. Check the account's Kerberos encryption settings."},
	{"failed to communicate with KDC", "The KDC could not be reached. Check --kdc (or the KDC entries in krb5.conf) and that UDP/TCP port 88 is open."},
	{"Cannot find KDC", "No KDC could be reached. Pass --kdc host[:port], or point --krb5-conf at a working krb5.conf."},
	{"no KDC", "No KDC could be reached. Pass --kdc host[:port], or point --krb5-conf at a working krb5.conf."},
	{"no such host", "A Kerberos hostname could not be resolved. Check DNS, or give the KDC as an IP address."},
	{"connection refused", "The KDC or the server refused the connection. Check the address and port, and that the service is running."},
	{"KRB_AP_ERR_MODIFIED", "The server could not validate the ticket. This usually means the service principal name is wrong; try the server's FQDN or set --spn."},
	{"response did not contain a valid KDC", "The KDC response could not be validated. Check the realm and KDC address."},
}

// isKerberosError reports whether err came from the Kerberos or SPNEGO layers.
func isKerberosError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "kerberos") || strings.Contains(msg, "krb_") ||
		strings.Contains(msg, "kdc") || strings.Contains(msg, "spnego") ||
		strings.Contains(msg, "gokrb5")
}

// describeKerberos turns a Kerberos error into a short sentence, preferring a known remediation hint.
func describeKerberos(err error) string {
	msg := err.Error()
	if hint := kerberosHint(err); hint != "" {
		return hint
	}
	if i := strings.Index(msg, "Kerberos"); i >= 0 {
		return "Kerberos authentication failed: " + msg[i:]
	}
	return "Kerberos authentication failed: " + msg
}

// kerberosHint matches a Kerberos error message against known failure modes and returns the matching advice.
func kerberosHint(err error) string {
	msg := err.Error()
	for _, h := range kerberosErrorHints {
		if strings.Contains(msg, h.match) {
			return h.hint
		}
	}
	return ""
}
