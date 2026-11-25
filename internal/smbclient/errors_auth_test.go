package smbclient

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cloudsoda/go-smb2"
)

// TestParseNTHash covers all accepted NT hash forms and rejects malformed values.
func TestParseNTHash(t *testing.T) {
	valid := []string{
		"0123456789abcdef0123456789abcdef",
		"0123456789ABCDEF0123456789ABCDEF",
		"0x0123456789abcdef0123456789abcdef",
		"aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef",
	}
	for _, input := range valid {
		hash, err := ParseNTHash(input)
		if err != nil {
			t.Fatalf("ParseNTHash(%q): %v", input, err)
		}
		if len(hash) != 16 {
			t.Fatalf("ParseNTHash(%q) returned %d bytes", input, len(hash))
		}
	}

	invalid := []string{
		"",
		"deadbeef",
		"zz23456789abcdef0123456789abcdef",
		"0123456789abcdef0123456789abcde",
	}
	for _, input := range invalid {
		if _, err := ParseNTHash(input); err == nil {
			t.Fatalf("ParseNTHash(%q) should fail", input)
		}
	}
}

// TestSplitIdentity checks DOMAIN\user, UPN, explicit-domain and local-account defaults.
func TestSplitIdentity(t *testing.T) {
	cases := []struct {
		user, domain      string
		wantUser, wantDom string
	}{
		{`CORP\alice`, "", "alice", "CORP"},
		{`CORP\alice`, "OTHER", "alice", "CORP"},
		{"alice@corp.example.com", "", "alice", "corp.example.com"},
		{"alice", "CORP", "alice", "CORP"},
		{"alice", "", "alice", "."},
		{"", "", "", "."},
	}
	for _, c := range cases {
		user, domain := SplitIdentity(c.user, c.domain)
		if user != c.wantUser || domain != c.wantDom {
			t.Fatalf("SplitIdentity(%q, %q) = (%q, %q), want (%q, %q)",
				c.user, c.domain, user, domain, c.wantUser, c.wantDom)
		}
	}
}

// TestDescribeCapitalisesWithoutBreakingUnicode verifies first-rune capitalisation of wrapped errors.
func TestDescribeCapitalisesWithoutBreakingUnicode(t *testing.T) {
	got := Describe(errors.New("échec inattendu"))
	if !strings.HasPrefix(got, "Échec") {
		t.Fatalf("Describe = %q", got)
	}
}

// TestIsAuthError distinguishes authentication failures from access-denied and network errors.
func TestIsAuthError(t *testing.T) {
	if !IsAuthError(&smb2.ResponseError{Code: statusAccountLockedOut}) {
		t.Fatal("a locked account should count as an auth error")
	}
	if IsAuthError(&smb2.ResponseError{Code: statusAccessDenied}) {
		t.Fatal("access denied is not an authentication failure")
	}
	if !IsAuthError(errors.New("Kerberos login failed: KDC_ERR_PREAUTH_FAILED")) {
		t.Fatal("a Kerberos failure should count as an auth error")
	}
	if IsAuthError(errors.New("connection refused")) {
		t.Fatal("a network error is not an auth error")
	}
}

// TestDescribeAuthenticationFailure checks the summary, hint and NTSTATUS detail for a logon failure.
func TestDescribeAuthenticationFailure(t *testing.T) {
	err := &smb2.ResponseError{Code: statusLogonFailure}
	got := Describe(err)
	if !strings.Contains(got, "Authentication failed") {
		t.Fatalf("Describe = %q", got)
	}
	if !strings.Contains(Hint(err), "domain") {
		t.Fatalf("Hint = %q", Hint(err))
	}
	if !strings.Contains(Details(err), "STATUS_LOGON_FAILURE") {
		t.Fatalf("Details = %q", Details(err))
	}
}

// TestDescribeAccessDeniedThroughWrapping checks that wrapped path errors are unwrapped for access-denied handling.
func TestDescribeAccessDeniedThroughWrapping(t *testing.T) {
	inner := &os.PathError{Op: "open", Path: "secret.txt", Err: &smb2.ResponseError{Code: statusAccessDenied}}
	err := errors.New("outer")
	err = wrapErr(err, inner)
	if !IsPermission(err) {
		t.Fatal("wrapped access-denied error not recognised")
	}
	if got := Describe(err); !strings.Contains(got, "Access denied") {
		t.Fatalf("Describe = %q", got)
	}
	if got := Details(err); !strings.Contains(got, "STATUS_ACCESS_DENIED") {
		t.Fatalf("Details = %q", got)
	}
}

// wrapErr wraps inner in a custom error whose Unwrap exposes it, for testing error chains.
func wrapErr(outer, inner error) error {
	return &wrapped{outer: outer, inner: inner}
}

type wrapped struct {
	outer, inner error
}

// Error returns the combined outer and inner message.
func (w *wrapped) Error() string { return w.outer.Error() + ": " + w.inner.Error() }

// Unwrap exposes the inner error so errors.Is and errors.As can traverse the chain.
func (w *wrapped) Unwrap() error { return w.inner }

// TestDescribeKerberosErrors checks clock-skew advice for KRB_AP_ERR_SKEW.
func TestDescribeKerberosErrors(t *testing.T) {
	err := errors.New("Kerberos login failed: KRB_AP_ERR_SKEW")
	got := Describe(err)
	if !strings.Contains(strings.ToLower(got), "clock") {
		t.Fatalf("Describe = %q, want clock-skew advice", got)
	}
	if !strings.Contains(Hint(err), "NTP") {
		t.Fatalf("Hint = %q", Hint(err))
	}
}

// TestDescribeContextAndNetworkErrors checks timeout, missing-path and bad-share descriptions.
func TestDescribeContextAndNetworkErrors(t *testing.T) {
	if got := Describe(context.DeadlineExceeded); !strings.Contains(got, "Timed out") {
		t.Fatalf("Describe(deadline) = %q", got)
	}
	if got := Describe(&os.PathError{Op: "open", Path: "x", Err: os.ErrNotExist}); !strings.Contains(got, "does not exist") {
		t.Fatalf("Describe(not exist) = %q", got)
	}
	if got := Describe(&smb2.ResponseError{Code: statusBadNetworkName}); !strings.Contains(got, "share does not exist") {
		t.Fatalf("Describe(bad share) = %q", got)
	}
}

// TestIsConnectionLost checks the transport and NTSTATUS errors classified as a lost session.
func TestIsConnectionLost(t *testing.T) {
	cases := []error{
		ErrConnectionLost,
		io.EOF,
		io.ErrUnexpectedEOF,
		&smb2.TransportError{Err: errors.New("reset by peer")},
		&smb2.ResponseError{Code: statusConnectionDropped},
	}
	for _, err := range cases {
		if !IsConnectionLost(err) {
			t.Fatalf("IsConnectionLost(%v) = false, want true", err)
		}
	}
	if IsConnectionLost(&smb2.ResponseError{Code: statusAccessDenied}) {
		t.Fatal("access denied must not be treated as a lost connection")
	}
}

// TestIsNotFound checks the NTSTATUS values classified as a missing object or share.
func TestIsNotFound(t *testing.T) {
	if !IsNotFound(&smb2.ResponseError{Code: statusObjectNameNotFound}) {
		t.Fatal("STATUS_OBJECT_NAME_NOT_FOUND not recognised")
	}
	if !IsNotFound(&smb2.ResponseError{Code: statusBadNetworkName}) {
		t.Fatal("STATUS_BAD_NETWORK_NAME not recognised")
	}
	if IsNotFound(&smb2.ResponseError{Code: statusAccessDenied}) {
		t.Fatal("access denied must not be treated as not-found")
	}
}

// TestStatusOfUnwrapsPathErrors verifies that statusOf finds an NTSTATUS inside an os.PathError.
func TestStatusOfUnwrapsPathErrors(t *testing.T) {
	err := &os.PathError{Op: "open", Path: "x", Err: &smb2.ResponseError{Code: statusAccountLockedOut}}
	code, ok := statusOf(err)
	if !ok || code != statusAccountLockedOut {
		t.Fatalf("statusOf = 0x%X, %v", code, ok)
	}
	if !strings.Contains(Describe(err), "locked") {
		t.Fatalf("Describe = %q", Describe(err))
	}
}
