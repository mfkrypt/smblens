// Package smbclient wraps the SMB2 client with the operations SMBLens needs:
// authentication, share enumeration with access probing, browsing, transfers,
// recursive walks, and security description retrieval.
package smbclient

import (
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

// AuthMethod selects how SMBLens authenticates to the server.
type AuthMethod string

const (
	// AuthPassword authenticates with a plaintext password (NTLMv2 on the wire).
	AuthPassword AuthMethod = "password"
	// AuthHash authenticates with an NT hash (pass-the-hash).
	AuthHash AuthMethod = "hash"
	// AuthKerberos authenticates with a Kerberos service ticket.
	AuthKerberos AuthMethod = "kerberos"
)

// Valid reports whether m is one of the supported authentication methods.
func (m AuthMethod) Valid() bool {
	switch m {
	case AuthPassword, AuthHash, AuthKerberos:
		return true
	}
	return false
}

// KerberosSource selects where Kerberos credentials come from.
type KerberosSource string

const (
	KerbPassword KerberosSource = "password"
	KerbCCache   KerberosSource = "ccache"
	KerbKeytab   KerberosSource = "keytab"
)

// Config describes one SMB connection.
type Config struct {
	Host string // hostname or IP address
	Port int    // TCP port, normally 445

	// Share and Path optionally open a share (and directory) right after
	// connecting instead of showing the share list.
	Share string
	Path  string

	Auth           AuthMethod
	KerberosSource KerberosSource
	Username       string
	Domain         string
	Password       string
	NTHash         string
	Realm          string
	KDC            string
	SPN            string
	CCachePath     string
	KeytabPath     string
	Krb5ConfPath   string

	ConnectTimeout time.Duration
	OpTimeout      time.Duration
}

// Address returns host:port suitable for net.Dial.
func (c Config) Address() string {
	port := c.Port
	if port == 0 {
		port = 445
	}
	return net.JoinHostPort(c.Host, fmt.Sprint(port))
}

// UserLabel identifies the account for display, without exposing secrets.
func (c Config) UserLabel() string {
	user := c.Username
	if user == "" {
		return "(anonymous)"
	}
	if c.Domain != "" && c.Domain != "." && !strings.ContainsAny(user, `\@`) {
		return c.Domain + `\` + user
	}
	return user
}

// ShareKind is the kind of resource a share exposes.
type ShareKind string

// Share kinds reported by the server service.
const (
	ShareDisk    ShareKind = "disk"
	SharePrint   ShareKind = "print"
	ShareDevice  ShareKind = "device"
	ShareIPC     ShareKind = "ipc"
	ShareUnknown ShareKind = "other"
)

// AccessState is the result of probing one share.
//
// SMB has no request that returns share-level permissions directly, and the
// NTFS ACL on the share root does not account for share permissions. The
// honest answer comes from trying: mount the share, list its root, and (unless
// disabled) create, write and delete a uniquely named probe file.
type AccessState struct {
	Mounted     bool
	Read        bool
	Write       bool
	WriteTested bool
	Denied      bool
	Note        string
	Err         error
}

// Label summarises the access state in at most two characters.
func (a AccessState) Label() string {
	if !a.Mounted {
		switch {
		case a.Denied:
			return "DENIED"
		case a.Err != nil:
			return "ERROR"
		default:
			return "-"
		}
	}
	read, write := "R", "W"
	if !a.Read {
		read = ""
	}
	if !a.Write {
		write = ""
	}
	if read+write == "" {
		return "-"
	}
	if !a.WriteTested && read != "" {
		return read + "*" // "*" = write access was not tested
	}
	return read + write
}

// ShareInfo is one share as returned by the server, plus its probe result.
type ShareInfo struct {
	Name      string
	Comment   string
	Kind      ShareKind
	Special   bool // IPC$, ADMIN$, C$, and other administrative shares
	Temporary bool
	Access    AccessState
}

// Entry is one directory entry, share-relative.
type Entry struct {
	Name    string
	Path    string // share-relative, slash separated
	Dir     bool
	Symlink bool
	Hidden  bool
	Size    int64
	ModTime time.Time
	Mode    os.FileMode
}

// IsSpecial reports whether the entry is a reparse point or other special
// object that SMBLens deliberately does not follow.
func (e Entry) IsSpecial() bool {
	return e.Mode&os.ModeIrregular != 0
}

// JoinPath joins share-relative path elements with forward slashes and
// cleans the result. The empty string denotes the share root.
func JoinPath(elem ...string) string {
	parts := make([]string, 0, len(elem))
	for _, e := range elem {
		// Do not trim spaces: they are legal and significant in SMB names.
		e = strings.Trim(e, `/\`)
		if e == "" {
			continue
		}
		parts = append(parts, e)
	}
	if len(parts) == 0 {
		return ""
	}
	joined := path.Clean(strings.Join(parts, "/"))
	if joined == "." {
		return ""
	}
	return strings.TrimPrefix(joined, "/")
}

// ParentPath returns the parent of a share-relative path.
func ParentPath(p string) string {
	p = JoinPath(p)
	if p == "" {
		return ""
	}
	parent := path.Dir(p)
	if parent == "." {
		return ""
	}
	return parent
}

// BaseName returns the final element of a share-relative path.
func BaseName(p string) string {
	return path.Base(JoinPath(p))
}
