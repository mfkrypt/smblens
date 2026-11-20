package smbclient

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudsoda/go-smb2"
)

// SECURITY_DESCRIPTOR control flags.
const (
	seDACLPresent       = 0x0004
	seDACLProtected     = 0x1000
	seDACLAutoInherited = 0x0400
)

// SID is a Windows security identifier, with a human name when it is one of
// the well-known accounts.
type SID struct {
	Raw  string
	Name string
}

// Display renders a SID as "Name (S-1-...)" when a name is known.
func (s SID) Display() string {
	if s.Name == "" {
		return s.Raw
	}
	if s.Raw == "" {
		return s.Name
	}
	return s.Name + " (" + s.Raw + ")"
}

// ACE is one access-control entry from a discretionary ACL.
type ACE struct {
	Type        string // Allow, Deny, Audit, ...
	Allow       bool
	Deny        bool
	Object      bool
	Inherited   bool
	InheritOnly bool
	Flags       []string // OI, CI, NP, IO, ID, ...
	Mask        uint32
	Trustee     SID
}

// RightsSummary describes the permissions in the ACE's access mask.
func (a ACE) RightsSummary() string { return AccessMaskSummary(a.Mask) }

// FlagsSummary lists the ACE inheritance/audit flags.
func (a ACE) FlagsSummary() string { return strings.Join(a.Flags, " ") }

// SecurityDescriptor is the parsed form of a Windows security descriptor.
type SecurityDescriptor struct {
	Owner SID
	Group SID

	DACLPresent       bool
	DACLProtected     bool
	DACLAutoInherited bool
	// NullDACL means there is no DACL at all, which grants full access to
	// everyone. An empty (but present) DACL does the opposite.
	NullDACL bool
	ACEs     []ACE
}

// Permissions is a path's NTFS security descriptor.
type Permissions struct {
	Path       string
	Descriptor *SecurityDescriptor
	ShareName  string
	Host       string
}

// Permissions reads the owner, group and DACL of a path. It requires
// READ_CONTROL on that object; failing to read the ACL does not necessarily
// mean the data is inaccessible.
func (s *Share) Permissions(ctx context.Context, remotePath string) (*Permissions, error) {
	remotePath, err := cleanRemotePath(remotePath)
	if err != nil {
		return nil, err
	}

	var raw []byte
	err = s.do(ctx, s.client.cfg.OpTimeout, func(share *smb2.Share) error {
		got, err := share.SecurityInfoRaw(remotePath,
			smb2.OwnerSecurityInformation|smb2.GroupSecurityInformation|smb2.DACLSecurityInformation)
		if err != nil {
			return err
		}
		raw = got
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading permissions of %s: %w", s.displayPath(remotePath), err)
	}

	descriptor, err := ParseSecurityDescriptor(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing permissions of %s: %w", s.displayPath(remotePath), err)
	}
	return &Permissions{
		Path:       remotePath,
		Descriptor: descriptor,
		ShareName:  s.Name(),
		Host:       s.Host(),
	}, nil
}

// ParseSecurityDescriptor parses a self-relative SECURITY_DESCRIPTOR.
//
// The input comes from the server, so every offset is bounds-checked; malformed
// data produces an error rather than a panic.
func ParseSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
	if len(data) < 20 {
		return nil, errors.New("security descriptor is shorter than its 20-byte header")
	}

	control := binary.LittleEndian.Uint16(data[2:4])
	ownerOffset := binary.LittleEndian.Uint32(data[4:8])
	groupOffset := binary.LittleEndian.Uint32(data[8:12])
	daclOffset := binary.LittleEndian.Uint32(data[16:20])

	sd := &SecurityDescriptor{
		DACLPresent:       control&seDACLPresent != 0,
		DACLProtected:     control&seDACLProtected != 0,
		DACLAutoInherited: control&seDACLAutoInherited != 0,
	}

	if ownerOffset != 0 {
		sid, err := parseSIDAt(data, int(ownerOffset))
		if err != nil {
			return nil, fmt.Errorf("owner SID: %w", err)
		}
		sd.Owner = sid
	}
	if groupOffset != 0 {
		sid, err := parseSIDAt(data, int(groupOffset))
		if err != nil {
			return nil, fmt.Errorf("group SID: %w", err)
		}
		sd.Group = sid
	}

	if daclOffset == 0 {
		// No DACL pointer means a null DACL: everyone has full control. This
		// is also the interpretation when SE_DACL_PRESENT is clear.
		sd.NullDACL = true
		return sd, nil
	}

	aces, err := parseACL(data, int(daclOffset))
	if err != nil {
		return nil, fmt.Errorf("DACL: %w", err)
	}
	sd.ACEs = aces
	return sd, nil
}

func parseACL(data []byte, offset int) ([]ACE, error) {
	if offset < 0 || offset+8 > len(data) {
		return nil, errors.New("ACL header is outside the security descriptor")
	}
	aclSize := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
	aceCount := int(binary.LittleEndian.Uint16(data[offset+4 : offset+6]))
	if aclSize < 8 || offset+aclSize > len(data) {
		return nil, fmt.Errorf("ACL size %d is invalid", aclSize)
	}

	limit := offset + aclSize
	aces := make([]ACE, 0, aceCount)
	pos := offset + 8

	for i := 0; i < aceCount; i++ {
		if pos+4 > limit {
			return nil, errors.New("ACE header is truncated")
		}
		aceType := data[pos]
		aceFlags := data[pos+1]
		aceSize := int(binary.LittleEndian.Uint16(data[pos+2 : pos+4]))
		if aceSize < 8 || pos+aceSize > limit {
			return nil, fmt.Errorf("ACE %d has invalid size %d", i, aceSize)
		}

		mask := binary.LittleEndian.Uint32(data[pos+4 : pos+8])

		// Object ACEs insert a flags field and two GUIDs before the SID.
		sidOffset := 8
		object := isObjectACEType(aceType)
		if object {
			sidOffset = 8 + 4 + 16 + 16
		}
		if sidOffset >= aceSize {
			return nil, fmt.Errorf("ACE %d is too short for its type", i)
		}
		trustee, err := parseSIDAt(data[pos:pos+aceSize], sidOffset)
		if err != nil {
			return nil, fmt.Errorf("ACE %d trustee: %w", i, err)
		}

		ace := ACE{
			Type:        aceTypeName(aceType),
			Allow:       isAllowACEType(aceType),
			Deny:        isDenyACEType(aceType),
			Object:      object,
			Inherited:   aceFlags&0x10 != 0,
			InheritOnly: aceFlags&0x08 != 0,
			Flags:       aceFlagsList(aceFlags),
			Mask:        mask,
			Trustee:     trustee,
		}
		aces = append(aces, ace)
		pos += aceSize
	}
	return aces, nil
}

func parseSIDAt(data []byte, offset int) (SID, error) {
	if offset < 0 || offset+8 > len(data) {
		return SID{}, errors.New("SID header is outside the buffer")
	}
	revision := data[offset]
	count := int(data[offset+1])
	if revision != 1 {
		return SID{}, fmt.Errorf("unsupported SID revision %d", revision)
	}
	if count > 15 {
		return SID{}, fmt.Errorf("SID has %d sub-authorities (maximum 15)", count)
	}
	if offset+8+count*4 > len(data) {
		return SID{}, errors.New("SID sub-authorities are truncated")
	}

	var authority uint64
	for i := 0; i < 6; i++ {
		authority = authority<<8 | uint64(data[offset+2+i])
	}

	raw := "S-1-" + fmt.Sprint(authority)
	for i := 0; i < count; i++ {
		sub := binary.LittleEndian.Uint32(data[offset+8+i*4 : offset+12+i*4])
		raw += "-" + fmt.Sprint(sub)
	}

	return SID{Raw: raw, Name: sidName(raw)}, nil
}

func isObjectACEType(t byte) bool {
	switch t {
	case 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10:
		return true
	}
	return false
}

func isAllowACEType(t byte) bool {
	switch t {
	case 0x00, 0x05, 0x09, 0x0B:
		return true
	}
	return false
}

func isDenyACEType(t byte) bool {
	switch t {
	case 0x01, 0x06, 0x0A, 0x0C:
		return true
	}
	return false
}

func aceTypeName(t byte) string {
	switch t {
	case 0x00:
		return "Allow"
	case 0x01:
		return "Deny"
	case 0x02:
		return "Audit"
	case 0x03:
		return "Alarm"
	case 0x05:
		return "Allow (object)"
	case 0x06:
		return "Deny (object)"
	case 0x07:
		return "Audit (object)"
	case 0x08:
		return "Alarm (object)"
	case 0x09:
		return "Allow (callback)"
	case 0x0A:
		return "Deny (callback)"
	case 0x0B:
		return "Allow (object callback)"
	case 0x0C:
		return "Deny (object callback)"
	case 0x0D:
		return "Audit (callback)"
	case 0x11:
		return "Mandatory label"
	case 0x12:
		return "Resource attribute"
	case 0x13:
		return "Scoped policy"
	default:
		return fmt.Sprintf("Type 0x%02X", t)
	}
}

func aceFlagsList(flags byte) []string {
	var out []string
	for _, f := range []struct {
		bit  byte
		name string
	}{
		{0x01, "OI"}, // object inherit
		{0x02, "CI"}, // container inherit
		{0x04, "NP"}, // no propagate
		{0x08, "IO"}, // inherit only
		{0x10, "ID"}, // inherited
		{0x40, "SA"}, // successful audit
		{0x80, "FA"}, // failed audit
	} {
		if flags&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

// AccessMaskSummary renders a file/directory access mask in familiar terms.
func AccessMaskSummary(mask uint32) string {
	switch mask {
	case 0x00000000:
		return "None"
	case 0x001F01FF:
		return "Full control"
	case 0x001301BF:
		return "Modify"
	case 0x001200A9:
		return "Read & execute"
	case 0x00120089:
		return "Read"
	case 0x00120116:
		return "Write"
	case 0x001200A0:
		return "Execute"
	case 0x001F0000:
		return "Full control (standard rights only)"
	case 0x10000000:
		return "Generic all"
	case 0x80000000:
		return "Generic read"
	case 0x40000000:
		return "Generic write"
	case 0x20000000:
		return "Generic execute"
	}

	components := []struct {
		bit  uint32
		name string
	}{
		{0x10000000, "generic all"},
		{0x80000000, "generic read"},
		{0x40000000, "generic write"},
		{0x20000000, "generic execute"},
		{0x02000000, "maximum allowed"},
		{0x01000000, "access system security"},
		{0x00100000, "synchronize"},
		{0x00080000, "write owner"},
		{0x00040000, "write DAC"},
		{0x00020000, "read control"},
		{0x00010000, "delete"},
		{0x00000100, "write attributes"},
		{0x00000080, "read attributes"},
		{0x00000040, "delete child"},
		{0x00000020, "execute / traverse"},
		{0x00000010, "write extended attributes"},
		{0x00000008, "read extended attributes"},
		{0x00000004, "append data / add folder"},
		{0x00000002, "write data / add file"},
		{0x00000001, "read data / list folder"},
	}

	var parts []string
	remaining := mask
	for _, c := range components {
		if remaining&c.bit != 0 {
			parts = append(parts, c.name)
			remaining &^= c.bit
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%08X", mask)
	}
	if remaining != 0 {
		parts = append(parts, fmt.Sprintf("0x%08X", remaining))
	}
	return strings.Join(parts, ", ")
}

// sidNames maps well-known SIDs to readable names (MS-DTYP 2.4.2.4).
var sidNames = map[string]string{
	"S-1-0-0":      "Nobody",
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "Local",
	"S-1-3-0":      "Creator Owner",
	"S-1-3-1":      "Creator Group",
	"S-1-3-2":      "Creator Owner Server",
	"S-1-3-3":      "Creator Group Server",
	"S-1-5-2":      "Network",
	"S-1-5-4":      "Interactive",
	"S-1-5-6":      "Service",
	"S-1-5-7":      "Anonymous",
	"S-1-5-9":      "Enterprise Domain Controllers",
	"S-1-5-10":     "Self",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-18":     "Local System",
	"S-1-5-32-544": `BUILTIN\Administrators`,
	"S-1-5-32-545": `BUILTIN\Users`,
	"S-1-5-32-546": `BUILTIN\Guests`,
	"S-1-5-32-547": `BUILTIN\Power Users`,
	"S-1-5-32-548": `BUILTIN\Account Operators`,
	"S-1-5-32-549": `BUILTIN\Server Operators`,
	"S-1-5-32-550": `BUILTIN\Print Operators`,
	"S-1-5-32-551": `BUILTIN\Backup Operators`,
	"S-1-5-32-552": `BUILTIN\Replicator`,
	"S-1-5-32-554": `BUILTIN\Pre-Windows 2000 Compatible Access`,
	"S-1-5-32-555": `BUILTIN\Remote Desktop Users`,
	"S-1-5-32-556": `BUILTIN\Network Configuration Operators`,
	"S-1-5-32-558": `BUILTIN\Performance Monitor Users`,
	"S-1-5-32-559": `BUILTIN\Performance Log Users`,
	"S-1-5-32-562": `BUILTIN\Distributed COM Users`,
	"S-1-5-32-568": `BUILTIN\IIS_IUSRS`,
	"S-1-5-32-573": `BUILTIN\Event Log Readers`,
	"S-1-5-32-574": `BUILTIN\Certificate Service DCOM Access`,
	"S-1-5-113":    "Local account",
	"S-1-5-114":    "Local account (administrator)",
	"S-1-16-4096":  "Low mandatory level",
	"S-1-16-8192":  "Medium mandatory level",
	"S-1-16-8448":  "Medium plus mandatory level",
	"S-1-16-12288": "High mandatory level",
	"S-1-16-16384": "System mandatory level",
}

// sidRIDNames names well-known domain-group RIDs that appear at the end of a
// S-1-5-21-<domain>-<rid> SID.
var sidRIDNames = map[uint32]string{
	500: "Administrator",
	501: "Guest",
	502: "KRBTGT",
	512: "Domain Admins",
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
	517: "Cert Publishers",
	518: "Schema Admins",
	519: "Enterprise Admins",
	520: "Group Policy Creator Owners",
	521: "Read-only Domain Controllers",
	522: "Cloneable Domain Controllers",
	525: "Protected Users",
	526: "Key Admins",
	527: "Enterprise Key Admins",
	553: "RAS and IAS Servers",
	571: "Allowed RODC Password Replication Group",
	572: "Denied RODC Password Replication Group",
}

// sidName returns a friendly name for a SID, or "" if it is not well known.
func sidName(raw string) string {
	if name, ok := sidNames[raw]; ok {
		return name
	}
	if !strings.HasPrefix(raw, "S-1-5-21-") {
		return ""
	}
	parts := strings.Split(raw, "-")
	if len(parts) < 5 {
		return ""
	}
	var rid uint32
	if _, err := fmt.Sscan(parts[len(parts)-1], &rid); err != nil {
		return ""
	}
	if name, ok := sidRIDNames[rid]; ok {
		switch rid {
		case 500, 501, 502: // built-in user accounts
			return name
		}
		return name + " (domain group)"
	}
	return ""
}
