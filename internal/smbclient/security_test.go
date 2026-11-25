package smbclient

import (
	"encoding/binary"
	"strings"
	"testing"
)

// sidBytesWithAuthority builds a binary SID.
func sidBytesWithAuthority(authority uint64, subs ...uint32) []byte {
	b := make([]byte, 8+len(subs)*4)
	b[0] = 1
	b[1] = byte(len(subs))
	for i := 0; i < 6; i++ {
		b[2+i] = byte(authority >> (8 * (5 - i)))
	}
	for i, sub := range subs {
		binary.LittleEndian.PutUint32(b[8+i*4:], sub)
	}
	return b
}

// sidBytes builds a SID in the NT authority (5).
func sidBytes(subs ...uint32) []byte {
	return sidBytesWithAuthority(5, subs...)
}

// aceBytes builds a plain ACE with the given type, flags, mask and trustee SID.
func aceBytes(aceType, flags byte, mask uint32, trustee []byte) []byte {
	b := make([]byte, 8+len(trustee))
	b[0] = aceType
	b[1] = flags
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	binary.LittleEndian.PutUint32(b[4:], mask)
	copy(b[8:], trustee)
	return b
}

// objectACEBytes builds an object ACE, including the object flags and GUIDs before its trustee.
func objectACEBytes(aceType, flags byte, mask uint32, trustee []byte) []byte {
	b := make([]byte, 8+4+16+16+len(trustee))
	b[0] = aceType
	b[1] = flags
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	binary.LittleEndian.PutUint32(b[4:], mask)
	// Four bytes of object flags and two GUIDs are skipped when locating the
	// trustee.
	copy(b[44:], trustee)
	return b
}

// aclBytes builds a DACL header followed by the supplied ACEs.
func aclBytes(aces ...[]byte) []byte {
	size := 8
	for _, ace := range aces {
		size += len(ace)
	}
	b := make([]byte, size)
	b[0] = 2
	binary.LittleEndian.PutUint16(b[2:], uint16(size))
	binary.LittleEndian.PutUint16(b[4:], uint16(len(aces)))
	offset := 8
	for _, ace := range aces {
		copy(b[offset:], ace)
		offset += len(ace)
	}
	return b
}

// securityDescriptor assembles a self-relative security descriptor from optional owner, group and DACL parts.
func securityDescriptor(owner, group, dacl []byte) []byte {
	const header = 20
	total := header + len(owner) + len(group) + len(dacl)
	b := make([]byte, total)
	b[0] = 1
	control := uint16(0x8000) // SE_SELF_RELATIVE
	if dacl != nil {
		control |= 0x0004 // SE_DACL_PRESENT
	}
	binary.LittleEndian.PutUint16(b[2:], control)

	offset := header
	if owner != nil {
		binary.LittleEndian.PutUint32(b[4:], uint32(offset))
		copy(b[offset:], owner)
		offset += len(owner)
	}
	if group != nil {
		binary.LittleEndian.PutUint32(b[8:], uint32(offset))
		copy(b[offset:], group)
		offset += len(group)
	}
	if dacl != nil {
		binary.LittleEndian.PutUint32(b[16:], uint32(offset))
		copy(b[offset:], dacl)
	}
	return b
}

// TestParseSecurityDescriptor checks owner, group, allow/deny ACEs, masks and inheritance flags.
func TestParseSecurityDescriptor(t *testing.T) {
	owner := sidBytes(32, 544)           // BUILTIN\Administrators
	group := sidBytesWithAuthority(1, 0) // Everyone
	allow := aceBytes(0x00, 0x03, 0x001F01FF, sidBytesWithAuthority(1, 0))
	deny := aceBytes(0x01, 0x10, 0x00000001, owner)
	sd, err := ParseSecurityDescriptor(securityDescriptor(owner, group, aclBytes(allow, deny)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if sd.Owner.Raw != "S-1-5-32-544" || sd.Owner.Name != `BUILTIN\Administrators` {
		t.Fatalf("owner = %+v", sd.Owner)
	}
	if sd.Group.Raw != "S-1-1-0" || sd.Group.Name != "Everyone" {
		t.Fatalf("group = %+v", sd.Group)
	}
	if sd.NullDACL {
		t.Fatal("DACL unexpectedly parsed as null")
	}
	if len(sd.ACEs) != 2 {
		t.Fatalf("ACEs = %d, want 2", len(sd.ACEs))
	}

	first := sd.ACEs[0]
	if !first.Allow || first.Deny || first.Type != "Allow" {
		t.Fatalf("first ACE = %+v", first)
	}
	if got := first.RightsSummary(); got != "Full control" {
		t.Fatalf("first ACE rights = %q", got)
	}
	if got := first.FlagsSummary(); got != "OI CI" {
		t.Fatalf("first ACE flags = %q", got)
	}
	if first.Trustee.Name != "Everyone" {
		t.Fatalf("first ACE trustee = %+v", first.Trustee)
	}

	second := sd.ACEs[1]
	if !second.Deny || !second.Inherited {
		t.Fatalf("second ACE = %+v", second)
	}
	if got := second.RightsSummary(); got != "read data / list folder" {
		t.Fatalf("second ACE rights = %q", got)
	}
}

// TestParseNullDACL verifies that a descriptor without a DACL is reported as a null DACL.
func TestParseNullDACL(t *testing.T) {
	sd, err := ParseSecurityDescriptor(securityDescriptor(sidBytesWithAuthority(1, 0), sidBytesWithAuthority(1, 0), nil))
	if err != nil {
		t.Fatal(err)
	}
	if !sd.NullDACL {
		t.Fatal("a missing DACL should be reported as null")
	}
}

// TestParseEmptyDACL verifies that an empty but present DACL differs from a null one.
func TestParseEmptyDACL(t *testing.T) {
	sd, err := ParseSecurityDescriptor(securityDescriptor(nil, nil, aclBytes()))
	if err != nil {
		t.Fatal(err)
	}
	if sd.NullDACL {
		t.Fatal("an empty but present DACL is not a null DACL")
	}
	if len(sd.ACEs) != 0 {
		t.Fatalf("ACEs = %d, want 0", len(sd.ACEs))
	}
}

// TestParseObjectACE checks that object ACEs locate their trustee after the GUID fields.
func TestParseObjectACE(t *testing.T) {
	ace := objectACEBytes(0x05, 0, 0x00000100, sidBytesWithAuthority(1, 0))
	sd, err := ParseSecurityDescriptor(securityDescriptor(nil, nil, aclBytes(ace)))
	if err != nil {
		t.Fatal(err)
	}
	if len(sd.ACEs) != 1 {
		t.Fatalf("ACEs = %d", len(sd.ACEs))
	}
	got := sd.ACEs[0]
	if !got.Object || !got.Allow {
		t.Fatalf("object ACE = %+v", got)
	}
	if got.Trustee.Name != "Everyone" {
		t.Fatalf("object ACE trustee = %+v", got.Trustee)
	}
	if got.Type != "Allow (object)" {
		t.Fatalf("object ACE type = %q", got.Type)
	}
}

// TestParseMalformedSecurityDescriptorsNeverPanic feeds truncated and corrupted descriptors to ensure errors replace panics.
func TestParseMalformedSecurityDescriptorsNeverPanic(t *testing.T) {
	owner := sidBytes(32, 544)
	dacl := aclBytes(aceBytes(0x00, 0, 0x1F01FF, sidBytes(1, 0)))
	valid := securityDescriptor(owner, sidBytes(1, 0), dacl)

	for i := 0; i < len(valid); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic parsing a %d-byte prefix: %v", i, r)
				}
			}()
			_, _ = ParseSecurityDescriptor(valid[:i])
		}()
	}

	// Corrupted sizes must be rejected, not panic.
	corrupt := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint16(corrupt[16:], 0xFFFF) // DACL offset beyond the buffer
	if _, err := ParseSecurityDescriptor(corrupt); err == nil {
		t.Fatal("expected an error for a DACL offset past the buffer")
	}

	corrupt = append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(corrupt[16:], 4) // DACL overlaps the header
	if _, err := ParseSecurityDescriptor(corrupt); err == nil {
		t.Fatal("expected an error for an overlapping DACL")
	}
}

// TestAccessMaskSummary checks named access masks and their decomposition into component rights.
func TestAccessMaskSummary(t *testing.T) {
	cases := map[uint32]string{
		0x00000000: "None",
		0x001F01FF: "Full control",
		0x001301BF: "Modify",
		0x001200A9: "Read & execute",
		0x00120089: "Read",
		0x00120116: "Write",
		0x80000000: "Generic read",
		0x00000001: "read data / list folder",
	}
	for mask, want := range cases {
		if got := AccessMaskSummary(mask); got != want {
			t.Fatalf("AccessMaskSummary(0x%08X) = %q, want %q", mask, got, want)
		}
	}

	combined := AccessMaskSummary(0x00000003)
	if !strings.Contains(combined, "read data") || !strings.Contains(combined, "write data") {
		t.Fatalf("combined mask summary = %q", combined)
	}
}

// TestSIDName checks well-known SID lookup and domain-group RID naming.
func TestSIDName(t *testing.T) {
	cases := map[string]string{
		"S-1-5-32-544":              `BUILTIN\Administrators`,
		"S-1-5-32-545":              `BUILTIN\Users`,
		"S-1-1-0":                   "Everyone",
		"S-1-5-11":                  "Authenticated Users",
		"S-1-5-21-1-2-3-512":        "Domain Admins (domain group)",
		"S-1-5-21-111-222-333-1105": "",
		"S-1-5-21-111-222-333-500":  "Administrator",
	}
	for raw, want := range cases {
		if got := sidName(raw); got != want {
			t.Fatalf("sidName(%q) = %q, want %q", raw, got, want)
		}
	}
}
