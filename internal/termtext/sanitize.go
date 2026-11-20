// Package termtext sanitises text that came from a remote server before it is
// rendered in a terminal.
//
// Filenames, share comments and file contents are attacker-controlled as far
// as this client is concerned. A malicious or compromised SMB server can put
// ANSI escape sequences in a filename, or Unicode bidirectional controls that
// make "gnp.exe" look like "exe.png". Everything displayed goes through this
// package first.
package termtext

import (
	"strings"
	"unicode/utf8"
)

// Clean prepares a single-line label (share name, filename, comment) for
// display. Escape sequences are removed; control characters and invisible
// formatting characters become '?' so that they cannot hide or spoof content.
func Clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune('�')
			i++
			continue
		}
		if r == 0x1b {
			i += escapeLength(s[i:])
			continue
		}
		if r == '\t' || r == '\n' || r == '\r' {
			// A label is one line; control whitespace is suspicious here.
			b.WriteByte('?')
			i += size
			continue
		}
		if !printable(r) {
			b.WriteByte('?')
			i += size
			continue
		}
		if isInvisibleFormatting(r) {
			b.WriteByte('?')
			i += size
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// CleanMultiline prepares file content for the viewer. Newlines and tabs are
// kept (tabs become four spaces); escape sequences and other control
// characters are removed, and invalid UTF-8 is replaced.
func CleanMultiline(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune('�')
			i++
			continue
		}
		if r == 0x1b {
			i += escapeLength(s[i:])
			continue
		}
		switch r {
		case '\n':
			b.WriteByte('\n')
		case '\t':
			b.WriteString("    ")
		case '\r':
			// CRLF and bare CR both render as a newline.
			b.WriteByte('\n')
			if i+size < len(s) && s[i+size] == '\n' {
				i++
			}
		default:
			if printable(r) && !isInvisibleFormatting(r) {
				b.WriteRune(r)
			}
		}
		i += size
	}
	return b.String()
}

// printable reports whether r may be shown as-is.
func printable(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return true
	}
	if r < 0x20 || r == 0x7f {
		return false
	}
	// C1 controls (U+0080-U+009F).
	if r >= 0x80 && r <= 0x9f {
		return false
	}
	return true
}

// isInvisibleFormatting identifies characters that can reorder or hide text.
func isInvisibleFormatting(r rune) bool {
	switch {
	case r == 0x00ad: // soft hyphen
		return true
	case r == 0x061c: // Arabic letter mark
		return true
	case r == 0x180e: // Mongolian vowel separator
		return true
	case r >= 0x200b && r <= 0x200f: // zero-width space/joiners, LRM, RLM
		return true
	case r >= 0x202a && r <= 0x202e: // bidi embedding/override
		return true
	case r >= 0x2060 && r <= 0x2064: // word joiner, invisible operators
		return true
	case r >= 0x2066 && r <= 0x2069: // bidi isolates
		return true
	case r == 0xfeff: // zero-width no-break space
		return true
	}
	return false
}

// escapeLength returns the number of bytes in the escape sequence starting at
// s[0] (which is ESC), so the caller can skip it. Sequences that never
// terminate are consumed to the end of the string, which is safer than
// letting their visible payload through.
func escapeLength(s string) int {
	if len(s) < 2 {
		return len(s)
	}
	switch s[1] {
	case '[': // CSI: ESC [ ... final byte 0x40-0x7E
		for i := 2; i < len(s); i++ {
			if s[i] >= 0x40 && s[i] <= 0x7e {
				return i + 1
			}
		}
		return len(s)
	case ']': // OSC: ESC ] ... BEL or ST (ESC \)
		for i := 2; i < len(s); i++ {
			if s[i] == 0x07 {
				return i + 1
			}
			if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
		}
		return len(s)
	case 'P', 'X', '^', '_': // DCS, SOS, PM, APC: terminated by ST
		for i := 2; i < len(s); i++ {
			if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
		}
		return len(s)
	default:
		return 2
	}
}
