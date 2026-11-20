package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mfkrypt/smblens/internal/smbclient"
)

// formatSize renders a byte count with binary units.
func formatSize(n int64) string {
	if n < 0 {
		return "?"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	for _, u := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, u)
		}
	}
	return fmt.Sprintf("%.1f EB", value/unit)
}

// formatTime renders a modification time in local time.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04")
}

// formatRate renders a transfer rate.
func formatRate(bytesPerSecond float64) string {
	if bytesPerSecond <= 0 {
		return ""
	}
	return formatSize(int64(bytesPerSecond)) + "/s"
}

// fileKind labels a directory entry's type.
func fileKind(e smbclient.Entry) string {
	switch {
	case e.Symlink:
		return "link"
	case e.Dir:
		return "dir"
	case e.Mode&os.ModeNamedPipe != 0:
		return "pipe"
	case e.Mode&os.ModeSocket != 0:
		return "socket"
	case e.Mode&os.ModeDevice != 0:
		return "device"
	case e.Mode&os.ModeIrregular != 0:
		return "special"
	default:
		return "file"
	}
}

// accessDetail renders a share's probe result as a sentence.
func accessDetail(state smbclient.AccessState) string {
	if state.Denied {
		return "denied (the account cannot connect to this share)"
	}
	if !state.Mounted {
		if state.Err != nil {
			return "could not be tested: " + smbclient.Describe(state.Err)
		}
		return "not tested"
	}
	var parts []string
	if state.Read {
		parts = append(parts, "read")
	}
	if state.WriteTested {
		if state.Write {
			parts = append(parts, "write")
		}
	} else if state.Read {
		parts = append(parts, "write not tested")
	}
	detail := strings.Join(parts, " + ")
	if detail == "" {
		detail = "connected, but no read or write access was demonstrated"
	}
	if state.Note != "" {
		detail += " · " + state.Note
	}
	if state.Err != nil {
		detail += " · " + smbclient.Describe(state.Err)
	}
	return detail
}

// plural picks the singular or plural noun.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// percent returns a 0..1 fraction, guarding against division by zero.
func percent(done, total int64) float64 {
	if total <= 0 {
		return 0
	}
	p := float64(done) / float64(total)
	if p > 1 {
		return 1
	}
	return p
}

// safeFilename makes a string safe for a local file name.
func safeFilename(s string) string {
	if s == "" {
		return "smblens"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._")
	if out == "" {
		return "value"
	}
	return out
}
