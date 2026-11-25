// Small shared helpers.

package ui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// validRemoteName rejects empty names, reserved dot names, path separators and NUL bytes before an SMB operation.
func validRemoteName(name string) error {
	switch {
	case strings.TrimSpace(name) == "":
		return errors.New("enter a name")
	case name == "." || name == "..":
		return errors.New("that name is reserved")
	case strings.ContainsAny(name, `/\`):
		return errors.New("a name cannot contain a path separator")
	case strings.ContainsRune(name, 0):
		return errors.New("the name contains an invalid character")
	}
	return nil
}

// expandPath trims a path and expands a leading ~ or ~/ using the current user's home directory.
func expandPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// resolveDownloadPath appends the remote name when the destination is an existing directory or ends in a separator.
func resolveDownloadPath(local, name string) string {
	if local == "" {
		return local
	}
	if info, err := os.Stat(local); err == nil && info.IsDir() {
		return filepath.Join(local, name)
	}
	if strings.HasSuffix(local, string(os.PathSeparator)) || strings.HasSuffix(local, "/") {
		return filepath.Join(local, name)
	}
	return local
}

// browserUNC formats the current host, share and path as a UNC path for prompts and reports.
func (a *App) browserUNC(path string) string {
	base := `\\` + a.cfg.Host + `\` + a.browser.shareName
	if path != "" {
		base += `\` + strings.ReplaceAll(path, "/", `\`)
	}
	return base
}
