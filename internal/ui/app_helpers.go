// Small shared helpers.

package ui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

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

func (a *App) browserUNC(path string) string {
	base := `\\` + a.cfg.Host + `\` + a.browser.shareName
	if path != "" {
		base += `\` + strings.ReplaceAll(path, "/", `\`)
	}
	return base
}
