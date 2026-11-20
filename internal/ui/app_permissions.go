// Permission lookups and the permissions dialog.

package ui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
)

func (a *App) openPermissionsFromShares(share smbclient.ShareInfo) tea.Cmd {
	client := a.client
	if client == nil {
		return nil
	}
	title := `\\` + a.cfg.Host + `\` + share.Name
	access := share.Access

	if a.cancelPerms != nil {
		a.cancelPerms()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelPerms = cancel
	a.seqPerms++
	seq := a.seqPerms

	a.dialog.openPermissionsLoading(title)
	a.dialog.setSize(a.width, a.height)

	accessCopy := access
	return func() tea.Msg {
		mounted, err := client.Mount(ctx, share.Name)
		if err != nil {
			return permissionsLoadedMsg{seq: seq, title: title, access: &accessCopy, err: err}
		}
		defer func() { _ = mounted.Close() }()
		perms, err := mounted.Permissions(ctx, "")
		return permissionsLoadedMsg{seq: seq, title: title, perms: perms, access: &accessCopy, err: err}
	}
}

func (a *App) openPermissionsForPath(path string) tea.Cmd {
	share := a.share
	if share == nil || path == "" {
		path = a.browser.path
	}
	if share == nil {
		return nil
	}
	title := a.browserUNC(path)

	if a.cancelPerms != nil {
		a.cancelPerms()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelPerms = cancel
	a.seqPerms++
	seq := a.seqPerms

	a.dialog.openPermissionsLoading(title)
	a.dialog.setSize(a.width, a.height)

	var access *smbclient.AccessState
	if info, ok := a.shareCache[a.browser.shareName]; ok {
		copy := info.Access
		access = &copy
	}

	return func() tea.Msg {
		perms, err := share.Permissions(ctx, path)
		return permissionsLoadedMsg{seq: seq, title: title, perms: perms, access: access, err: err}
	}
}

func (a *App) onPermissionsLoaded(msg permissionsLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.seq != a.seqPerms || a.dialog.kind != dialogPermissions {
		return a, nil
	}
	a.stopPermsLoad()

	var body string
	if msg.err != nil {
		a.lastErr = msg.err
		if a.fatal(msg.err) {
			return a, nil
		}
		body = "Target: " + msg.title + "\n\n"
		body += "The security descriptor could not be read: " + smbclient.Describe(msg.err) + "\n\n"
		if hint := smbclient.Hint(msg.err); hint != "" {
			body += "Hint: " + hint + "\n\n"
		}
		body += "Reading an ACL requires READ_CONTROL. Not being able to read it does not by itself mean the data is inaccessible."
	} else {
		body = permissionReport(msg.perms, msg.access)
	}
	a.dialog.setBody(body)
	a.dialog.setSize(a.width, a.height)
	return a, nil
}
