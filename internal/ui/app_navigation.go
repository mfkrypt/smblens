// Screen transitions and session teardown.

package ui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
)

func (a *App) quit() (tea.Model, tea.Cmd) {
	a.quitting = true
	a.Close()
	return a, tea.Quit
}

func (a *App) disconnect() (tea.Model, tea.Cmd) {
	a.closeSession()
	a.screen = screenConnect
	a.connect.connecting = false
	a.connect.clampFocus()
	return a, nil
}

func (a *App) leaveBrowser() (tea.Model, tea.Cmd) {
	a.stopDirLoad()
	if a.share != nil {
		_ = a.share.Close()
		a.share = nil
	}
	a.browser.clear()
	a.screen = screenShares
	a.shares.setSize(a.width, a.bodyHeight)
	if len(a.shares.all) == 0 && a.client != nil {
		return a, a.loadSharesCmd()
	}
	return a, nil
}

func (a *App) leaveTree() (tea.Model, tea.Cmd) {
	a.tree.detach()
	if a.treeBack == screenBrowser && a.share != nil {
		a.screen = screenBrowser
		return a, nil
	}
	a.screen = screenShares
	if len(a.shares.all) == 0 && a.client != nil {
		return a, a.loadSharesCmd()
	}
	return a, nil
}

// closeSession tears down all SMB state while preserving the login form.
func (a *App) closeSession() {
	a.cancelAll()
	a.tree.detach()
	if a.share != nil {
		_ = a.share.Close()
		a.share = nil
	}
	if a.client != nil {
		_ = a.client.Close()
		a.client = nil
	}
	a.browser.clear()
	a.viewer.reset()
	a.shares.setData(nil, nil)
	a.shareCache = make(map[string]smbclient.ShareInfo)
	a.mounting = false
	a.dialog.close()

	// Invalidate any result still in flight from the closed session.
	a.seqShares++
	a.seqOpen++
	a.seqDir++
	a.seqFile++
	a.seqPerms++
	a.seqOp++
}

func (a *App) cancelAll() {
	for _, cancel := range []context.CancelFunc{
		a.cancelShares, a.cancelOpen, a.cancelDir, a.cancelFile, a.cancelPerms, a.cancelOp,
	} {
		if cancel != nil {
			cancel()
		}
	}
	a.cancelShares, a.cancelOpen, a.cancelDir, a.cancelFile, a.cancelPerms, a.cancelOp = nil, nil, nil, nil, nil, nil
	if a.dialog.transfer != nil {
		a.dialog.transfer.cancelTransfer()
	}
	if a.tree.running {
		a.tree.cancelScan()
	}
}
