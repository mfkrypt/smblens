// Key handling for every screen.

package ui

import (
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
)

func (a *App) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		return a.quit()
	}
	if a.dialog.active() {
		return a.handleDialogKey(msg)
	}
	if msg.String() == "f1" {
		return a.openHelp()
	}

	onConnect := a.screen == screenConnect
	filtering := a.isFiltering()

	if !onConnect && !filtering && msg.String() == "?" {
		return a.openHelp()
	}
	if !onConnect && !filtering && msg.String() == "i" && a.lastErr != nil {
		return a.openErrorDialog("Error details", a.lastErr)
	}
	if onConnect && msg.String() == "ctrl+e" && a.connect.err != nil {
		return a.openErrorDialog("Connection error", a.connect.err)
	}

	switch a.screen {
	case screenConnect:
		return a, a.connect.handleKey(msg, a.cfg)
	case screenShares:
		return a.handleSharesKey(msg)
	case screenBrowser:
		return a.handleBrowserKey(msg)
	case screenTree:
		return a.handleTreeKey(msg)
	case screenViewer:
		return a.handleViewerKey(msg)
	}
	return a, nil
}

func (a *App) isFiltering() bool {
	switch a.screen {
	case screenShares:
		return a.shares.filtering
	case screenBrowser:
		return a.browser.filtering
	case screenTree:
		return a.tree.filtering
	}
	return false
}

func (a *App) handleSharesKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.shares.filtering {
		return a, a.shares.handleFilterKey(msg)
	}
	switch msg.String() {
	case "q":
		return a.quit()
	case "esc", "c":
		return a.disconnect()
	case "enter":
		if a.shares.loading || a.mounting {
			return a, nil
		}
		share, ok := a.shares.selected()
		if !ok {
			return a, nil
		}
		return a, a.openShareCmd(share.Name, "")
	case "p":
		share, ok := a.shares.selected()
		if !ok {
			return a, nil
		}
		return a, a.openPermissionsFromShares(share)
	case "t":
		share, ok := a.shares.selected()
		if !ok || a.client == nil || a.tree.running {
			return a, nil
		}
		a.treeBack = screenShares
		a.screen = screenTree
		a.tree.setSize(a.width, a.bodyHeight)
		return a, a.tree.startScan(a.client, a.cfg.Host, share.Name, "", a.opts.MaxDepth)
	case "e":
		path := shareExportName(a.cfg.Host)
		if err := writeShareReport(path, a.cfg, a.shares.all); err != nil {
			return a.openErrorDialog("Export failed", err)
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		return a, a.setToast("Exported "+path, false)
	case "r":
		if a.shares.loading {
			return a, nil
		}
		return a, a.loadSharesCmd()
	case "s":
		a.shares.cycleSort()
		return a, nil
	case "/":
		return a, a.shares.startFilter()
	}
	return a, a.shares.updateTable(msg)
}

func (a *App) handleBrowserKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.browser.filtering {
		return a, a.browser.handleFilterKey(msg)
	}
	loading := a.browser.loading

	switch msg.String() {
	case "q", "esc":
		return a.leaveBrowser()
	case "backspace", "h":
		if loading {
			return a, nil
		}
		if a.browser.path == "" {
			return a, nil
		}
		return a, a.loadDirCmd(smbclient.ParentPath(a.browser.path))
	case "enter", "right", "l":
		if loading {
			return a, nil
		}
		entry, ok := a.browser.selected()
		if !ok {
			return a, nil
		}
		if entry.Symlink || entry.IsSpecial() {
			return a, a.setToast("Symlinks and reparse points are not followed by SMBLens.", true)
		}
		if entry.Dir {
			return a, a.loadDirCmd(entry.Path)
		}
		return a, a.openViewerCmd(entry)
	case "v":
		entry, ok := a.browser.selected()
		if !ok || loading {
			return a, nil
		}
		if entry.Dir {
			return a, a.setToast("Select a file to view (folders open with enter).", true)
		}
		if entry.Symlink || entry.IsSpecial() {
			return a, a.setToast("Symlinks and reparse points are not followed by SMBLens.", true)
		}
		return a, a.openViewerCmd(entry)
	case "d":
		entry, ok := a.browser.selected()
		if !ok || loading {
			return a, nil
		}
		if entry.Symlink || entry.IsSpecial() {
			return a, a.setToast("Symlinks and reparse points are not followed by SMBLens.", true)
		}
		if entry.Dir {
			return a.openFolderDownloadPrompt(entry)
		}
		return a.openDownloadPrompt(entry)
	case "u":
		if loading {
			return a, nil
		}
		return a.openUploadPrompt()
	case "m":
		if loading {
			return a, nil
		}
		return a.openMkdirPrompt()
	case "R":
		entry, ok := a.browser.selected()
		if !ok || loading {
			return a, nil
		}
		return a.openRenamePrompt(entry)
	case "x":
		entry, ok := a.browser.selected()
		if !ok || loading {
			return a, nil
		}
		return a.openDeleteConfirm(entry)
	case "t":
		if loading || a.client == nil || a.tree.running {
			return a, nil
		}
		a.treeBack = screenBrowser
		a.screen = screenTree
		a.tree.setSize(a.width, a.bodyHeight)
		return a, a.tree.startScan(a.client, a.cfg.Host, a.browser.shareName, a.browser.path, a.opts.MaxDepth)
	case "p":
		entry, ok := a.browser.selected()
		path := a.browser.path
		if ok {
			path = entry.Path
		}
		return a, a.openPermissionsForPath(path)
	case "r":
		if loading {
			return a, nil
		}
		return a, a.loadDirCmd(a.browser.path)
	case "/":
		return a, a.browser.startFilter()
	case "s":
		a.browser.cycleSort()
		return a, nil
	case ".":
		a.browser.toggleHidden()
		return a, nil
	}
	return a, a.browser.updateTable(msg)
}

func (a *App) handleTreeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.tree.filtering {
		return a, a.tree.handleFilterKey(msg)
	}
	switch msg.String() {
	case "esc":
		if a.tree.running {
			a.tree.cancelScan()
			return a, a.setToast("Stopping the scan…", false)
		}
		return a.leaveTree()
	case "q":
		return a.leaveTree()
	case "e":
		return a.exportTree()
	case "/":
		return a, a.tree.startFilter()
	}
	return a, a.tree.updateTable(msg)
}

func (a *App) handleViewerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		a.stopFileLoad()
		a.viewer.reset()
		a.screen = screenBrowser
		return a, nil
	}
	return a, a.viewer.update(msg)
}
