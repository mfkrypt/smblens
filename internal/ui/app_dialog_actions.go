// Prompt, confirmation and file-operation actions initiated from dialogs.

package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
	"github.com/mfkrypt/smblens/internal/termtext"
)

// handleDialogKey routes keys to the active dialog.
func (a *App) handleDialogKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch a.dialog.kind {
	case dialogHelp, dialogError, dialogPermissions:
		switch msg.String() {
		case "esc", "enter", "q", "?":
			a.stopPermsLoad()
			a.dialog.close()
			return a, nil
		}
		var cmd tea.Cmd
		a.dialog.viewport, cmd = a.dialog.viewport.Update(msg)
		return a, cmd

	case dialogConfirm:
		switch msg.String() {
		case "y", "enter":
			return a.confirmPending()
		case "n", "esc":
			a.dialog.close()
			return a, nil
		}
		return a, nil

	case dialogPrompt:
		switch msg.String() {
		case "esc":
			a.dialog.close()
			return a, nil
		case "enter":
			return a.submitPrompt()
		}
		var cmd tea.Cmd
		a.dialog.prompt, cmd = a.dialog.prompt.Update(msg)
		return a, cmd

	case dialogTransfer:
		state := a.dialog.transfer
		if state == nil {
			a.dialog.close()
			return a, nil
		}
		if state.finished {
			switch msg.String() {
			case "esc", "enter", "q":
				a.dialog.close()
				return a, nil
			case "i":
				if state.err != nil {
					return a.openErrorDialog("Transfer failed", state.err)
				}
				if state.direction == transferDownloadTree {
					if err := state.failureError(); err != nil {
						return a.openErrorDialog("Download incomplete", err)
					}
				}
			}
			return a, nil
		}
		if msg.String() == "esc" {
			state.cancelTransfer()
			return a, nil
		}
		return a, nil
	}
	return a, nil
}

func (a *App) openMkdirPrompt() (tea.Model, tea.Cmd) {
	cmd := a.dialog.openPrompt(
		"New folder",
		"Create a folder in "+a.browserUNC(a.browser.path),
		"", "folder name",
		pendingAction{kind: actionMkdir},
	)
	a.dialog.setSize(a.width, a.height)
	return a, cmd
}

func (a *App) openRenamePrompt(entry smbclient.Entry) (tea.Model, tea.Cmd) {
	cmd := a.dialog.openPrompt(
		"Rename",
		"Rename "+entry.Name+" in "+a.browserUNC(a.browser.path),
		termtext.Clean(entry.Name), "new name",
		pendingAction{kind: actionRename, entry: entry},
	)
	a.dialog.setSize(a.width, a.height)
	return a, cmd
}

func (a *App) openUploadPrompt() (tea.Model, tea.Cmd) {
	cmd := a.dialog.openPrompt(
		"Upload",
		"Upload a local file into "+a.browserUNC(a.browser.path),
		"", "/path/to/local/file",
		pendingAction{kind: actionUpload},
	)
	a.dialog.setSize(a.width, a.height)
	return a, cmd
}

func (a *App) openDownloadPrompt(entry smbclient.Entry) (tea.Model, tea.Cmd) {
	cmd := a.dialog.openPrompt(
		"Download",
		"Download "+entry.Name+" ("+formatSize(entry.Size)+") to a local path. The default is the current directory.",
		a.defaultDownloadPath(entry.Name), "local file or folder",
		pendingAction{kind: actionDownload, entry: entry},
	)
	a.dialog.setSize(a.width, a.height)
	return a, cmd
}

func (a *App) openFolderDownloadPrompt(entry smbclient.Entry) (tea.Model, tea.Cmd) {
	cmd := a.dialog.openPrompt(
		"Download folder",
		fmt.Sprintf("Download %q and everything inside it. The remote structure is recreated in the local folder; files with matching names are replaced.", entry.Name),
		a.defaultDownloadPath(entry.Name), "local folder",
		pendingAction{kind: actionDownloadTree, entry: entry},
	)
	a.dialog.setSize(a.width, a.height)
	return a, cmd
}

// defaultDownloadPath returns <cwd>/<name>, sanitised for local use.
func (a *App) defaultDownloadPath(name string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return name
	}
	return smbclient.LocalDownloadPath(cwd, "", name)
}

func (a *App) openDeleteConfirm(entry smbclient.Entry) (tea.Model, tea.Cmd) {
	kind := "file"
	if entry.Dir {
		kind = "folder (it must be empty)"
	}
	a.dialog.openConfirm(
		"Delete "+kind+"?",
		fmt.Sprintf("Permanently delete %q from %s?\n\nThis cannot be undone.", entry.Name, a.browserUNC(a.browser.path)),
		pendingAction{kind: actionDeleteEntry, entry: entry},
	)
	a.dialog.setSize(a.width, a.height)
	return a, nil
}

func (a *App) submitPrompt() (tea.Model, tea.Cmd) {
	value := a.dialog.promptValue()
	pending := a.dialog.pending

	switch pending.kind {
	case actionMkdir:
		if err := validRemoteName(value); err != nil {
			a.dialog.err = err
			return a, nil
		}
		remote := smbclient.JoinPath(a.browser.path, value)
		a.dialog.close()
		return a, a.runFileOp("Created folder "+value, refreshDir, func(ctx context.Context, share *smbclient.Share) error {
			return share.Mkdir(ctx, remote)
		})

	case actionRename:
		if err := validRemoteName(value); err != nil {
			a.dialog.err = err
			return a, nil
		}
		remote := smbclient.JoinPath(a.browser.path, value)
		if remote == pending.entry.Path {
			a.dialog.close()
			return a, nil
		}
		oldPath := pending.entry.Path
		a.dialog.close()
		return a, a.runFileOp("Renamed to "+value, refreshDir, func(ctx context.Context, share *smbclient.Share) error {
			return share.Rename(ctx, oldPath, remote)
		})

	case actionUpload:
		local := expandPath(value)
		if local == "" {
			a.dialog.err = errors.New("enter the path of a local file")
			return a, nil
		}
		info, err := os.Stat(local)
		if err != nil {
			a.dialog.err = fmt.Errorf("cannot read %s: %w", local, err)
			return a, nil
		}
		if info.IsDir() {
			a.dialog.err = errors.New("that is a folder; choose a single file")
			return a, nil
		}
		remote := smbclient.JoinPath(a.browser.path, filepath.Base(local))
		if err := validRemoteName(filepath.Base(local)); err != nil {
			a.dialog.err = err
			return a, nil
		}
		a.dialog.close()
		return a, a.startTransfer(transferUpload, local, remote, false)

	case actionDownload:
		local := expandPath(value)
		if local == "" {
			a.dialog.err = errors.New("enter a local destination")
			return a, nil
		}
		local = resolveDownloadPath(local, pending.entry.Name)
		if info, err := os.Stat(local); err == nil && !info.IsDir() {
			a.dialog.openConfirm(
				"Replace local file?",
				fmt.Sprintf("%s already exists. Replace it?", local),
				pendingAction{kind: actionDownload, entry: pending.entry, path: local, localPath: pending.entry.Path},
			)
			a.dialog.setSize(a.width, a.height)
			return a, nil
		}
		a.dialog.close()
		return a, a.startTransfer(transferDownload, local, pending.entry.Path, true)

	case actionDownloadTree:
		local := expandPath(value)
		if local == "" {
			a.dialog.err = errors.New("enter a local destination folder")
			return a, nil
		}
		info, statErr := os.Stat(local)
		switch {
		case statErr == nil && !info.IsDir():
			a.dialog.err = errors.New("a file exists at that path; choose a folder")
			return a, nil
		case statErr == nil && info.IsDir():
			a.dialog.openConfirm(
				"Merge into existing folder?",
				fmt.Sprintf("%s already exists. Files with matching names will be replaced.", local),
				pendingAction{kind: actionDownloadTree, entry: pending.entry, path: local},
			)
			a.dialog.setSize(a.width, a.height)
			return a, nil
		case statErr != nil && !os.IsNotExist(statErr):
			a.dialog.err = fmt.Errorf("cannot use %s: %w", local, statErr)
			return a, nil
		}
		a.dialog.close()
		return a, a.startTransfer(transferDownloadTree, local, pending.entry.Path, false)
	}

	a.dialog.close()
	return a, nil
}

func (a *App) confirmPending() (tea.Model, tea.Cmd) {
	pending := a.dialog.pending
	a.dialog.close()

	switch pending.kind {
	case actionDeleteEntry:
		return a, a.runFileOp("Deleted "+pending.entry.Name, refreshDir, func(ctx context.Context, share *smbclient.Share) error {
			return share.Remove(ctx, pending.entry.Path)
		})
	case actionUpload:
		return a, a.startTransfer(transferUpload, pending.localPath, pending.path, true)
	case actionDownload:
		return a, a.startTransfer(transferDownload, pending.path, pending.localPath, true)
	case actionDownloadTree:
		return a, a.startTransfer(transferDownloadTree, pending.path, pending.entry.Path, false)
	}
	return a, nil
}

// runFileOp executes a short file operation against the browsed share.
func (a *App) runFileOp(desc string, refresh refreshTarget, fn func(context.Context, *smbclient.Share) error) tea.Cmd {
	share := a.share
	if share == nil {
		return nil
	}
	if a.cancelOp != nil {
		a.cancelOp()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelOp = cancel

	a.seqOp++
	seq := a.seqOp

	return func() tea.Msg {
		err := fn(ctx, share)
		return operationDoneMsg{seq: seq, desc: desc, err: err, refresh: refresh}
	}
}

func (a *App) onOperationDone(msg operationDoneMsg) (tea.Model, tea.Cmd) {
	if msg.seq != a.seqOp {
		return a, nil
	}
	a.cancelOp = nil
	if msg.err != nil {
		a.lastErr = msg.err
		if a.fatal(msg.err) {
			return a, nil
		}
		if errors.Is(msg.err, smbclient.ErrExists) {
			return a, nil
		}
		return a.openErrorDialog("Operation failed", msg.err)
	}

	cmds := []tea.Cmd{a.setToast(msg.desc, false)}
	if msg.refresh == refreshDir && a.screen == screenBrowser {
		cmds = append(cmds, a.loadDirCmd(a.browser.path))
	}
	return a, tea.Batch(cmds...)
}
