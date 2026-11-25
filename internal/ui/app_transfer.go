// Upload and download transfers.

package ui

import (
	"context"
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
	"github.com/mfkrypt/smblens/internal/termtext"
)

// startTransfer opens the transfer dialog and starts the upload or download goroutine.
func (a *App) startTransfer(direction transferDirection, local, remote string, overwrite bool) tea.Cmd {
	share := a.share
	if share == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch := runTransfer(ctx, cancel, direction, share, local, remote, overwrite)
	state := newTransferState(direction, a.cfg.Host, a.browser.shareName, remote, local, cancel, ch, a.theme)

	a.dialog.openTransfer(state)
	switch direction {
	case transferUpload:
		a.dialog.pending = pendingAction{kind: actionUpload, path: remote, localPath: local}
	case transferDownload:
		a.dialog.pending = pendingAction{kind: actionDownload, path: local, localPath: remote}
	default:
		a.dialog.pending = pendingAction{}
	}
	a.dialog.setSize(a.width, a.height)

	return waitForTransferEvent(ch)
}

// onTransferEvent applies progress, handles overwrite confirmations and reports completion or cancellation.
func (a *App) onTransferEvent(msg transferEventMsg) (tea.Model, tea.Cmd) {
	state := a.dialog.transfer
	if state == nil || a.dialog.kind != dialogTransfer {
		return a, nil
	}
	state.update(msg.event)

	if !msg.event.finished {
		return a, waitForTransferEvent(state.ch)
	}

	if errors.Is(msg.event.err, smbclient.ErrExists) && state.direction == transferUpload {
		pending := a.dialog.pending
		pending.kind = actionUpload
		a.dialog.openConfirm(
			"Replace remote file?",
			fmt.Sprintf(`%s already exists. Replace it?`, termtext.Clean(pending.path)),
			pending,
		)
		a.dialog.setSize(a.width, a.height)
		return a, nil
	}

	if state.cancelled {
		a.dialog.close()
		return a, a.setToast("Transfer cancelled.", true)
	}
	if state.err != nil {
		a.lastErr = state.err
		if a.fatal(state.err) {
			return a, nil
		}
		return a, nil // keep the dialog open with the error
	}

	if state.direction == transferDownloadTree {
		if state.failed > 0 || state.skipped > 0 {
			a.lastErr = state.failureError()
			return a, nil // keep the summary visible; i shows every failure
		}
		desc := fmt.Sprintf("Downloaded %d file%s to %s",
			state.filesDone, plural(state.filesDone, "", "s"), termtext.Clean(state.local))
		a.dialog.close()
		return a, a.setToast(desc, false)
	}

	// Success.
	desc := "Download complete"
	if state.direction == transferUpload {
		desc = "Upload complete: " + termtext.Clean(state.remote)
	} else {
		desc = "Saved " + state.local
	}
	a.dialog.close()
	cmds := []tea.Cmd{a.setToast(desc, false)}
	if state.direction == transferUpload && a.screen == screenBrowser {
		cmds = append(cmds, a.loadDirCmd(a.browser.path))
	}
	return a, tea.Batch(cmds...)
}
