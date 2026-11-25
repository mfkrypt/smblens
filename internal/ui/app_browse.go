// Directory listings and the file viewer.

package ui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
)

// loadDirCmd asynchronously lists a directory and invalidates any earlier listing.
func (a *App) loadDirCmd(path string) tea.Cmd {
	share := a.share
	if share == nil {
		return nil
	}
	if a.cancelDir != nil {
		a.cancelDir()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelDir = cancel

	a.seqDir++
	seq := a.seqDir
	a.browser.setLoading()

	return func() tea.Msg {
		entries, err := share.List(ctx, path)
		return entriesLoadedMsg{seq: seq, path: path, entries: entries, err: err}
	}
}

// onEntriesLoaded applies a directory listing, ignoring stale responses and handling connection loss.
func (a *App) onEntriesLoaded(msg entriesLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.seq != a.seqDir {
		return a, nil
	}
	a.cancelDir = nil
	if msg.err != nil {
		a.lastErr = msg.err
		if a.fatal(msg.err) {
			return a, nil
		}
	}
	a.browser.setData(msg.path, msg.entries, msg.err)
	if msg.err != nil {
		return a, a.setToast(smbclient.Describe(msg.err), true)
	}
	return a, nil
}

// openViewerCmd opens the viewer and asynchronously reads the selected file.
func (a *App) openViewerCmd(entry smbclient.Entry) tea.Cmd {
	share := a.share
	if share == nil {
		return nil
	}
	if a.cancelFile != nil {
		a.cancelFile()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelFile = cancel

	a.seqFile++
	seq := a.seqFile
	a.viewer.open(a.cfg.Host, a.browser.shareName, entry.Path)
	a.viewer.setSize(a.width, a.bodyHeight)
	a.screen = screenViewer

	return func() tea.Msg {
		content, err := share.ReadText(ctx, entry.Path, smbclient.MaxViewBytes)
		return fileLoadedMsg{seq: seq, content: content, err: err}
	}
}

// onFileLoaded applies a file read result to the viewer, ignoring stale responses.
func (a *App) onFileLoaded(msg fileLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.seq != a.seqFile {
		return a, nil
	}
	a.cancelFile = nil
	if msg.err != nil {
		a.lastErr = msg.err
		if a.fatal(msg.err) {
			return a, nil
		}
	}
	a.viewer.setContent(msg.content, msg.err)
	return a, nil
}

// stopFileLoad cancels an in-flight file read.
func (a *App) stopFileLoad() {
	if a.cancelFile != nil {
		a.cancelFile()
		a.cancelFile = nil
	}
}

// stopDirLoad cancels an in-flight directory listing.
func (a *App) stopDirLoad() {
	if a.cancelDir != nil {
		a.cancelDir()
		a.cancelDir = nil
	}
}

// stopPermsLoad cancels an in-flight permission lookup.
func (a *App) stopPermsLoad() {
	if a.cancelPerms != nil {
		a.cancelPerms()
		a.cancelPerms = nil
	}
}
