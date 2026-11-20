// Directory listings and the file viewer.

package ui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
)

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

func (a *App) stopFileLoad() {
	if a.cancelFile != nil {
		a.cancelFile()
		a.cancelFile = nil
	}
}

func (a *App) stopDirLoad() {
	if a.cancelDir != nil {
		a.cancelDir()
		a.cancelDir = nil
	}
}

func (a *App) stopPermsLoad() {
	if a.cancelPerms != nil {
		a.cancelPerms()
		a.cancelPerms = nil
	}
}
