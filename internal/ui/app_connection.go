// Connection setup and share enumeration.

package ui

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
)

func (a *App) dialCmd(cfg smbclient.Config) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout+5*time.Second)
		defer cancel()
		client, err := smbclient.Dial(ctx, cfg)
		return connectedMsg{client: client, cfg: cfg, err: err}
	}
}

func (a *App) onConnected(msg connectedMsg) (tea.Model, tea.Cmd) {
	a.connect.connecting = false
	if msg.err != nil {
		a.connect.err = msg.err
		a.lastErr = msg.err
		a.screen = screenConnect
		if smbclient.IsAuthError(msg.err) {
			return a, a.connect.focusSecret()
		}
		return a, a.connect.focusServer()
	}

	if a.client != nil {
		_ = a.client.Close()
	}
	a.client = msg.client
	a.cfg = msg.cfg
	a.connect.err = nil
	a.shareCache = make(map[string]smbclient.ShareInfo)
	a.shares.setContext(a.cfg.Host, !a.opts.NoWriteProbe)

	if a.cfg.Share != "" {
		if a.opts.Recursive {
			a.screen = screenTree
			a.treeBack = screenShares
			a.tree.setSize(a.width, a.bodyHeight)
			return a, a.tree.startScan(a.client, a.cfg.Host, a.cfg.Share, a.cfg.Path, a.opts.MaxDepth)
		}
		return a, a.openShareCmd(a.cfg.Share, a.cfg.Path)
	}

	a.screen = screenShares
	return a, a.loadSharesCmd()
}

func (a *App) loadSharesCmd() tea.Cmd {
	client := a.client
	if client == nil {
		return nil
	}
	if a.cancelShares != nil {
		a.cancelShares()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelShares = cancel

	a.seqShares++
	seq := a.seqShares
	a.shares.setLoading()
	probe := !a.opts.NoWriteProbe

	return func() tea.Msg {
		entries, err := client.EnumerateShares(ctx, probe)
		return sharesLoadedMsg{seq: seq, entries: entries, err: err}
	}
}

func (a *App) onSharesLoaded(msg sharesLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.seq != a.seqShares {
		return a, nil
	}
	a.cancelShares = nil
	if msg.err != nil {
		a.lastErr = msg.err
		if a.fatal(msg.err) {
			return a, nil
		}
	}
	a.shares.setData(msg.entries, msg.err)
	a.shareCache = make(map[string]smbclient.ShareInfo, len(msg.entries))
	for _, share := range msg.entries {
		a.shareCache[share.Name] = share
	}
	if msg.err != nil && len(msg.entries) == 0 {
		return a, a.setToast(smbclient.Describe(msg.err), true)
	}
	return a, nil
}

func (a *App) openShareCmd(name, initialPath string) tea.Cmd {
	client := a.client
	if client == nil {
		return nil
	}
	if a.cancelOpen != nil {
		a.cancelOpen()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelOpen = cancel

	a.seqOpen++
	seq := a.seqOpen
	a.mounting = true

	return func() tea.Msg {
		share, err := client.Mount(ctx, name)
		if err != nil {
			return shareOpenedMsg{seq: seq, name: name, path: initialPath, err: err}
		}
		entries, listErr := share.List(ctx, initialPath)
		return shareOpenedMsg{seq: seq, share: share, name: name, path: initialPath, entries: entries, err: listErr}
	}
}

func (a *App) onShareOpened(msg shareOpenedMsg) (tea.Model, tea.Cmd) {
	if msg.seq != a.seqOpen {
		if msg.share != nil {
			_ = msg.share.Close()
		}
		return a, nil
	}
	a.cancelOpen = nil
	a.mounting = false

	if msg.share == nil {
		a.lastErr = msg.err
		if a.fatal(msg.err) {
			return a, nil
		}
		a.dialog.openError("Could not open share", msg.err)
		a.dialog.setSize(a.width, a.height)
		if a.screen == screenConnect {
			a.screen = screenShares
			return a, a.loadSharesCmd()
		}
		return a, nil
	}

	if a.share != nil {
		_ = a.share.Close()
	}
	a.share = msg.share
	a.browser.setShare(msg.share, msg.name)
	a.browser.setSize(a.width, a.bodyHeight)
	a.browser.setData(msg.path, msg.entries, msg.err)
	a.screen = screenBrowser
	if msg.err != nil {
		a.lastErr = msg.err
	}
	return a, nil
}
