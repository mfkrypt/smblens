package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/mfkrypt/smblens/internal/config"
	"github.com/mfkrypt/smblens/internal/smbclient"
	"github.com/mfkrypt/smblens/internal/termtext"
	"github.com/muesli/termenv"
)

// screenID identifies the active full-screen view.
type screenID int

const (
	screenConnect screenID = iota
	screenShares
	screenBrowser
	screenTree
	screenViewer
)

// String returns the screen name shown in help titles and window messages.
func (s screenID) String() string {
	switch s {
	case screenConnect:
		return "Connect"
	case screenShares:
		return "Shares"
	case screenBrowser:
		return "Browser"
	case screenTree:
		return "Recursive scan"
	case screenViewer:
		return "Viewer"
	}
	return "SMBLens"
}

// refreshTarget says what a completed operation should reload.
type refreshTarget int

const (
	refreshNone refreshTarget = iota
	refreshDir
)

// Messages produced by asynchronous work.
type (
	connectSubmitMsg struct {
		cfg smbclient.Config
	}
	connectedMsg struct {
		client *smbclient.Client
		cfg    smbclient.Config
		err    error
	}
	sharesLoadedMsg struct {
		seq     int
		entries []smbclient.ShareInfo
		err     error
	}
	shareOpenedMsg struct {
		seq     int
		share   *smbclient.Share
		name    string
		path    string
		entries []smbclient.Entry
		err     error
	}
	entriesLoadedMsg struct {
		seq     int
		path    string
		entries []smbclient.Entry
		err     error
	}
	fileLoadedMsg struct {
		seq     int
		content smbclient.FileContent
		err     error
	}
	permissionsLoadedMsg struct {
		seq    int
		title  string
		perms  *smbclient.Permissions
		access *smbclient.AccessState
		err    error
	}
	operationDoneMsg struct {
		seq     int
		desc    string
		err     error
		refresh refreshTarget
	}
	toastExpiredMsg struct {
		seq int
	}
)

// App is the root Bubble Tea model.
type App struct {
	opts   *config.Options
	cfg    smbclient.Config
	client *smbclient.Client
	share  *smbclient.Share // currently browsed share

	screen     screenID
	width      int
	height     int
	bodyHeight int

	theme *theme
	keys  keyBindings
	help  help.Model
	spin  spinner.Model

	connect *connectForm
	shares  sharesModel
	browser browserModel
	tree    treeModel
	viewer  viewerModel
	dialog  dialogModel

	shareCache map[string]smbclient.ShareInfo

	mounting bool
	treeBack screenID
	quitting bool

	// Async bookkeeping. Each operation type has a sequence number so stale
	// results are ignored, and a cancel function so quitting is immediate.
	seqShares int
	seqOpen   int
	seqDir    int
	seqFile   int
	seqPerms  int
	seqOp     int

	cancelShares context.CancelFunc
	cancelOpen   context.CancelFunc
	cancelDir    context.CancelFunc
	cancelFile   context.CancelFunc
	cancelPerms  context.CancelFunc
	cancelOp     context.CancelFunc

	toast    string
	toastErr bool
	toastSeq int

	lastErr error
}

// New creates the application model.
func New(opts *config.Options) *App {
	if opts.NoColor {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	t := newTheme()
	a := &App{
		opts:       opts,
		cfg:        opts.Config,
		screen:     screenConnect,
		theme:      t,
		keys:       defaultKeys(),
		help:       help.New(),
		spin:       spinner.New(),
		dialog:     newDialog(t),
		shareCache: make(map[string]smbclient.ShareInfo),
	}
	a.spin.Spinner = spinner.Dot
	a.spin.Style = lipgloss.NewStyle().Foreground(colors.accent)

	a.connect = newConnectForm(opts.Config, t)
	a.shares = newSharesModel(t)
	a.browser = newBrowserModel(t)
	a.tree = newTreeModel(t)
	a.viewer = newViewerModel(t)

	a.shares.setContext("", !opts.NoWriteProbe)
	a.layout(100, 30)
	a.connect.connecting = false
	return a
}

// Init implements tea.Model.
func (a *App) Init() tea.Cmd {
	cmds := []tea.Cmd{a.spin.Tick, tea.SetWindowTitle("SMBLens")}
	if a.opts.ReadyToConnect() {
		a.connect.connecting = true
		cmds = append(cmds, a.dialCmd(a.opts.Config))
	} else {
		cmds = append(cmds, a.connect.focusCmd())
	}
	return tea.Batch(cmds...)
}

// Close releases the SMB session and any mounted share. It is idempotent.
func (a *App) Close() {
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
}

// Update implements tea.Model.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.layout(msg.Width, msg.Height)
		return a, nil
	case tea.KeyMsg:
		return a.handleKey(msg)
	case spinner.TickMsg:
		var cmd tea.Cmd
		a.spin, cmd = a.spin.Update(msg)
		return a, cmd

	case connectSubmitMsg:
		a.cfg = msg.cfg
		a.connect.connecting = true
		a.connect.err = nil
		return a, a.dialCmd(msg.cfg)
	case connectedMsg:
		return a.onConnected(msg)

	case sharesLoadedMsg:
		return a.onSharesLoaded(msg)
	case shareOpenedMsg:
		return a.onShareOpened(msg)
	case entriesLoadedMsg:
		return a.onEntriesLoaded(msg)
	case fileLoadedMsg:
		return a.onFileLoaded(msg)
	case permissionsLoadedMsg:
		return a.onPermissionsLoaded(msg)
	case operationDoneMsg:
		return a.onOperationDone(msg)

	case treeEventMsg:
		return a.onTreeEvent(msg)
	case treeChannelClosedMsg:
		a.tree.running = false
		return a, nil
	case transferEventMsg:
		return a.onTransferEvent(msg)
	case transferChannelClosedMsg:
		return a, nil

	case toastExpiredMsg:
		if msg.seq == a.toastSeq {
			a.toast = ""
			a.toastErr = false
		}
		return a, nil
	}

	return a, a.forward(msg)
}

// View implements tea.Model.
func (a *App) View() string {
	if a.quitting {
		return ""
	}
	header := a.headerView()
	body := a.bodyView()
	status := a.statusView()
	footer := a.footerView()
	return lipgloss.JoinVertical(lipgloss.Left, header, body, status, footer)
}

// ---------------------------------------------------------------------------
// Layout

// layout stores the terminal size, derives the body height and resizes every screen model.
func (a *App) layout(width, height int) {
	if width < 40 {
		width = 40
	}
	if height < 12 {
		height = 12
	}
	a.width, a.height = width, height
	a.bodyHeight = height - 5 // header (2), status (1), footer (2)
	if a.bodyHeight < 4 {
		a.bodyHeight = 4
	}

	a.connect.setSize(width, a.bodyHeight)
	a.shares.setSize(width, a.bodyHeight)
	a.browser.setSize(width, a.bodyHeight)
	a.tree.setSize(width, a.bodyHeight)
	a.viewer.setSize(width, a.bodyHeight)
	a.dialog.setSize(width, height)
	a.help.Width = width - 2
}

// headerView renders the title bar with the connected host and authentication method.
func (a *App) headerView() string {
	left := a.theme.appTitle.Render("SMBLens")
	right := "SMB client for share enumeration"
	if a.client != nil {
		right = fmt.Sprintf("%s  ·  %s  ·  %s", a.cfg.Host, a.cfg.UserLabel(), authLabel(a.cfg))
	} else if a.cfg.Host != "" {
		right = a.cfg.Host
	}
	line := left + "  " + a.theme.muted.Render(termtext.Clean(right))
	line = ansi.Truncate(line, a.width-2, "…")
	return a.theme.header.Width(a.width - 2).Render(line)
}

// footerView renders the short key hints for the active screen or dialog.
func (a *App) footerView() string {
	h := a.help
	h.Width = a.width - 2
	line := h.ShortHelpView(a.currentKeyMap().ShortHelp())
	return a.theme.footer.Width(a.width - 2).Render(line)
}

// statusView renders the busy indicator, a transient toast, or an empty status line.
func (a *App) statusView() string {
	if text := a.busyText(); text != "" {
		return a.theme.status.Render(a.spin.View() + " " + a.theme.muted.Render(text))
	}
	if a.toast != "" {
		style := a.theme.success
		if a.toastErr {
			style = a.theme.danger
		}
		return a.theme.status.Render(style.Render(a.toast))
	}
	return a.theme.status.Render("")
}

// bodyView renders the active dialog or screen and pads it to the body height.
func (a *App) bodyView() string {
	var body string
	if a.dialog.active() {
		body = lipgloss.Place(a.width, a.bodyHeight, lipgloss.Center, lipgloss.Center, a.dialog.View())
		return body
	}
	switch a.screen {
	case screenConnect:
		a.connect.setSize(a.width, a.bodyHeight)
		body = lipgloss.Place(a.width, a.bodyHeight, lipgloss.Center, lipgloss.Center, a.connect.View())
	case screenShares:
		body = a.shares.View()
	case screenBrowser:
		body = a.browser.View()
	case screenTree:
		body = a.tree.View()
	case screenViewer:
		body = a.viewer.View()
	}
	return padToHeight(body, a.bodyHeight)
}

// padToHeight appends newlines so s occupies at least height lines.
func padToHeight(s string, height int) string {
	current := lipgloss.Height(s)
	if current >= height {
		return s
	}
	return s + strings.Repeat("\n", height-current)
}

// busyText describes whichever asynchronous operation currently blocks the interface.
func (a *App) busyText() string {
	switch {
	case a.connect.connecting:
		return "Connecting…"
	case a.mounting:
		return "Opening share…"
	case a.shares.loading:
		return "Enumerating shares and probing access…"
	case a.browser.loading:
		return "Listing folder…"
	case a.viewer.loading:
		return "Reading file…"
	case a.tree.running:
		return "Scanning…"
	case a.dialog.kind == dialogPermissions && a.dialog.loading:
		return "Reading permissions…"
	case a.dialog.kind == dialogTransfer && a.dialog.transfer != nil && !a.dialog.transfer.finished:
		return "Transferring…"
	}
	return ""
}

// authLabel returns a short human name for the configured authentication method.
func authLabel(cfg smbclient.Config) string {
	switch cfg.Auth {
	case smbclient.AuthHash:
		return "NT hash"
	case smbclient.AuthKerberos:
		return "Kerberos"
	default:
		return "password"
	}
}

// ---------------------------------------------------------------------------
// Key handling

// ---------------------------------------------------------------------------
// Screen transitions

// ---------------------------------------------------------------------------
// Connection

// ---------------------------------------------------------------------------
// Browsing

// ---------------------------------------------------------------------------
// Prompt and confirmation actions

// ---------------------------------------------------------------------------
// Transfers

// ---------------------------------------------------------------------------
// Permissions

// ---------------------------------------------------------------------------
// Tree and help

// ---------------------------------------------------------------------------
// Small helpers

// setToast displays a sanitised status message and schedules its expiry after six seconds.
func (a *App) setToast(text string, isErr bool) tea.Cmd {
	a.toast = termtext.Clean(text)
	a.toastErr = isErr
	a.toastSeq++
	seq := a.toastSeq
	return tea.Tick(6*time.Second, func(time.Time) tea.Msg {
		return toastExpiredMsg{seq: seq}
	})
}

// fatal handles a lost SMB session by tearing it down, returning to the login screen and reporting the error.
func (a *App) fatal(err error) bool {
	if err == nil || !smbclient.IsConnectionLost(err) {
		return false
	}
	a.closeSession()
	a.screen = screenConnect
	a.connect.connecting = false
	a.connect.err = err
	a.toast = "Connection lost. Reconnect to continue."
	a.toastErr = true
	a.toastSeq++
	a.lastErr = err
	return true
}

// forward passes non-application messages to the focused text input or scrollable dialog viewport.
func (a *App) forward(msg tea.Msg) tea.Cmd {
	var cmds []tea.Cmd
	if a.dialog.active() {
		if a.dialog.kind == dialogPrompt {
			var cmd tea.Cmd
			a.dialog.prompt, cmd = a.dialog.prompt.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		if a.dialog.kind == dialogHelp || a.dialog.kind == dialogError || a.dialog.kind == dialogPermissions {
			var cmd tea.Cmd
			a.dialog.viewport, cmd = a.dialog.viewport.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		return tea.Batch(cmds...)
	}
	switch a.screen {
	case screenConnect:
		cmds = append(cmds, a.connect.updateInputs(msg))
	case screenShares:
		if a.shares.filtering {
			var cmd tea.Cmd
			a.shares.filter, cmd = a.shares.filter.Update(msg)
			cmds = append(cmds, cmd)
		}
	case screenBrowser:
		if a.browser.filtering {
			var cmd tea.Cmd
			a.browser.filter, cmd = a.browser.filter.Update(msg)
			cmds = append(cmds, cmd)
		}
	case screenTree:
		if a.tree.filtering {
			var cmd tea.Cmd
			a.tree.filter, cmd = a.tree.filter.Update(msg)
			cmds = append(cmds, cmd)
		}
	}
	return tea.Batch(cmds...)
}
