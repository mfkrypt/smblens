package ui

import "github.com/charmbracelet/bubbles/key"

// keyBindings holds every shortcut in one place so the footer help and the
// full help screen never drift apart.
type keyBindings struct {
	up     key.Binding
	down   key.Binding
	top    key.Binding
	bottom key.Binding
	pgUp   key.Binding
	pgDown key.Binding

	open        key.Binding
	back        key.Binding
	parent      key.Binding
	refresh     key.Binding
	filter      key.Binding
	sort        key.Binding
	hidden      key.Binding
	tree        key.Binding
	perms       key.Binding
	view        key.Binding
	download    key.Binding
	upload      key.Binding
	mkdir       key.Binding
	rename      key.Binding
	delete      key.Binding
	export      key.Binding
	cancelScan  key.Binding
	disconnect  key.Binding
	help        key.Binding
	quit        key.Binding
	quitConnect key.Binding // the login form treats "q" as input

	nextField key.Binding
	prevField key.Binding
	choose    key.Binding
	connect   key.Binding

	confirm key.Binding
	cancel  key.Binding
	details key.Binding
	scroll  key.Binding
}

func defaultKeys() keyBindings {
	return keyBindings{
		up:     key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		down:   key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		top:    key.NewBinding(key.WithKeys("home"), key.WithHelp("home", "top")),
		bottom: key.NewBinding(key.WithKeys("end"), key.WithHelp("end", "bottom")),
		pgUp:   key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "page up")),
		pgDown: key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdn", "page down")),

		open:        key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open")),
		back:        key.NewBinding(key.WithKeys("esc", "q"), key.WithHelp("esc/q", "back")),
		parent:      key.NewBinding(key.WithKeys("backspace", "h"), key.WithHelp("h", "parent folder")),
		refresh:     key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		filter:      key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		sort:        key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "sort")),
		hidden:      key.NewBinding(key.WithKeys("."), key.WithHelp(".", "hidden files")),
		tree:        key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "recursive scan")),
		perms:       key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "permissions")),
		view:        key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "view")),
		download:    key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "download")),
		upload:      key.NewBinding(key.WithKeys("u"), key.WithHelp("u", "upload")),
		mkdir:       key.NewBinding(key.WithKeys("m"), key.WithHelp("m", "new folder")),
		rename:      key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "rename")),
		delete:      key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "delete")),
		export:      key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "export JSON")),
		cancelScan:  key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "stop scan")),
		disconnect:  key.NewBinding(key.WithKeys("esc", "c"), key.WithHelp("esc/c", "disconnect")),
		help:        key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		quit:        key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		quitConnect: key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "quit")),

		nextField: key.NewBinding(key.WithKeys("tab", "down"), key.WithHelp("tab", "next field")),
		prevField: key.NewBinding(key.WithKeys("shift+tab", "up"), key.WithHelp("shift+tab", "previous field")),
		choose:    key.NewBinding(key.WithKeys("left", "right"), key.WithHelp("←/→", "change")),
		connect:   key.NewBinding(key.WithKeys("ctrl+s"), key.WithHelp("ctrl+s", "connect")),

		confirm: key.NewBinding(key.WithKeys("y", "enter"), key.WithHelp("y/enter", "confirm")),
		cancel:  key.NewBinding(key.WithKeys("esc", "n"), key.WithHelp("esc", "cancel")),
		details: key.NewBinding(key.WithKeys("i"), key.WithHelp("i", "error details")),
		scroll:  key.NewBinding(key.WithKeys("up", "down", "pgup", "pgdown"), key.WithHelp("↑/↓", "scroll")),
	}
}

// The key maps below satisfy help.KeyMap for each screen.

type sharesKeys struct{ k keyBindings }

func (s sharesKeys) ShortHelp() []key.Binding {
	return []key.Binding{s.k.open, s.k.perms, s.k.tree, s.k.filter, s.k.disconnect, s.k.help, s.k.quit}
}

func (s sharesKeys) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{s.k.up, s.k.down, s.k.pgUp, s.k.pgDown, s.k.top, s.k.bottom},
		{s.k.open, s.k.perms, s.k.tree, s.k.refresh, s.k.filter, s.k.sort},
		{s.k.export, s.k.disconnect, s.k.help, s.k.quit},
	}
}

type browserKeys struct{ k keyBindings }

func (b browserKeys) ShortHelp() []key.Binding {
	return []key.Binding{b.k.open, b.k.view, b.k.download, b.k.upload, b.k.delete, b.k.tree, b.k.back, b.k.help}
}

func (b browserKeys) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{b.k.up, b.k.down, b.k.pgUp, b.k.pgDown, b.k.top, b.k.bottom},
		{b.k.open, b.k.view, b.k.download, b.k.upload, b.k.mkdir, b.k.rename, b.k.delete},
		{b.k.tree, b.k.perms, b.k.refresh, b.k.filter, b.k.sort, b.k.hidden, b.k.parent},
		{b.k.back, b.k.help},
	}
}

type treeKeys struct{ k keyBindings }

func (t treeKeys) ShortHelp() []key.Binding {
	return []key.Binding{t.k.up, t.k.down, t.k.scroll, t.k.filter, t.k.export, t.k.cancelScan, t.k.back, t.k.help}
}

func (t treeKeys) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{t.k.up, t.k.down, t.k.pgUp, t.k.pgDown, t.k.top, t.k.bottom},
		{t.k.filter, t.k.export, t.k.cancelScan, t.k.back, t.k.help},
	}
}

type viewerKeys struct{ k keyBindings }

func (v viewerKeys) ShortHelp() []key.Binding {
	return []key.Binding{v.k.up, v.k.down, v.k.pgUp, v.k.pgDown, v.k.top, v.k.bottom, v.k.back, v.k.help}
}

func (v viewerKeys) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{v.k.up, v.k.down, v.k.pgUp, v.k.pgDown, v.k.top, v.k.bottom},
		{v.k.back, v.k.help},
	}
}

type connectKeys struct{ k keyBindings }

func (c connectKeys) ShortHelp() []key.Binding {
	return []key.Binding{c.k.nextField, c.k.prevField, c.k.choose, c.k.connect, c.k.quitConnect}
}

func (c connectKeys) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{c.k.nextField, c.k.prevField, c.k.choose, c.k.connect},
		{c.k.quitConnect},
	}
}

type dialogKeys struct{ k keyBindings }

func (d dialogKeys) ShortHelp() []key.Binding {
	return []key.Binding{d.k.scroll, d.k.confirm, d.k.cancel}
}

func (d dialogKeys) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{d.k.scroll, d.k.confirm, d.k.cancel, d.k.details},
	}
}
