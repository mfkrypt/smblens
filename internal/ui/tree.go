package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
	"github.com/mfkrypt/smblens/internal/termtext"
)

// maxTreeItems bounds a recursive scan so a huge share cannot exhaust memory
// or make the interface unresponsive.
const maxTreeItems = 200_000

// maxTreeRows bounds the rows shown in the table; all discovered items stay in
// memory for export.
const maxTreeRows = 200_000

// treeEvent is sent from the scan goroutine to the interface.
type treeEvent struct {
	items     []smbclient.WalkItem
	stats     smbclient.WalkStats
	truncated bool
	done      bool
	err       error
}

type treeEventMsg struct {
	event treeEvent
}

type treeChannelClosedMsg struct{}

// treeModel shows the result of a recursive scan.
type treeModel struct {
	table   table.Model
	filter  textinput.Model
	items   []smbclient.WalkItem
	visible []smbclient.WalkItem
	rows    []table.Row

	host      string
	shareName string
	root      string

	stats     smbclient.WalkStats
	running   bool
	done      bool
	cancelled bool
	truncated bool
	filterCut bool
	err       error

	filtering     bool
	filterText    string
	width, height int
	theme         *theme

	ch     <-chan treeEvent
	cancel context.CancelFunc
}

// newTreeModel builds the scan results table, filter input and empty state.
func newTreeModel(t *theme) treeModel {
	tbl := table.New(
		table.WithColumns(treeColumns(80)),
		table.WithFocused(true),
	)
	st := table.DefaultStyles()
	st.Header = t.tableHeader
	st.Cell = t.tableCell
	st.Selected = t.tableSelect
	tbl.SetStyles(st)

	filter := newTextInput("filter paths")
	filter.Prompt = "filter › "
	filter.CharLimit = 160

	return treeModel{table: tbl, filter: filter, theme: t}
}

// treeColumns lays out the path, size, modification and type columns for the given width.
func treeColumns(width int) []table.Column {
	if width < 56 {
		width = 56
	}
	sizeWidth := 10
	timeWidth := 17
	kindWidth := 7
	overhead := 8
	pathWidth := width - overhead - sizeWidth - timeWidth - kindWidth
	if pathWidth < 18 {
		pathWidth = 18
	}
	return []table.Column{
		{Title: "PATH", Width: pathWidth},
		{Title: "SIZE", Width: sizeWidth},
		{Title: "MODIFIED", Width: timeWidth},
		{Title: "TYPE", Width: kindWidth},
	}
}

// setSize resizes the table, columns and filter for the available body area.
func (m *treeModel) setSize(width, height int) {
	m.width, m.height = width, height
	m.table.SetWidth(width)
	m.table.SetColumns(treeColumns(width))
	m.filter.Width = width - 16
	reserved := 3 // title, subtitle, and the selected-entry detail line
	if m.err != nil {
		reserved += 2
	}
	if m.truncated || m.filterCut {
		reserved++
	}
	if m.filtering {
		reserved++
	}
	tableHeight := height - reserved
	if tableHeight < 3 {
		tableHeight = 3
	}
	m.table.SetHeight(tableHeight)
}

// startScan begins a recursive scan using a freshly mounted share. The scan
// owns and closes its own tree connection.
func (m *treeModel) startScan(client *smbclient.Client, host, shareName, root string, maxDepth int) tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())

	m.host = host
	m.shareName = shareName
	m.root = root
	m.items = nil
	m.visible = nil
	m.rows = nil
	m.stats = smbclient.WalkStats{}
	m.running = true
	m.done = false
	m.cancelled = false
	m.truncated = false
	m.filterCut = false
	m.err = nil
	m.filtering = false
	m.filterText = ""
	m.filter.Blur()
	m.filter.SetValue("")
	m.cancel = cancel
	m.table.SetRows(nil)
	m.table.SetCursor(0)

	m.ch = runTreeScan(ctx, cancel, client, shareName, root, maxDepth)
	return waitForTreeEvent(m.ch)
}

// runTreeScan mounts the share, walks it, and streams batches of results. The
// scan owns its tree connection and closes it before finishing.
func runTreeScan(ctx context.Context, cancel context.CancelFunc, client *smbclient.Client, shareName, root string, maxDepth int) <-chan treeEvent {
	ch := make(chan treeEvent, 64)

	go func() {
		defer close(ch)

		share, err := client.Mount(ctx, shareName)
		if err != nil {
			sendTreeEvent(ch, treeEvent{done: true, err: err}, 2*time.Second)
			return
		}
		defer func() { _ = share.Close() }()

		var (
			batch     []smbclient.WalkItem
			stats     smbclient.WalkStats
			lastFlush = time.Now()
			count     int
			truncated bool
		)

		flush := func() {
			if len(batch) == 0 {
				return
			}
			sendTreeEvent(ch, treeEvent{items: batch, stats: stats}, time.Second)
			batch = nil
			lastFlush = time.Now()
		}

		opts := smbclient.WalkOptions{
			MaxDepth: maxDepth,
			Progress: func(s smbclient.WalkStats) { stats = s },
		}
		walkErr := share.WalkShare(ctx, root, opts, func(item smbclient.WalkItem) {
			if count >= maxTreeItems {
				truncated = true
				flush()
				cancel()
				return
			}
			count++
			batch = append(batch, item)
			if len(batch) >= 250 || time.Since(lastFlush) >= 120*time.Millisecond {
				flush()
			}
		})
		flush()

		if truncated && errors.Is(walkErr, context.Canceled) {
			walkErr = nil
		}
		sendTreeEvent(ch, treeEvent{stats: stats, truncated: truncated, done: true, err: walkErr}, 2*time.Second)
	}()

	return ch
}

// sendTreeEvent delivers a scan event unless the consumer has gone away within the timeout.
func sendTreeEvent(ch chan<- treeEvent, event treeEvent, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ch <- event:
	case <-timer.C:
	}
}

// waitForTreeEvent waits for the next scan batch or reports that the scan stream closed.
func waitForTreeEvent(ch <-chan treeEvent) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-ch
		if !ok {
			return treeChannelClosedMsg{}
		}
		return treeEventMsg{event: event}
	}
}

// handleEvent merges a streamed batch into the model and reports whether the
// scan is finished.
func (m *treeModel) handleEvent(event treeEvent) bool {
	m.appendItems(event.items)
	if event.stats != (smbclient.WalkStats{}) || event.done {
		m.stats = event.stats
	}
	if event.truncated {
		m.truncated = true
	}
	if !event.done {
		return false
	}

	m.running = false
	m.done = true
	m.cancel = nil
	switch {
	case errors.Is(event.err, context.Canceled):
		m.cancelled = true
	case event.err != nil:
		m.err = event.err
	}
	m.setSize(m.width, m.height)
	return true
}

// appendItems adds streamed scan items to the model and its filtered table rows.
func (m *treeModel) appendItems(items []smbclient.WalkItem) {
	if len(items) == 0 {
		return
	}
	needle := strings.ToLower(strings.TrimSpace(m.filterText))
	for _, item := range items {
		m.items = append(m.items, item)
		if needle != "" && !strings.Contains(strings.ToLower(item.Path), needle) {
			continue
		}
		if len(m.visible) >= maxTreeRows {
			m.filterCut = true
			continue
		}
		m.visible = append(m.visible, item)
		m.rows = append(m.rows, treeRow(item))
	}
	m.table.SetRows(m.rows)
}

// treeRow formats one scan item as a table row.
func treeRow(item smbclient.WalkItem) table.Row {
	name := termtext.Clean(item.Path)
	if item.Dir {
		name += "/"
	}
	size := formatSize(item.Size)
	if item.Dir {
		size = "-"
	}
	kind := fileKind(item.Entry)
	if item.Err != nil {
		size = "-"
		kind = "ERROR"
	}
	return table.Row{name, size, formatTime(item.ModTime), kind}
}

// cancelScan stops an in-progress scan. Completed results remain visible.
func (m *treeModel) cancelScan() {
	if m.cancel != nil {
		m.cancel()
		m.cancelled = true
	}
}

// detach stops the scan and drains its channel, for when the screen is left.
func (m *treeModel) detach() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if m.ch != nil {
		drainTreeChannel(m.ch)
		m.ch = nil
	}
}

// drainTreeChannel consumes a scan channel in the background so its producer can exit.
func drainTreeChannel(ch <-chan treeEvent) {
	go func() {
		for range ch {
		}
	}()
}

// selected returns the scan item under the table cursor and whether one exists.
func (m *treeModel) selected() (smbclient.WalkItem, bool) {
	cursor := m.table.Cursor()
	if cursor < 0 || cursor >= len(m.visible) {
		return smbclient.WalkItem{}, false
	}
	return m.visible[cursor], true
}

// selectedError returns the error attached to the selected scan item, if any.
func (m *treeModel) selectedError() string {
	item, ok := m.selected()
	if !ok || item.Err == nil {
		return ""
	}
	return item.Err.Error()
}

// startFilter focuses the filter input while keeping the existing filter text.
func (m *treeModel) startFilter() tea.Cmd {
	m.filtering = true
	m.filter.SetValue(m.filterText)
	m.filter.CursorEnd()
	m.rebuildRows()
	m.setSize(m.width, m.height)
	return m.filter.Focus()
}

// stopFilter leaves filter mode, optionally clearing the filter text.
func (m *treeModel) stopFilter(clear bool) {
	m.filtering = false
	m.filter.Blur()
	if clear {
		m.filterText = ""
	}
	m.rebuildRows()
	m.setSize(m.width, m.height)
}

// handleFilterKey handles esc and enter and forwards other keys to the filter input.
func (m *treeModel) handleFilterKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		m.stopFilter(true)
		return nil
	case "enter":
		m.stopFilter(false)
		return nil
	}
	var cmd tea.Cmd
	m.filter, cmd = m.filter.Update(msg)
	m.filterText = m.filter.Value()
	m.rebuildRows()
	return cmd
}

// rebuildRows reapplies the filter to all collected scan items.
func (m *treeModel) rebuildRows() {
	needle := strings.ToLower(strings.TrimSpace(m.filterText))
	m.visible = m.visible[:0]
	m.rows = m.rows[:0]
	m.filterCut = false
	for _, item := range m.items {
		if needle != "" && !strings.Contains(strings.ToLower(item.Path), needle) {
			continue
		}
		if len(m.visible) >= maxTreeRows {
			m.filterCut = true
			break
		}
		m.visible = append(m.visible, item)
		m.rows = append(m.rows, treeRow(item))
	}
	m.table.SetRows(m.rows)
	m.setSize(m.width, m.height)
}

// updateTable forwards navigation keys to the table model.
func (m *treeModel) updateTable(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return cmd
}

// View renders the scan title, statistics, warnings, errors and result table.
func (m *treeModel) View() string {
	t := m.theme
	title := t.appTitle.Render("Recursive scan") + t.muted.Render("  "+m.pathLabel())

	state := "scanning…"
	switch {
	case m.cancelled:
		state = "cancelled"
	case m.done && m.err == nil:
		state = "complete"
	}
	stats := fmt.Sprintf("%s · %d folder%s · %d file%s · %s · %d error%s",
		state,
		m.stats.Dirs, plural(m.stats.Dirs, "", "s"),
		m.stats.Files, plural(m.stats.Files, "", "s"),
		formatSize(m.stats.Bytes),
		m.stats.Errors, plural(m.stats.Errors, "", "s"),
	)
	if m.filtering || m.filterText != "" {
		stats += fmt.Sprintf(" · %d shown", len(m.visible))
	}
	subtitle := t.muted.Render(stats)

	parts := []string{title, subtitle}
	if m.err != nil {
		parts = append(parts, t.errorBox.Render(smbclient.Describe(m.err)))
	}
	if m.truncated {
		parts = append(parts, t.warning.Render(fmt.Sprintf("Stopped after %d entries; increase the depth limit or scan a smaller folder.", maxTreeItems)))
	} else if m.filterCut {
		parts = append(parts, t.warning.Render("Only the first matching entries are shown."))
	}
	switch {
	case len(m.visible) == 0 && m.running:
		parts = append(parts, "", t.muted.Render("Scanning…"))
	case len(m.visible) == 0 && m.done:
		parts = append(parts, "", t.muted.Render("Nothing was found."))
	default:
		parts = append(parts, m.table.View())
	}
	if detail := m.selectedError(); detail != "" {
		parts = append(parts, t.danger.Render("error: "+termtext.Clean(detail)))
	} else {
		parts = append(parts, "")
	}
	if m.filtering {
		parts = append(parts, t.filter.Render(" ")+m.filter.View())
	}
	return strings.Join(parts, "\n")
}

// pathLabel formats the scanned host, share and root as a UNC path.
func (m *treeModel) pathLabel() string {
	base := `\\` + termtext.Clean(m.host) + `\` + termtext.Clean(m.shareName)
	if m.root != "" {
		base += `\` + termtext.Clean(strings.ReplaceAll(m.root, "/", `\`))
	}
	return base
}
