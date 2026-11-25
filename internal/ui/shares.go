package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
	"github.com/mfkrypt/smblens/internal/termtext"
)

// shareSort selects the share list ordering.
type shareSort int

const (
	shareSortName shareSort = iota
	shareSortAccess
)

// sharesModel is the share enumeration screen.
type sharesModel struct {
	table   table.Model
	filter  textinput.Model
	all     []smbclient.ShareInfo
	visible []smbclient.ShareInfo

	host        string
	probeWrites bool
	sortMode    shareSort
	filtering   bool
	filterText  string
	loading     bool
	err         error

	width, height int
	theme         *theme
}

// newSharesModel builds the share table, filter input and empty enumeration state.
func newSharesModel(t *theme) sharesModel {
	tbl := table.New(
		table.WithColumns(shareColumns(80)),
		table.WithFocused(true),
	)
	st := table.DefaultStyles()
	st.Header = t.tableHeader
	st.Cell = t.tableCell
	st.Selected = t.tableSelect
	tbl.SetStyles(st)

	filter := newTextInput("filter shares")
	filter.Prompt = "filter › "
	filter.CharLimit = 120

	return sharesModel{table: tbl, filter: filter, theme: t}
}

// shareColumns lays out the name, type, access and comment columns for the given width.
func shareColumns(width int) []table.Column {
	if width < 50 {
		width = 50
	}
	nameWidth := 24
	kindWidth := 8
	accessWidth := 10
	overhead := 8
	commentWidth := width - overhead - nameWidth - kindWidth - accessWidth
	if commentWidth < 8 {
		commentWidth = 8
	}
	return []table.Column{
		{Title: "NAME", Width: nameWidth},
		{Title: "TYPE", Width: kindWidth},
		{Title: "ACCESS", Width: accessWidth},
		{Title: "COMMENT", Width: commentWidth},
	}
}

// setSize resizes the table, columns and filter for the available body area.
func (m *sharesModel) setSize(width, height int) {
	m.width, m.height = width, height
	m.table.SetWidth(width)
	m.table.SetColumns(shareColumns(width))
	m.filter.Width = width - 16
	reserved := 2 // title and subtitle
	if m.err != nil {
		reserved += 2
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

// setContext records the server and whether write probing was enabled for the status line.
func (m *sharesModel) setContext(host string, probeWrites bool) {
	m.host = host
	m.probeWrites = probeWrites
}

// setLoading clears the previous error and marks the enumeration as in progress.
func (m *sharesModel) setLoading() {
	m.loading = true
	m.err = nil
}

// setData installs a share enumeration, clears the loading state and rebuilds the visible rows.
func (m *sharesModel) setData(entries []smbclient.ShareInfo, err error) {
	m.loading = false
	m.err = err
	m.all = entries
	m.rebuild()
	m.setSize(m.width, m.height)
}

// rebuild applies the filter and sort then updates the table rows.
func (m *sharesModel) rebuild() {
	needle := strings.ToLower(strings.TrimSpace(m.filterText))
	filtered := make([]smbclient.ShareInfo, 0, len(m.all))
	for _, share := range m.all {
		if needle != "" {
			haystack := strings.ToLower(share.Name + " " + share.Comment)
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		filtered = append(filtered, share)
	}

	switch m.sortMode {
	case shareSortAccess:
		sort.SliceStable(filtered, func(i, j int) bool {
			ri, rj := accessRank(filtered[i].Access), accessRank(filtered[j].Access)
			if ri != rj {
				return ri < rj
			}
			return strings.ToLower(filtered[i].Name) < strings.ToLower(filtered[j].Name)
		})
	default:
		sort.SliceStable(filtered, func(i, j int) bool {
			if filtered[i].Special != filtered[j].Special {
				return !filtered[i].Special
			}
			return strings.ToLower(filtered[i].Name) < strings.ToLower(filtered[j].Name)
		})
	}

	rows := make([]table.Row, 0, len(filtered))
	for _, share := range filtered {
		kind := kindLabel(share.Kind)
		if share.Special {
			kind = "admin"
		}
		rows = append(rows, table.Row{
			termtext.Clean(share.Name),
			kind,
			share.Access.Label(),
			termtext.Clean(share.Comment),
		})
	}

	m.visible = filtered
	m.table.SetRows(rows)
	if len(rows) == 0 {
		m.table.SetCursor(0)
	}
}

// accessRank assigns shares a sort position based on their effective access.
func accessRank(state smbclient.AccessState) int {
	switch {
	case state.Denied:
		return 3
	case !state.Mounted && state.Err != nil:
		return 4
	case state.Read && state.Write:
		return 0
	case state.Read:
		return 1
	case state.Write:
		return 2
	default:
		return 5
	}
}

// selected returns the share under the table cursor and whether one exists.
func (m *sharesModel) selected() (smbclient.ShareInfo, bool) {
	cursor := m.table.Cursor()
	if cursor < 0 || cursor >= len(m.visible) {
		return smbclient.ShareInfo{}, false
	}
	return m.visible[cursor], true
}

// startFilter focuses the filter input and clears any previous filter.
func (m *sharesModel) startFilter() tea.Cmd {
	m.filtering = true
	m.filter.SetValue("")
	m.filterText = ""
	m.rebuild()
	m.setSize(m.width, m.height)
	return m.filter.Focus()
}

// stopFilter leaves filter mode, optionally clearing the filter text.
func (m *sharesModel) stopFilter(clear bool) {
	m.filtering = false
	m.filter.Blur()
	if clear {
		m.filterText = ""
	}
	m.filter.SetValue(m.filterText)
	m.rebuild()
	m.setSize(m.width, m.height)
}

// handleFilterKey routes a key press while the filter is active.
func (m *sharesModel) handleFilterKey(msg tea.KeyMsg) tea.Cmd {
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
	m.rebuild()
	return cmd
}

// cycleSort switches between name order and access order.
func (m *sharesModel) cycleSort() {
	if m.sortMode == shareSortName {
		m.sortMode = shareSortAccess
	} else {
		m.sortMode = shareSortName
	}
	m.rebuild()
}

// updateTable forwards navigation keys to the table.
func (m *sharesModel) updateTable(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return cmd
}

// View renders the share title, probe status, errors and table.
func (m *sharesModel) View() string {
	t := m.theme
	title := t.appTitle.Render("Shares") + t.muted.Render("  on "+termtext.Clean(m.host))

	status := fmt.Sprintf("%d share%s", len(m.all), plural(len(m.all), "", "s"))
	if len(m.visible) != len(m.all) {
		status += fmt.Sprintf(" · %d matching", len(m.visible))
	}
	if m.probeWrites {
		status += " · write probe on"
	} else {
		status += " · write probe off"
	}
	if m.sortMode == shareSortAccess {
		status += " · sorted by access"
	}
	subtitle := t.muted.Render(status)

	parts := []string{title, subtitle}
	if m.err != nil {
		parts = append(parts, t.errorBox.Render(smbclient.Describe(m.err)))
	}
	switch {
	case m.loading && len(m.all) == 0:
		parts = append(parts, "", t.muted.Render("Enumerating shares and probing access…"))
	case len(m.all) == 0 && m.err == nil:
		parts = append(parts, "", t.muted.Render("The server returned no shares."))
	case len(m.visible) == 0:
		parts = append(parts, "", t.muted.Render("No shares match the filter."))
	default:
		parts = append(parts, m.table.View())
	}
	if m.filtering {
		parts = append(parts, m.theme.filter.Render(" ")+m.filter.View())
	}
	return strings.Join(parts, "\n")
}
