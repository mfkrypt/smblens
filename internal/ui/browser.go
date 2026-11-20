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

// browserSort selects the directory ordering.
type browserSort int

const (
	browserSortName browserSort = iota
	browserSortSize
	browserSortModified
)

// browserModel is the directory browsing screen.
type browserModel struct {
	table   table.Model
	filter  textinput.Model
	entries []smbclient.Entry
	visible []smbclient.Entry

	share     *smbclient.Share
	host      string
	shareName string
	path      string

	sortMode      browserSort
	showHidden    bool
	filtering     bool
	filterText    string
	loading       bool
	err           error
	width, height int
	theme         *theme
}

func newBrowserModel(t *theme) browserModel {
	tbl := table.New(
		table.WithColumns(browserColumns(80)),
		table.WithFocused(true),
	)
	st := table.DefaultStyles()
	st.Header = t.tableHeader
	st.Cell = t.tableCell
	st.Selected = t.tableSelect
	tbl.SetStyles(st)

	filter := newTextInput("filter names")
	filter.Prompt = "filter › "
	filter.CharLimit = 120

	return browserModel{table: tbl, filter: filter, theme: t}
}

func browserColumns(width int) []table.Column {
	if width < 56 {
		width = 56
	}
	sizeWidth := 10
	timeWidth := 17
	kindWidth := 7
	overhead := 8
	nameWidth := width - overhead - sizeWidth - timeWidth - kindWidth
	if nameWidth < 18 {
		nameWidth = 18
	}
	return []table.Column{
		{Title: "NAME", Width: nameWidth},
		{Title: "SIZE", Width: sizeWidth},
		{Title: "MODIFIED", Width: timeWidth},
		{Title: "TYPE", Width: kindWidth},
	}
}

func (m *browserModel) setSize(width, height int) {
	m.width, m.height = width, height
	m.table.SetWidth(width)
	m.table.SetColumns(browserColumns(width))
	m.filter.Width = width - 16

	reserved := 2 // title and path
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

func (m *browserModel) setLoading() {
	m.loading = true
	m.err = nil
}

func (m *browserModel) setData(path string, entries []smbclient.Entry, err error) {
	m.loading = false
	m.err = err
	m.path = path
	m.entries = entries
	m.rebuild()
	m.setSize(m.width, m.height)
}

// setShare records which mounted share is being browsed.
func (m *browserModel) setShare(share *smbclient.Share, name string) {
	m.share = share
	m.shareName = name
	if share != nil {
		m.host = share.Host()
	}
}

// clear detaches from the share when leaving the browser.
func (m *browserModel) clear() {
	m.share = nil
	m.host = ""
	m.shareName = ""
	m.path = ""
	m.entries = nil
	m.visible = nil
	m.table.SetRows(nil)
	m.err = nil
	m.loading = false
}

func (m *browserModel) rebuild() {
	needle := strings.ToLower(strings.TrimSpace(m.filterText))
	filtered := make([]smbclient.Entry, 0, len(m.entries))
	for _, entry := range m.entries {
		if entry.Hidden && !m.showHidden {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(entry.Name), needle) {
			continue
		}
		filtered = append(filtered, entry)
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].Dir != filtered[j].Dir {
			return filtered[i].Dir
		}
		switch m.sortMode {
		case browserSortSize:
			if filtered[i].Size != filtered[j].Size {
				return filtered[i].Size > filtered[j].Size
			}
		case browserSortModified:
			if !filtered[i].ModTime.Equal(filtered[j].ModTime) {
				return filtered[i].ModTime.After(filtered[j].ModTime)
			}
		}
		return strings.ToLower(filtered[i].Name) < strings.ToLower(filtered[j].Name)
	})

	rows := make([]table.Row, 0, len(filtered))
	for _, entry := range filtered {
		name := termtext.Clean(entry.Name)
		switch {
		case entry.Dir:
			name += "/"
		case entry.Symlink:
			name += "@"
		}
		size := formatSize(entry.Size)
		if entry.Dir {
			size = "-"
		}
		rows = append(rows, table.Row{
			name,
			size,
			formatTime(entry.ModTime),
			fileKind(entry),
		})
	}

	m.visible = filtered
	m.table.SetRows(rows)
	if cursor := m.table.Cursor(); cursor >= len(rows) {
		m.table.SetCursor(len(rows) - 1)
	}
	if m.table.Cursor() < 0 {
		m.table.SetCursor(0)
	}
}

func (m *browserModel) selected() (smbclient.Entry, bool) {
	cursor := m.table.Cursor()
	if cursor < 0 || cursor >= len(m.visible) {
		return smbclient.Entry{}, false
	}
	return m.visible[cursor], true
}

func (m *browserModel) startFilter() tea.Cmd {
	m.filtering = true
	m.filter.SetValue("")
	m.filterText = ""
	m.rebuild()
	m.setSize(m.width, m.height)
	return m.filter.Focus()
}

func (m *browserModel) stopFilter(clear bool) {
	m.filtering = false
	m.filter.Blur()
	if clear {
		m.filterText = ""
	}
	m.filter.SetValue(m.filterText)
	m.rebuild()
	m.setSize(m.width, m.height)
}

func (m *browserModel) handleFilterKey(msg tea.KeyMsg) tea.Cmd {
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

func (m *browserModel) updateTable(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return cmd
}

func (m *browserModel) cycleSort() {
	switch m.sortMode {
	case browserSortName:
		m.sortMode = browserSortModified
	case browserSortModified:
		m.sortMode = browserSortSize
	default:
		m.sortMode = browserSortName
	}
	m.rebuild()
}

func (m *browserModel) toggleHidden() {
	m.showHidden = !m.showHidden
	m.rebuild()
}

func (m *browserModel) sortLabel() string {
	switch m.sortMode {
	case browserSortSize:
		return "size"
	case browserSortModified:
		return "modified"
	default:
		return "name"
	}
}

func (m *browserModel) View() string {
	t := m.theme
	title := t.appTitle.Render("Share") + t.muted.Render("  "+m.uncPath())
	pathLine := t.breadcrumb.Render(m.uncPath() + pathSuffix(m.path))

	status := fmt.Sprintf("%d entr%s", len(m.visible), plural(len(m.visible), "y", "ies"))
	if len(m.visible) != len(m.entries) {
		status += fmt.Sprintf(" · %d total", len(m.entries))
	}
	status += " · sort " + m.sortLabel()
	if m.showHidden {
		status += " · hidden shown"
	}
	subtitle := t.muted.Render(status)

	parts := []string{title, pathLine + "  " + subtitle}
	if m.err != nil {
		parts = append(parts, t.errorBox.Render(smbclient.Describe(m.err)))
	}
	switch {
	case m.loading && len(m.entries) == 0:
		parts = append(parts, "", t.muted.Render("Listing…"))
	case len(m.entries) == 0 && m.err == nil:
		parts = append(parts, "", t.muted.Render("This folder is empty."))
	case len(m.visible) == 0:
		parts = append(parts, "", t.muted.Render("No entries match the filter."))
	default:
		parts = append(parts, m.table.View())
	}
	if m.filtering {
		parts = append(parts, m.theme.filter.Render(" ")+m.filter.View())
	}
	return strings.Join(parts, "\n")
}

// uncDisplay formats a share name for display.
func (m *browserModel) uncPath() string {
	if m.shareName == "" {
		return ""
	}
	host := m.host
	if host == "" && m.share != nil {
		host = m.share.Host()
	}
	return `\\` + termtext.Clean(host) + `\` + termtext.Clean(m.shareName)
}

// pathSuffix renders the path component with a leading backslash.
func pathSuffix(p string) string {
	if p == "" {
		return `\`
	}
	return `\` + termtext.Clean(strings.ReplaceAll(p, "/", `\`))
}
