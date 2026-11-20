package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mfkrypt/smblens/internal/smbclient"
	"github.com/mfkrypt/smblens/internal/termtext"
)

// viewerModel displays a remote text file.
type viewerModel struct {
	viewport viewport.Model
	raw      string

	host      string
	shareName string
	path      string

	loading   bool
	err       error
	binary    bool
	truncated bool
	size      int64

	width, height int
	theme         *theme
}

func newViewerModel(t *theme) viewerModel {
	return viewerModel{
		viewport: viewport.New(80, 20),
		theme:    t,
	}
}

func (m *viewerModel) open(host, shareName, path string) {
	m.host = host
	m.shareName = shareName
	m.path = path
	m.loading = true
	m.err = nil
	m.binary = false
	m.truncated = false
	m.size = 0
	m.raw = ""
	m.viewport.SetContent("")
	m.viewport.SetYOffset(0)
	m.viewport.SetXOffset(0)
}

func (m *viewerModel) setContent(content smbclient.FileContent, err error) {
	m.loading = false
	m.err = err
	m.binary = content.Binary
	m.truncated = content.Truncated
	m.size = content.Size
	if err != nil {
		m.raw = ""
		m.wrapContent()
		return
	}
	if content.Binary {
		m.raw = ""
		m.wrapContent()
		return
	}
	m.raw = termtext.CleanMultiline(string(content.Data))
	m.wrapContent()
	m.viewport.SetYOffset(0)
}

// wrapContent reflows the text to the current width. Lip Gloss wraps at the
// style's width, so long lines remain readable in the viewport.
func (m *viewerModel) wrapContent() {
	width := m.viewport.Width
	if width < 20 {
		width = 20
	}
	if m.raw == "" {
		m.viewport.SetContent("")
		return
	}
	wrapped := lipgloss.NewStyle().Width(width).Render(m.raw)
	m.viewport.SetContent(wrapped)
}

func (m *viewerModel) setSize(width, height int) {
	m.width, m.height = width, height
	m.viewport.Width = width - 2
	reserved := 3 // title, location, blank
	if m.binary || m.truncated || m.err != nil {
		reserved++
	}
	m.viewport.Height = height - reserved
	if m.viewport.Height < 3 {
		m.viewport.Height = 3
	}
	m.wrapContent()
}

func (m *viewerModel) update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return cmd
}

func (m *viewerModel) reset() {
	m.path = ""
	m.raw = ""
	m.err = nil
	m.loading = false
	m.viewport.SetContent("")
}

func (m *viewerModel) View() string {
	t := m.theme
	title := t.appTitle.Render("View") + t.muted.Render("  "+termtext.Clean(m.path))
	location := t.muted.Render(`\\` + termtext.Clean(m.host) + `\` + termtext.Clean(m.shareName))

	parts := []string{title, location}

	switch {
	case m.loading:
		parts = append(parts, "", t.muted.Render("Loading…"))
		return strings.Join(parts, "\n")
	case m.err != nil:
		parts = append(parts, t.errorBox.Render(smbclient.Describe(m.err)))
		return strings.Join(parts, "\n")
	case m.binary:
		parts = append(parts, "",
			t.warning.Render(fmt.Sprintf("This file looks binary (%s). Download it to inspect it locally.", formatSize(m.size))))
		return strings.Join(parts, "\n")
	}

	if m.truncated {
		parts = append(parts, t.warning.Render(fmt.Sprintf(
			"Showing the first %s of %s.", formatSize(int64(smbclient.MaxViewBytes)), formatSize(m.size))))
	}
	parts = append(parts, "", m.viewport.View())
	return strings.Join(parts, "\n")
}
