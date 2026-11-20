package ui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/mfkrypt/smblens/internal/smbclient"
)

// palette holds the adaptive colours used throughout the interface.
type palette struct {
	accent   lipgloss.AdaptiveColor
	text     lipgloss.AdaptiveColor
	muted    lipgloss.AdaptiveColor
	faint    lipgloss.AdaptiveColor
	success  lipgloss.AdaptiveColor
	warning  lipgloss.AdaptiveColor
	danger   lipgloss.AdaptiveColor
	selected lipgloss.AdaptiveColor
}

var colors = palette{
	accent:   lipgloss.AdaptiveColor{Light: "#5B46CC", Dark: "#A78BFA"},
	text:     lipgloss.AdaptiveColor{Light: "#1F2937", Dark: "#E5E7EB"},
	muted:    lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#9CA3AF"},
	faint:    lipgloss.AdaptiveColor{Light: "#9CA3AF", Dark: "#6B7280"},
	success:  lipgloss.AdaptiveColor{Light: "#15803D", Dark: "#4ADE80"},
	warning:  lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"},
	danger:   lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#F87171"},
	selected: lipgloss.AdaptiveColor{Light: "#EDE9FE", Dark: "#312E81"},
}

// theme is the set of styles used by the screens.
type theme struct {
	appTitle    lipgloss.Style
	label       lipgloss.Style
	labelActive lipgloss.Style
	value       lipgloss.Style
	muted       lipgloss.Style
	faint       lipgloss.Style
	accent      lipgloss.Style
	success     lipgloss.Style
	warning     lipgloss.Style
	danger      lipgloss.Style
	breadcrumb  lipgloss.Style
	header      lipgloss.Style
	footer      lipgloss.Style
	status      lipgloss.Style
	errorBox    lipgloss.Style
	dialog      lipgloss.Style
	dialogTitle lipgloss.Style
	tableHeader lipgloss.Style
	tableCell   lipgloss.Style
	tableSelect lipgloss.Style
	filter      lipgloss.Style
}

func newTheme() *theme {
	return &theme{
		appTitle:    lipgloss.NewStyle().Bold(true).Foreground(colors.accent),
		label:       lipgloss.NewStyle().Foreground(colors.muted),
		labelActive: lipgloss.NewStyle().Bold(true).Foreground(colors.accent),
		value:       lipgloss.NewStyle().Foreground(colors.text),
		muted:       lipgloss.NewStyle().Foreground(colors.muted),
		faint:       lipgloss.NewStyle().Foreground(colors.faint),
		accent:      lipgloss.NewStyle().Foreground(colors.accent),
		success:     lipgloss.NewStyle().Foreground(colors.success),
		warning:     lipgloss.NewStyle().Foreground(colors.warning),
		danger:      lipgloss.NewStyle().Foreground(colors.danger),
		breadcrumb:  lipgloss.NewStyle().Foreground(colors.text).Bold(true),
		header: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(colors.faint).
			Padding(0, 1),
		footer: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), true, false, false, false).
			BorderForeground(colors.faint).
			Padding(0, 1),
		status: lipgloss.NewStyle().Padding(0, 1),
		errorBox: lipgloss.NewStyle().
			Foreground(colors.danger).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colors.danger).
			Padding(0, 1),
		dialog: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colors.accent).
			Padding(1, 2),
		dialogTitle: lipgloss.NewStyle().Bold(true).Foreground(colors.accent).MarginBottom(1),
		tableHeader: lipgloss.NewStyle().Bold(true).Foreground(colors.accent).Padding(0, 1),
		tableCell:   lipgloss.NewStyle().Foreground(colors.text).Padding(0, 1),
		tableSelect: lipgloss.NewStyle().Bold(true).Background(colors.selected).Foreground(colors.text).Padding(0, 1),
		filter:      lipgloss.NewStyle().Foreground(colors.warning),
	}
}

// kindLabel shortens a share kind for the table.
func kindLabel(kind smbclient.ShareKind) string {
	switch kind {
	case smbclient.ShareDisk:
		return "disk"
	case smbclient.SharePrint:
		return "print"
	case smbclient.ShareDevice:
		return "device"
	case smbclient.ShareIPC:
		return "ipc"
	default:
		return "other"
	}
}
