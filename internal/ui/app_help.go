// Help and error dialogs.

package ui

import (
	"github.com/charmbracelet/bubbles/help"
	tea "github.com/charmbracelet/bubbletea"
)

func (a *App) openHelp() (tea.Model, tea.Cmd) {
	h := help.New()
	h.ShowAll = true
	h.Width = a.dialog.textWidth()
	body := h.View(a.currentKeyMap())
	a.dialog.openHelp("Keys · "+a.screen.String(), body)
	a.dialog.setSize(a.width, a.height)
	return a, nil
}

func (a *App) openErrorDialog(title string, err error) (tea.Model, tea.Cmd) {
	a.dialog.openError(title, err)
	a.dialog.setSize(a.width, a.height)
	a.lastErr = err
	return a, nil
}

func (a *App) currentKeyMap() help.KeyMap {
	if a.dialog.active() {
		return dialogKeys{a.keys}
	}
	switch a.screen {
	case screenShares:
		return sharesKeys{a.keys}
	case screenBrowser:
		return browserKeys{a.keys}
	case screenTree:
		return treeKeys{a.keys}
	case screenViewer:
		return viewerKeys{a.keys}
	default:
		return connectKeys{a.keys}
	}
}
