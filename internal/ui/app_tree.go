// Recursive scan events and exports.

package ui

import (
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
)

// onTreeEvent merges a streamed scan batch and requests the next batch until the scan finishes.
func (a *App) onTreeEvent(msg treeEventMsg) (tea.Model, tea.Cmd) {
	if a.screen != screenTree {
		return a, nil
	}
	done := a.tree.handleEvent(msg.event)
	if done {
		if msg.event.err != nil {
			a.lastErr = msg.event.err
			if a.fatal(msg.event.err) {
				return a, nil
			}
		}
		return a, nil
	}
	return a, waitForTreeEvent(a.tree.ch)
}

// exportTree writes the collected scan results to a JSON file and reports the result.
func (a *App) exportTree() (tea.Model, tea.Cmd) {
	if len(a.tree.items) == 0 {
		return a, a.setToast("There is nothing to export yet.", true)
	}
	path := treeExportName(a.cfg.Host, a.tree.shareName)
	items := a.tree.items
	host, share, root := a.tree.host, a.tree.shareName, a.tree.root

	a.seqOp++
	seq := a.seqOp
	return a, func() tea.Msg {
		err := writeTreeReport(path, host, share, root, items)
		if err == nil {
			if abs, absErr := filepath.Abs(path); absErr == nil {
				path = abs
			}
		}
		return operationDoneMsg{seq: seq, desc: "Exported " + path, err: err}
	}
}
