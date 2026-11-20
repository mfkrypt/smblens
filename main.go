// Command smblens is an interactive SMB client for Active Directory share
// enumeration.
package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/config"
	"github.com/mfkrypt/smblens/internal/ui"
)

func main() {
	opts, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "smblens: %v\nTry 'smblens --help'.\n", err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		fmt.Print(config.Usage())
		return
	}
	if opts.ShowVersion {
		fmt.Printf("SMBLens %s\n", config.Version)
		return
	}

	if !isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "smblens: an interactive terminal is required (stdin is not a TTY).")
		os.Exit(1)
	}

	app := ui.New(opts)
	program := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		app.Close()
		fmt.Fprintf(os.Stderr, "smblens: %v\n", err)
		os.Exit(1)
	}
	app.Close()
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
