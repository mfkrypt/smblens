package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mfkrypt/smblens/internal/smbclient"
	"github.com/mfkrypt/smblens/internal/termtext"
)

// dialogKind identifies the modal currently shown.
type dialogKind int

const (
	dialogNone dialogKind = iota
	dialogHelp
	dialogConfirm
	dialogPrompt
	dialogError
	dialogPermissions
	dialogTransfer
)

// actionKind identifies what a prompt or confirmation will do on submit.
type actionKind int

const (
	actionNone actionKind = iota
	actionDeleteEntry
	actionMkdir
	actionRename
	actionUpload
	actionDownload
	actionDownloadTree
	actionExportShares
	actionExportTree
)

// pendingAction carries the context a dialog needs when it is confirmed.
type pendingAction struct {
	kind      actionKind
	entry     smbclient.Entry
	path      string
	localPath string
}

// dialogModel renders the modal overlays: help, confirmations, text prompts,
// error details, permission reports, and transfers.
type dialogModel struct {
	kind     dialogKind
	title    string
	body     string
	prompt   textinput.Model
	viewport viewport.Model
	pending  pendingAction
	loading  bool
	err      error

	transfer *transferState

	width, height int
	theme         *theme
}

// newDialog builds the modal model and its prompt and viewport widgets.
func newDialog(t *theme) dialogModel {
	prompt := newTextInput("")
	prompt.Prompt = "› "
	return dialogModel{
		prompt:   prompt,
		viewport: viewport.New(80, 16),
		theme:    t,
	}
}

// active reports whether a modal is currently displayed.
func (d *dialogModel) active() bool { return d.kind != dialogNone }

// close dismisses the modal and clears its transient state.
func (d *dialogModel) close() {
	d.kind = dialogNone
	d.title = ""
	d.body = ""
	d.pending = pendingAction{}
	d.loading = false
	d.err = nil
	d.transfer = nil
	d.prompt.Blur()
}

// setSize records the terminal size used to lay out the dialog.
func (d *dialogModel) setSize(width, height int) {
	d.width, d.height = width, height
}

// openHelp displays scrollable help text.
func (d *dialogModel) openHelp(title, body string) {
	d.kind = dialogHelp
	d.title = title
	d.body = body
	d.err = nil
	d.loading = false
	d.viewport.SetContent(body)
	d.viewport.SetYOffset(0)
}

// openConfirm displays a yes/no confirmation and stores the action to run on confirmation.
func (d *dialogModel) openConfirm(title, body string, pending pendingAction) {
	d.kind = dialogConfirm
	d.title = termtext.Clean(title)
	d.body = termtext.CleanMultiline(body)
	d.pending = pending
	d.err = nil
	d.loading = false
}

// openPrompt displays a text prompt and focuses its input.
func (d *dialogModel) openPrompt(title, body, initial, placeholder string, pending pendingAction) tea.Cmd {
	d.kind = dialogPrompt
	d.title = termtext.Clean(title)
	d.body = termtext.CleanMultiline(body)
	d.pending = pending
	d.err = nil
	d.loading = false
	d.prompt.SetValue(initial)
	d.prompt.Placeholder = placeholder
	d.prompt.CursorEnd()
	return d.prompt.Focus()
}

// openError displays technical error details and remediation hints.
func (d *dialogModel) openError(title string, err error) {
	d.kind = dialogError
	d.title = termtext.Clean(title)
	d.err = err
	d.loading = false
	d.body = smbclient.Details(err)
	hint := smbclient.Hint(err)
	if hint != "" {
		d.body += "\n\nHint: " + hint
	}
	d.body = termtext.CleanMultiline(d.body)
	d.body = wrapText(d.body, d.textWidth())
	d.viewport.SetContent(d.body)
	d.viewport.SetYOffset(0)
}

// openPermissionsLoading shows a permissions dialog while the descriptor is fetched.
func (d *dialogModel) openPermissionsLoading(title string) {
	d.kind = dialogPermissions
	d.title = termtext.Clean(title)
	d.err = nil
	d.loading = true
	d.body = "Loading permissions…"
	d.viewport.SetContent(d.body)
	d.viewport.SetYOffset(0)
}

// openTransfer displays a transfer's progress dialog.
func (d *dialogModel) openTransfer(state *transferState) {
	d.kind = dialogTransfer
	d.title = state.title()
	d.transfer = state
	d.err = nil
	d.loading = false
}

// setBody replaces the dialog body with wrapped, sanitised text.
func (d *dialogModel) setBody(body string) {
	d.loading = false
	d.body = wrapText(termtext.CleanMultiline(body), d.textWidth())
	d.viewport.SetContent(d.body)
	d.viewport.SetYOffset(0)
}

// textWidth returns the usable text width inside the dialog border.
func (d *dialogModel) textWidth() int {
	width := d.boxWidth() - 6
	if width < 20 {
		width = 20
	}
	return width
}

// boxWidth computes a dialog width appropriate to its kind and the terminal.
func (d *dialogModel) boxWidth() int {
	width := d.width
	if width == 0 {
		width = 100
	}
	max := 100
	switch d.kind {
	case dialogPrompt, dialogConfirm:
		max = 66
	case dialogTransfer:
		max = 78
	}
	w := width - 6
	if w > max {
		w = max
	}
	if w < 24 {
		w = width - 2
	}
	if w < 16 {
		w = width
	}
	if w < 16 {
		w = 16
	}
	return w
}

// viewportHeight computes a bounded height for scrollable dialog content.
func (d *dialogModel) viewportHeight() int {
	height := d.height - 10
	if height > 22 {
		height = 22
	}
	if height < 5 {
		height = 5
	}
	return height
}

// View renders the dialog centred by the caller.
func (d *dialogModel) View() string {
	t := d.theme
	width := d.boxWidth()
	innerWidth := width - 6
	if innerWidth < 20 {
		innerWidth = 20
	}

	var body string
	switch d.kind {
	case dialogHelp, dialogError, dialogPermissions:
		d.viewport.Width = innerWidth
		d.viewport.Height = d.viewportHeight()
		body = d.viewport.View()
		if d.loading {
			body = t.muted.Render("Loading permissions…")
		}
		body += "\n\n" + t.muted.Render("↑/↓ scroll · esc close")

	case dialogConfirm:
		body = wrapText(d.body, innerWidth) + "\n\n" +
			t.warning.Render("y/enter confirm") + t.muted.Render("   ·   esc cancel")

	case dialogPrompt:
		inputWidth := innerWidth - 4
		if inputWidth < 10 {
			inputWidth = 10
		}
		d.prompt.Width = inputWidth
		body = wrapText(d.body, innerWidth) + "\n\n" + d.prompt.View()
		if d.err != nil {
			body += "\n\n" + t.danger.Render(wrapText(smbclient.Describe(d.err), innerWidth))
		}
		body += "\n\n" + t.muted.Render("enter submit · esc cancel")

	case dialogTransfer:
		if d.transfer != nil {
			body = d.transfer.View(innerWidth)
		}
	}

	content := t.dialogTitle.Render(d.title) + "\n" + lipgloss.NewStyle().Width(innerWidth).Render(body)
	return t.dialog.Render(content)
}

// promptValue returns the current prompt text.
func (d *dialogModel) promptValue() string {
	return strings.TrimSpace(d.prompt.Value())
}

// wrapText wraps plain text to width, preserving explicit line breaks.
func wrapText(s string, width int) string {
	if width <= 0 {
		return s
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		runes := []rune(line)
		if len(runes) <= width {
			out = append(out, line)
			continue
		}
		for len(runes) > width {
			cut := width
			for i := width; i > width/2; i-- {
				if runes[i] == ' ' || runes[i] == '\t' {
					cut = i
					break
				}
			}
			out = append(out, strings.TrimRight(string(runes[:cut]), " "))
			runes = []rune(strings.TrimLeft(string(runes[cut:]), " "))
		}
		if len(runes) > 0 {
			out = append(out, string(runes))
		}
	}
	return strings.Join(out, "\n")
}

// permissionReport formats a security descriptor for the permissions dialog.
func permissionReport(perms *smbclient.Permissions, access *smbclient.AccessState) string {
	if perms == nil || perms.Descriptor == nil {
		return "No security descriptor was returned."
	}
	sd := perms.Descriptor

	var b strings.Builder
	fmt.Fprintf(&b, "Path: \\\\%s\\%s", perms.Host, perms.ShareName)
	if perms.Path != "" {
		b.WriteString(`\` + strings.ReplaceAll(perms.Path, "/", `\`))
	}
	b.WriteString("\n")
	if access != nil {
		fmt.Fprintf(&b, "Effective access (share probe): %s\n", accessDetail(*access))
	}
	b.WriteString("\n")
	owner := sd.Owner.Display()
	if owner == "" {
		owner = "(not reported)"
	}
	group := sd.Group.Display()
	if group == "" {
		group = "(not reported)"
	}
	fmt.Fprintf(&b, "Owner: %s\n", owner)
	fmt.Fprintf(&b, "Group: %s\n", group)

	switch {
	case sd.NullDACL:
		b.WriteString("\nDACL: none. This is a NULL DACL, which grants full control to everyone.\n")
	case len(sd.ACEs) == 0:
		b.WriteString("\nDACL: present but empty. Only the owner can read the permissions; everyone else is denied.\n")
	default:
		flags := []string{fmt.Sprintf("%d entr%s", len(sd.ACEs), plural(len(sd.ACEs), "y", "ies"))}
		if sd.DACLProtected {
			flags = append(flags, "protected from inheritance")
		}
		if sd.DACLAutoInherited {
			flags = append(flags, "auto-inherited")
		}
		fmt.Fprintf(&b, "\nDACL (%s):\n", strings.Join(flags, ", "))
	}

	for i, ace := range sd.ACEs {
		fmt.Fprintf(&b, "\n%d. %s%s — %s\n", i+1, ace.Type, objectSuffix(ace), ace.RightsSummary())
		fmt.Fprintf(&b, "   trustee: %s\n", ace.Trustee.Display())
		flags := ace.Flags
		if len(flags) > 0 {
			fmt.Fprintf(&b, "   flags:   %s\n", strings.Join(flags, " "))
		}
		fmt.Fprintf(&b, "   mask:    0x%08X\n", ace.Mask)
	}

	b.WriteString("\nThis is the object's security descriptor. Share permissions are enforced ")
	b.WriteString("in addition to it, so the account may have less access than this ACL suggests.")
	b.WriteString("\nReading an ACL requires READ_CONTROL; failing to read one does not itself mean access is denied.")
	return b.String()
}

// objectSuffix marks an ACE whose rights apply to a specific object.
func objectSuffix(ace smbclient.ACE) string {
	if ace.Object {
		return " (object-specific)"
	}
	return ""
}
