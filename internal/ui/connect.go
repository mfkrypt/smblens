package ui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mfkrypt/smblens/internal/config"
	"github.com/mfkrypt/smblens/internal/smbclient"
	"github.com/mfkrypt/smblens/internal/termtext"
)

// authChoice is the login form's authentication selector.
type authChoice int

const (
	authChoicePassword authChoice = iota
	authChoiceHash
	authChoiceKerberos
)

func (a authChoice) method() smbclient.AuthMethod {
	switch a {
	case authChoiceHash:
		return smbclient.AuthHash
	case authChoiceKerberos:
		return smbclient.AuthKerberos
	default:
		return smbclient.AuthPassword
	}
}

func authChoiceFor(method smbclient.AuthMethod) authChoice {
	switch method {
	case smbclient.AuthHash:
		return authChoiceHash
	case smbclient.AuthKerberos:
		return authChoiceKerberos
	default:
		return authChoicePassword
	}
}

func (a authChoice) label() string {
	switch a {
	case authChoiceHash:
		return "NT hash (pass-the-hash)"
	case authChoiceKerberos:
		return "Kerberos"
	default:
		return "Password"
	}
}

// formField identifies one focusable row of the login form.
type formField int

const (
	fieldServer formField = iota
	fieldAuth
	fieldSource
	fieldDomain
	fieldUser
	fieldSecret
	fieldKDC
)

// connectForm is the login screen. Its fields adapt to the selected
// authentication method so that only relevant inputs are shown.
type connectForm struct {
	server textinput.Model
	domain textinput.Model
	user   textinput.Model
	secret textinput.Model
	kdc    textinput.Model

	auth   authChoice
	source smbclient.KerberosSource
	focus  int

	width, height int
	connecting    bool
	err           error
	theme         *theme
}

func newConnectForm(cfg smbclient.Config, t *theme) *connectForm {
	f := &connectForm{
		server: newTextInput("host[:port][/share]"),
		domain: newTextInput("domain or realm"),
		user:   newTextInput("username"),
		secret: newTextInput(""),
		kdc:    newTextInput("kdc.example.com (optional)"),
		auth:   authChoiceFor(cfg.Auth),
		source: cfg.KerberosSource,
		theme:  t,
	}
	if f.source == "" {
		switch {
		case cfg.CCachePath != "":
			f.source = smbclient.KerbCCache
		case cfg.KeytabPath != "":
			f.source = smbclient.KerbKeytab
		default:
			f.source = smbclient.KerbPassword
		}
	}

	f.server.SetValue(targetDisplay(cfg))
	f.domain.SetValue(cfg.Domain)
	f.user.SetValue(cfg.Username)
	if cfg.Realm != "" {
		f.domain.SetValue(cfg.Realm)
	}
	f.kdc.SetValue(cfg.KDC)

	switch f.auth {
	case authChoiceHash:
		f.secret.SetValue(cfg.NTHash)
		f.secret.Placeholder = "32 hex characters"
	case authChoiceKerberos:
		switch f.source {
		case smbclient.KerbCCache:
			f.secret.SetValue(cfg.CCachePath)
			f.secret.Placeholder = "/tmp/krb5cc_1000"
		case smbclient.KerbKeytab:
			f.secret.SetValue(cfg.KeytabPath)
			f.secret.Placeholder = "/etc/krb5.keytab"
		default:
			f.secret.SetValue(cfg.Password)
			f.secret.Placeholder = "password"
		}
	default:
		f.secret.SetValue(cfg.Password)
		f.secret.Placeholder = "password"
	}
	f.applySecretMode()

	f.focus = f.firstIncompleteField()
	f.syncFocus()
	return f
}

func newTextInput(placeholder string) textinput.Model {
	in := textinput.New()
	in.Prompt = "› "
	in.Placeholder = placeholder
	in.CharLimit = 512
	in.PromptStyle = lipgloss.NewStyle().Foreground(colors.accent)
	in.TextStyle = lipgloss.NewStyle().Foreground(colors.text)
	in.PlaceholderStyle = lipgloss.NewStyle().Foreground(colors.faint)
	return in
}

// targetDisplay reconstructs the server line from a configuration.
func targetDisplay(cfg smbclient.Config) string {
	if cfg.Host == "" {
		return ""
	}
	host := cfg.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	out := host
	if cfg.Port != 0 && cfg.Port != 445 {
		out += fmt.Sprintf(":%d", cfg.Port)
	}
	if cfg.Share != "" {
		out += "/" + cfg.Share
		if cfg.Path != "" {
			out += "/" + cfg.Path
		}
	}
	return out
}

// applySecretMode masks the password field and resets the cursor position.
func (f *connectForm) applySecretMode() {
	if f.auth == authChoicePassword || (f.auth == authChoiceKerberos && f.source == smbclient.KerbPassword) {
		f.secret.EchoMode = textinput.EchoPassword
	} else {
		f.secret.EchoMode = textinput.EchoNormal
	}
}

// fields returns the focusable rows for the current authentication mode.
func (f *connectForm) fields() []formField {
	fields := []formField{fieldServer, fieldAuth}
	if f.auth == authChoiceKerberos {
		fields = append(fields, fieldSource)
		if f.source != smbclient.KerbCCache {
			fields = append(fields, fieldDomain, fieldUser)
		}
	} else {
		fields = append(fields, fieldDomain, fieldUser)
	}
	fields = append(fields, fieldSecret)
	if f.auth == authChoiceKerberos {
		fields = append(fields, fieldKDC)
	}
	return fields
}

func (f *connectForm) focusedField() formField {
	fields := f.fields()
	if f.focus < 0 {
		f.focus = 0
	}
	if f.focus >= len(fields) {
		f.focus = len(fields) - 1
	}
	return fields[f.focus]
}

func (f *connectForm) moveFocus(delta int) tea.Cmd {
	f.focus += delta
	fields := f.fields()
	if f.focus < 0 {
		f.focus = 0
	}
	if f.focus >= len(fields) {
		f.focus = len(fields) - 1
	}
	return f.syncFocus()
}

// syncFocus focuses the text input belonging to the active row, if any.
func (f *connectForm) syncFocus() tea.Cmd {
	for _, in := range []*textinput.Model{&f.server, &f.domain, &f.user, &f.secret, &f.kdc} {
		in.Blur()
	}
	switch f.focusedField() {
	case fieldServer:
		return f.server.Focus()
	case fieldDomain:
		return f.domain.Focus()
	case fieldUser:
		return f.user.Focus()
	case fieldSecret:
		return f.secret.Focus()
	case fieldKDC:
		return f.kdc.Focus()
	}
	return nil
}

// focusField moves focus to a named row, if it is visible.
func (f *connectForm) focusField(target formField) tea.Cmd {
	for i, field := range f.fields() {
		if field == target {
			f.focus = i
			break
		}
	}
	return f.syncFocus()
}

// focusSecret moves focus to the secret field, for correcting failed logins.
func (f *connectForm) focusSecret() tea.Cmd {
	return f.focusField(fieldSecret)
}

// focusServer moves focus to the server field, for correcting network errors.
func (f *connectForm) focusServer() tea.Cmd {
	return f.focusField(fieldServer)
}

// focusCmd starts the cursor animation for the initially focused field.
func (f *connectForm) focusCmd() tea.Cmd {
	return f.syncFocus()
}

// firstIncompleteField focuses the first required row that is empty.
func (f *connectForm) firstIncompleteField() int {
	for i, field := range f.fields() {
		empty := func(in textinput.Model) bool { return strings.TrimSpace(in.Value()) == "" }
		switch field {
		case fieldServer:
			if empty(f.server) {
				return i
			}
		case fieldDomain:
			if f.auth == authChoiceKerberos && f.source != smbclient.KerbCCache && empty(f.domain) {
				return i
			}
		case fieldUser:
			if !(f.auth == authChoiceKerberos && f.source == smbclient.KerbCCache) && empty(f.user) {
				return i
			}
		case fieldSecret:
			if empty(f.secret) {
				return i
			}
		}
	}
	return 0
}

func (f *connectForm) setSize(width, height int) {
	f.width, f.height = width, height
	formWidth := width - 6
	if formWidth > 76 {
		formWidth = 76
	}
	if formWidth < 36 {
		formWidth = 36
	}
	inputWidth := formWidth - 22
	if inputWidth < 16 {
		inputWidth = 16
	}
	for _, in := range []*textinput.Model{&f.server, &f.domain, &f.user, &f.secret, &f.kdc} {
		in.Width = inputWidth
	}
}

// updateInputs forwards non-key messages (such as cursor blink ticks) to the
// text inputs.
func (f *connectForm) updateInputs(msg tea.Msg) tea.Cmd {
	var cmds []tea.Cmd
	for _, in := range []*textinput.Model{&f.server, &f.domain, &f.user, &f.secret, &f.kdc} {
		var cmd tea.Cmd
		*in, cmd = in.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}
	return tea.Batch(cmds...)
}

// handleKey processes a key press. It returns a command when the form wants to
// submit.
func (f *connectForm) handleKey(msg tea.KeyMsg, base smbclient.Config) tea.Cmd {
	if f.connecting {
		return nil
	}

	switch msg.String() {
	case "tab", "down":
		return f.moveFocus(1)
	case "shift+tab", "up":
		return f.moveFocus(-1)
	case "ctrl+s":
		return f.submit(base)
	case "enter":
		if f.focus >= len(f.fields())-1 {
			return f.submit(base)
		}
		return f.moveFocus(1)
	case "left":
		switch f.focusedField() {
		case fieldAuth:
			return f.cycleAuth(-1)
		case fieldSource:
			return f.cycleSource(-1)
		}
	case "right":
		switch f.focusedField() {
		case fieldAuth:
			return f.cycleAuth(1)
		case fieldSource:
			return f.cycleSource(1)
		}
	}

	f.updateFocusedInput(msg)
	return nil
}

func (f *connectForm) updateFocusedInput(msg tea.KeyMsg) {
	var in *textinput.Model
	switch f.focusedField() {
	case fieldServer:
		in = &f.server
	case fieldDomain:
		in = &f.domain
	case fieldUser:
		in = &f.user
	case fieldSecret:
		in = &f.secret
	case fieldKDC:
		in = &f.kdc
	}
	if in != nil {
		*in, _ = in.Update(msg)
	}
}

func (f *connectForm) cycleAuth(delta int) tea.Cmd {
	f.auth = authChoice((int(f.auth) + delta + 3) % 3)
	f.secret.SetValue("")
	f.secret.Placeholder = "password"
	switch f.auth {
	case authChoiceHash:
		f.secret.Placeholder = "32 hex characters"
	case authChoiceKerberos:
		switch f.source {
		case smbclient.KerbCCache:
			f.secret.Placeholder = "/tmp/krb5cc_1000"
		case smbclient.KerbKeytab:
			f.secret.Placeholder = "/etc/krb5.keytab"
		}
	}
	f.applySecretMode()
	f.err = nil
	return f.clampFocus()
}

func (f *connectForm) cycleSource(delta int) tea.Cmd {
	sources := []smbclient.KerberosSource{smbclient.KerbPassword, smbclient.KerbCCache, smbclient.KerbKeytab}
	index := 0
	for i, s := range sources {
		if s == f.source {
			index = i
		}
	}
	index = (index + delta + len(sources)) % len(sources)
	f.source = sources[index]
	f.secret.SetValue("")
	switch f.source {
	case smbclient.KerbCCache:
		f.secret.Placeholder = "/tmp/krb5cc_1000"
	case smbclient.KerbKeytab:
		f.secret.Placeholder = "/etc/krb5.keytab"
	default:
		f.secret.Placeholder = "password"
	}
	f.applySecretMode()
	f.err = nil
	return f.clampFocus()
}

func (f *connectForm) clampFocus() tea.Cmd {
	if f.focus >= len(f.fields()) {
		f.focus = len(f.fields()) - 1
	}
	if f.focus < 0 {
		f.focus = 0
	}
	return f.syncFocus()
}

// submit validates the form and produces a connection request.
func (f *connectForm) submit(base smbclient.Config) tea.Cmd {
	cfg, err := f.buildConfig(base)
	if err != nil {
		f.err = err
		return nil
	}
	f.err = nil
	f.connecting = true
	return func() tea.Msg { return connectSubmitMsg{cfg: cfg} }
}

// buildConfig validates the form and produces an SMB configuration.
func (f *connectForm) buildConfig(base smbclient.Config) (smbclient.Config, error) {
	cfg := base

	host, port, share, initialPath, err := config.ParseTarget(strings.TrimSpace(f.server.Value()))
	if err != nil {
		return cfg, err
	}
	if host == "" {
		return cfg, errors.New("enter a server to connect to")
	}
	cfg.Host = host
	cfg.Port = port
	cfg.Share = share
	cfg.Path = initialPath

	cfg.Auth = f.auth.method()
	cfg.KerberosSource = ""
	cfg.Username = strings.TrimSpace(f.user.Value())
	cfg.Domain = ""
	cfg.Realm = ""
	cfg.Password = ""
	cfg.NTHash = ""
	cfg.CCachePath = ""
	cfg.KeytabPath = ""
	cfg.KDC = strings.TrimSpace(f.kdc.Value())

	secret := strings.TrimSpace(f.secret.Value())

	switch cfg.Auth {
	case smbclient.AuthHash:
		cfg.Domain = strings.TrimSpace(f.domain.Value())
		if cfg.Username == "" {
			return cfg, errors.New("enter a username")
		}
		if secret == "" {
			return cfg, errors.New("enter an NT hash")
		}
		if _, err := smbclient.ParseNTHash(secret); err != nil {
			return cfg, err
		}
		cfg.NTHash = secret

	case smbclient.AuthKerberos:
		cfg.KerberosSource = f.source
		switch f.source {
		case smbclient.KerbCCache:
			if secret == "" {
				return cfg, errors.New("enter the path to a Kerberos credential cache")
			}
			cfg.CCachePath = secret
			cfg.Username = ""
		case smbclient.KerbKeytab:
			cfg.Realm = strings.TrimSpace(f.domain.Value())
			if cfg.Username == "" {
				return cfg, errors.New("enter a username")
			}
			if secret == "" {
				return cfg, errors.New("enter the path to a keytab")
			}
			cfg.KeytabPath = secret
		default:
			cfg.Realm = strings.TrimSpace(f.domain.Value())
			if cfg.Username == "" {
				return cfg, errors.New("enter a username")
			}
			if secret == "" {
				return cfg, errors.New("enter a password")
			}
			cfg.Password = secret
		}
		if cfg.Realm == "" && f.source != smbclient.KerbCCache {
			return cfg, errors.New("enter the Kerberos realm (for example CORP.EXAMPLE.COM)")
		}

	default:
		cfg.Domain = strings.TrimSpace(f.domain.Value())
		if cfg.Username == "" {
			return cfg, errors.New("enter a username")
		}
		if secret == "" {
			return cfg, errors.New("enter a password")
		}
		cfg.Password = secret
	}

	return cfg, nil
}

// View renders the login form.
func (f *connectForm) View() string {
	t := f.theme
	formWidth := f.width - 6
	if formWidth > 76 {
		formWidth = 76
	}
	if formWidth < 36 {
		formWidth = 36
	}

	var rows []string
	rows = append(rows, renderFormRow(t, f.focusedField() == fieldServer, "Server", f.server.View()))

	authValue := "‹ " + f.auth.label() + " ›"
	if f.focusedField() == fieldAuth {
		authValue = t.accent.Bold(true).Render(authValue)
	} else {
		authValue = t.value.Render(authValue)
	}
	rows = append(rows, renderFormRow(t, f.focusedField() == fieldAuth, "Auth", authValue))

	if f.auth == authChoiceKerberos {
		sourceValue := "‹ " + string(f.source) + " ›"
		if f.focusedField() == fieldSource {
			sourceValue = t.accent.Bold(true).Render(sourceValue)
		} else {
			sourceValue = t.value.Render(sourceValue)
		}
		rows = append(rows, renderFormRow(t, f.focusedField() == fieldSource, "Kerberos via", sourceValue))

		if f.source != smbclient.KerbCCache {
			rows = append(rows, renderFormRow(t, f.focusedField() == fieldDomain, "Realm", f.domain.View()))
			rows = append(rows, renderFormRow(t, f.focusedField() == fieldUser, "Username", f.user.View()))
		}
	} else {
		rows = append(rows, renderFormRow(t, f.focusedField() == fieldDomain, "Domain (opt.)", f.domain.View()))
		rows = append(rows, renderFormRow(t, f.focusedField() == fieldUser, "Username", f.user.View()))
	}

	secretLabel := "Password"
	switch f.auth {
	case authChoiceHash:
		secretLabel = "NT hash"
	case authChoiceKerberos:
		switch f.source {
		case smbclient.KerbCCache:
			secretLabel = "CCache"
		case smbclient.KerbKeytab:
			secretLabel = "Keytab"
		}
	}
	rows = append(rows, renderFormRow(t, f.focusedField() == fieldSecret, secretLabel, f.secret.View()))

	if f.auth == authChoiceKerberos {
		rows = append(rows, renderFormRow(t, f.focusedField() == fieldKDC, "KDC", f.kdc.View()))
	}

	title := t.appTitle.Render("SMBLens") + t.muted.Render("  ·  connect to an SMB server")
	subtitle := t.muted.Render("tab/↑↓ move · ←/→ change · ctrl+s connect · ctrl+c quit · F1 keys")

	body := lipgloss.JoinVertical(lipgloss.Left, title, "", strings.Join(rows, "\n"), "", subtitle)

	if hint := f.modeHint(); hint != "" {
		body += "\n" + t.faint.Width(formWidth).Render(hint)
	}
	if f.err != nil {
		body += "\n\n" + t.errorBox.Width(formWidth-4).Render(termtext.Clean(smbclient.Describe(f.err)))
		body += "\n" + t.faint.Render("ctrl+e shows technical details")
	}
	if f.connecting {
		body += "\n\n" + t.accent.Render("Connecting…")
	}

	boxWidth := formWidth + 4
	return lipgloss.NewStyle().Width(boxWidth).Render(body)
}

// modeHint explains requirements specific to the selected mode.
func (f *connectForm) modeHint() string {
	switch f.auth {
	case authChoiceKerberos:
		switch f.source {
		case smbclient.KerbCCache:
			return "Kerberos uses the server's DNS name. A valid TGT must be present in the cache."
		case smbclient.KerbKeytab:
			return "Kerberos uses the server's DNS name. The keytab must be readable by this process."
		default:
			return "Kerberos requires a correct realm and a server DNS name that matches its cifs/ service principal."
		}
	}
	return ""
}

func renderFormRow(t *theme, focused bool, label, value string) string {
	style := t.label
	marker := "  "
	if focused {
		style = t.labelActive
		marker = "▸ "
	}
	return marker + style.Width(14).Render(label) + value
}
