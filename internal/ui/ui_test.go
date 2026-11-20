package ui

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/help"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/config"
	"github.com/mfkrypt/smblens/internal/smbclient"
)

func testOptions() *config.Options {
	return &config.Options{
		Config: smbclient.Config{
			Auth:           smbclient.AuthPassword,
			ConnectTimeout: 5 * time.Second,
			OpTimeout:      5 * time.Second,
		},
		MaxDepth: 10,
		NoColor:  true,
	}
}

func testApp() *App {
	a := New(testOptions())
	a.layout(100, 32)
	return a
}

func keyRunes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestViewsAtManySizes(t *testing.T) {
	a := testApp()
	a.shares.setContext("fileserver", true)
	a.shares.setData([]smbclient.ShareInfo{
		{Name: "share", Kind: smbclient.ShareDisk, Access: smbclient.AccessState{Mounted: true, Read: true, Write: true, WriteTested: true}},
	}, nil)

	screens := []screenID{screenConnect, screenShares, screenBrowser, screenTree, screenViewer}
	for _, width := range []int{40, 60, 80, 120, 200} {
		for _, height := range []int{12, 24, 40} {
			a.layout(width, height)
			for _, screen := range screens {
				a.screen = screen
				view := a.View()
				if strings.TrimSpace(view) == "" {
					t.Fatalf("empty view for screen %v at %dx%d", screen, width, height)
				}
			}

			// Dialogs must also render at every size.
			a.dialog.openError("Error", errors.New("something went wrong"))
			if strings.TrimSpace(a.View()) == "" {
				t.Fatalf("empty error dialog at %dx%d", width, height)
			}
			a.dialog.close()
		}
	}
}

func TestConnectFormBuildsPasswordConfig(t *testing.T) {
	a := testApp()
	a.connect.server.SetValue("fileserver:1445/share/docs")
	a.connect.domain.SetValue("CORP")
	a.connect.user.SetValue("alice")
	a.connect.secret.SetValue("secret")

	cfg, err := a.connect.buildConfig(a.cfg)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.Host != "fileserver" || cfg.Port != 1445 {
		t.Fatalf("host/port = %q/%d", cfg.Host, cfg.Port)
	}
	if cfg.Share != "share" || cfg.Path != "docs" {
		t.Fatalf("share/path = %q/%q", cfg.Share, cfg.Path)
	}
	if cfg.Auth != smbclient.AuthPassword || cfg.Password != "secret" {
		t.Fatalf("auth = %q, password = %q", cfg.Auth, cfg.Password)
	}
	if cfg.Username != "alice" || cfg.Domain != "CORP" {
		t.Fatalf("identity = %q/%q", cfg.Username, cfg.Domain)
	}
}

func TestConnectFormHashValidation(t *testing.T) {
	a := testApp()
	a.connect.server.SetValue("fileserver")
	a.connect.auth = authChoiceHash
	a.connect.applySecretMode()
	a.connect.user.SetValue("alice")
	a.connect.secret.SetValue("short")

	if _, err := a.connect.buildConfig(a.cfg); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("expected an NT hash error, got %v", err)
	}

	a.connect.secret.SetValue("0123456789abcdef0123456789abcdef")
	cfg, err := a.connect.buildConfig(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth != smbclient.AuthHash || cfg.NTHash == "" || cfg.Password != "" {
		t.Fatalf("unexpected hash config: %+v", cfg)
	}
}

func TestConnectFormAllowsBlankDomainForPasswordAndHash(t *testing.T) {
	a := testApp()
	a.connect.server.SetValue("fileserver")
	a.connect.domain.SetValue("")
	a.connect.user.SetValue(`CORP\alice`)
	a.connect.secret.SetValue("secret")

	cfg, err := a.connect.buildConfig(a.cfg)
	if err != nil {
		t.Fatalf("password with a blank domain: %v", err)
	}
	if cfg.Domain != "" || cfg.Username != `CORP\alice` {
		t.Fatalf("unexpected identity: %q / %q", cfg.Username, cfg.Domain)
	}
	if user, domain := smbclient.SplitIdentity(cfg.Username, cfg.Domain); user != "alice" || domain != "CORP" {
		t.Fatalf("embedded domain resolved to %q / %q", user, domain)
	}

	a.connect.user.SetValue("alice")
	cfg, err = a.connect.buildConfig(a.cfg)
	if err != nil {
		t.Fatalf("password with a bare username and no domain: %v", err)
	}
	if _, domain := smbclient.SplitIdentity(cfg.Username, cfg.Domain); domain != "." {
		t.Fatalf("bare username defaulted to domain %q, want .", domain)
	}

	a.connect.auth = authChoiceHash
	a.connect.applySecretMode()
	a.connect.user.SetValue(`CORP\alice`)
	a.connect.secret.SetValue("0123456789abcdef0123456789abcdef")
	if _, err := a.connect.buildConfig(a.cfg); err != nil {
		t.Fatalf("NT hash with a blank domain: %v", err)
	}
}

func TestConnectFormKerberosValidation(t *testing.T) {
	a := testApp()
	a.connect.server.SetValue("fileserver.example.com")
	a.connect.auth = authChoiceKerberos
	a.connect.source = smbclient.KerbPassword
	a.connect.applySecretMode()
	a.connect.user.SetValue("alice")
	a.connect.secret.SetValue("password")

	if _, err := a.connect.buildConfig(a.cfg); err == nil || !strings.Contains(err.Error(), "realm") {
		t.Fatalf("expected a realm error, got %v", err)
	}

	a.connect.domain.SetValue("CORP.EXAMPLE.COM")
	cfg, err := a.connect.buildConfig(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth != smbclient.AuthKerberos || cfg.Realm != "CORP.EXAMPLE.COM" {
		t.Fatalf("unexpected Kerberos config: %+v", cfg)
	}
	if cfg.KerberosSource != smbclient.KerbPassword || cfg.Password != "password" {
		t.Fatalf("unexpected Kerberos credentials: %+v", cfg)
	}

	a.connect.source = smbclient.KerbCCache
	a.connect.secret.SetValue("/tmp/krb5cc_test")
	a.connect.user.SetValue("")
	cfg, err = a.connect.buildConfig(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KerberosSource != smbclient.KerbCCache || cfg.CCachePath != "/tmp/krb5cc_test" {
		t.Fatalf("unexpected ccache config: %+v", cfg)
	}
}

func TestConnectFormKeyHandling(t *testing.T) {
	a := testApp()
	form := a.connect
	form.moveFocus(-100) // focus the server field

	form.handleKey(keyRunes("fileserver"), a.cfg)
	if form.server.Value() != "fileserver" {
		t.Fatalf("server = %q", form.server.Value())
	}

	form.handleKey(tea.KeyMsg{Type: tea.KeyTab}, a.cfg)
	if got := form.focusedField(); got != fieldAuth {
		t.Fatalf("focused field = %v, want auth", got)
	}

	form.handleKey(tea.KeyMsg{Type: tea.KeyRight}, a.cfg)
	if form.auth != authChoiceHash {
		t.Fatalf("auth = %v, want hash", form.auth)
	}
	form.handleKey(keyRunes("leftover"), a.cfg)
	if form.secret.Value() != "" {
		t.Fatal("cycling the auth method should clear the old secret")
	}
}

func TestSharesFilterSortAndSelection(t *testing.T) {
	m := newSharesModel(newTheme())
	m.setSize(120, 30)
	m.setData([]smbclient.ShareInfo{
		{Name: "zeta", Kind: smbclient.ShareDisk, Access: smbclient.AccessState{Mounted: true, Read: true, WriteTested: true}},
		{Name: "public", Kind: smbclient.ShareDisk, Comment: "everyone", Access: smbclient.AccessState{Mounted: true, Read: true, Write: true, WriteTested: true}},
		{Name: "IPC$", Kind: smbclient.ShareIPC, Special: true, Access: smbclient.AccessState{Mounted: true}},
	}, nil)

	if len(m.visible) != 3 {
		t.Fatalf("visible = %d", len(m.visible))
	}
	if m.visible[0].Name != "public" {
		t.Fatalf("first share = %q, want regular shares sorted by name before special ones", m.visible[0].Name)
	}

	m.startFilter()
	m.filterText = "pub"
	m.rebuild()
	if len(m.visible) != 1 || m.visible[0].Name != "public" {
		t.Fatalf("filtered shares = %+v", m.visible)
	}
	m.stopFilter(true)
	if len(m.visible) != 3 {
		t.Fatalf("clearing the filter left %d shares", len(m.visible))
	}

	m.cycleSort()
	if m.visible[0].Access.Label() != "RW" {
		t.Fatalf("access sort put %q first", m.visible[0].Name)
	}

	m.table.SetCursor(0)
	share, ok := m.selected()
	if !ok || share.Name != "public" {
		t.Fatalf("selected = %+v, %v", share, ok)
	}
}

func TestBrowserFilterSortAndHidden(t *testing.T) {
	m := newBrowserModel(newTheme())
	m.setSize(120, 30)
	m.setData("docs", []smbclient.Entry{
		{Name: "b.txt", Path: "docs/b.txt", Size: 20},
		{Name: "a", Path: "docs/a", Dir: true},
		{Name: ".hidden", Path: "docs/.hidden", Hidden: true},
	}, nil)

	if len(m.visible) != 2 {
		t.Fatalf("visible = %d, want hidden entries excluded", len(m.visible))
	}
	if !m.visible[0].Dir {
		t.Fatal("directories should sort first")
	}

	m.toggleHidden()
	if len(m.visible) != 3 {
		t.Fatalf("visible after showing hidden = %d", len(m.visible))
	}

	m.filterText = "b.txt"
	m.rebuild()
	if len(m.visible) != 1 || m.visible[0].Name != "b.txt" {
		t.Fatalf("filtered entries = %+v", m.visible)
	}
}

func TestTreeAppendAndErrorDetail(t *testing.T) {
	m := newTreeModel(newTheme())
	m.setSize(120, 30)
	m.appendItems([]smbclient.WalkItem{
		{Entry: smbclient.Entry{Name: "dir", Path: "dir", Dir: true}, Depth: 1},
		{Entry: smbclient.Entry{Name: "file.txt", Path: "file.txt", Size: 10}, Depth: 1},
		{Entry: smbclient.Entry{Name: "blocked", Path: "blocked", Dir: true}, Depth: 1, Err: errors.New("access denied")},
	})
	if len(m.visible) != 3 {
		t.Fatalf("visible = %d", len(m.visible))
	}

	m.table.SetCursor(2)
	if got := m.selectedError(); !strings.Contains(got, "access denied") {
		t.Fatalf("selectedError = %q", got)
	}

	done := m.handleEvent(treeEvent{
		stats: smbclient.WalkStats{Dirs: 1, Files: 1, Bytes: 10, Errors: 1},
		done:  true,
	})
	if !done || m.running || !m.done {
		t.Fatalf("done=%v running=%v state=%v", done, m.running, m.done)
	}
	if !strings.Contains(m.View(), "1 file") {
		t.Fatalf("tree view does not show stats: %q", m.View())
	}
}

func TestDialogPromptAndReport(t *testing.T) {
	tm := newTheme()
	d := newDialog(tm)
	d.setSize(100, 40)
	d.openPrompt("New folder", "Create in \\\\srv\\share", "", "name", pendingAction{kind: actionMkdir})
	d.prompt.SetValue("reports")
	if d.promptValue() != "reports" {
		t.Fatalf("prompt value = %q", d.promptValue())
	}
	if !strings.Contains(d.View(), "New folder") {
		t.Fatal("dialog title missing")
	}

	desc := &smbclient.SecurityDescriptor{
		Owner: smbclient.SID{Raw: "S-1-5-32-544", Name: `BUILTIN\Administrators`},
		ACEs: []smbclient.ACE{
			{Type: "Allow", Allow: true, Mask: 0x1F01FF, Trustee: smbclient.SID{Raw: "S-1-1-0", Name: "Everyone"}},
			{Type: "Deny", Deny: true, Mask: 0x00000001, Trustee: smbclient.SID{Raw: "S-1-5-32-545", Name: `BUILTIN\Users`}, Inherited: true, Flags: []string{"ID"}},
		},
	}
	access := smbclient.AccessState{Mounted: true, Read: true, Write: true, WriteTested: true}
	report := permissionReport(&smbclient.Permissions{
		Path: "docs", Host: "srv", ShareName: "share", Descriptor: desc,
	}, &access)
	for _, want := range []string{`\\srv\share\docs`, "read + write", "BUILTIN\\Administrators", "Full control", "Deny", "NTFS ACL"} {
		if !strings.Contains(report, want) {
			t.Fatalf("permission report does not contain %q:\n%s", want, report)
		}
	}
}

func TestAppHelpDialog(t *testing.T) {
	a := testApp()
	a.screen = screenShares
	a.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	if a.dialog.kind != dialogHelp {
		t.Fatalf("dialog kind = %v, want help", a.dialog.kind)
	}
	if !strings.Contains(a.View(), "Keys") {
		t.Fatal("help dialog is not rendered")
	}
	a.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if a.dialog.active() {
		t.Fatal("esc did not close the help dialog")
	}
}

func TestAppFilterFlow(t *testing.T) {
	a := testApp()
	a.screen = screenShares
	a.shares.setData([]smbclient.ShareInfo{
		{Name: "public"},
		{Name: "private"},
	}, nil)

	a.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	if !a.shares.filtering {
		t.Fatal("filter did not start")
	}
	a.Update(keyRunes("pub"))
	if len(a.shares.visible) != 1 || a.shares.visible[0].Name != "public" {
		t.Fatalf("filtered shares = %+v", a.shares.visible)
	}
	a.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if a.shares.filtering || len(a.shares.visible) != 2 {
		t.Fatal("esc did not cancel the filter")
	}
}

func TestAppExportShares(t *testing.T) {
	t.Chdir(t.TempDir())
	a := testApp()
	a.screen = screenShares
	a.shares.setData([]smbclient.ShareInfo{
		{Name: "share", Kind: smbclient.ShareDisk, Access: smbclient.AccessState{Mounted: true, Read: true, Write: true, WriteTested: true}},
	}, nil)

	a.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})

	files, err := filepath.Glob("smblens-shares-*.json")
	if err != nil || len(files) != 1 {
		t.Fatalf("export file not created: %v %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var report shareReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	if len(report.Shares) != 1 || report.Shares[0].Name != "share" {
		t.Fatalf("export content = %+v", report)
	}
	if !report.Shares[0].Access.Write || !report.Shares[0].Access.Read {
		t.Fatalf("export access = %+v", report.Shares[0].Access)
	}
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("export permissions = %v, want 0600", info.Mode().Perm())
	}
}

func TestTreeReportExport(t *testing.T) {
	t.Chdir(t.TempDir())
	items := []smbclient.WalkItem{
		{Entry: smbclient.Entry{Path: "dir", Dir: true}},
		{Entry: smbclient.Entry{Path: "dir/file.txt", Size: 10}},
		{Entry: smbclient.Entry{Path: "blocked", Dir: true}, Err: errors.New("access denied")},
	}
	path := treeExportName("srv", "share")
	if err := writeTreeReport(path, "srv", "share", "", items); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report treeReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 3 || report.Entries[2].Error == "" {
		t.Fatalf("tree report = %+v", report)
	}
}

func TestServerStringsAreSanitisedInViews(t *testing.T) {
	a := testApp()
	osc := "\x1b]0;pwned\x07"
	csi := "\x1b[31m"

	a.shares.setContext("host"+osc, true)
	a.shares.setData([]smbclient.ShareInfo{{
		Name:    "share" + osc,
		Comment: "comment" + csi,
		Kind:    smbclient.ShareDisk,
	}}, nil)
	a.browser.setShare(nil, "share"+osc)
	a.browser.setData("dir"+csi+"red", []smbclient.Entry{{
		Name: "file" + osc, Path: "dir/file", Size: 1,
	}}, nil)
	a.viewer.open("host", "share"+osc, "dir"+csi+"red/file.txt")
	a.viewer.setContent(smbclient.FileContent{Data: []byte("content" + csi + "more")}, nil)
	a.tree.host, a.tree.shareName, a.tree.root = "host"+osc, "share"+osc, "dir"+csi+"red"
	a.tree.appendItems([]smbclient.WalkItem{{
		Entry: smbclient.Entry{Name: "file" + csi, Path: "dir" + osc + "file.txt"},
	}})

	views := map[string]string{
		"shares":  func() string { a.screen = screenShares; return a.View() }(),
		"browser": func() string { a.screen = screenBrowser; return a.View() }(),
		"tree":    func() string { a.screen = screenTree; return a.View() }(),
		"viewer":  func() string { a.screen = screenViewer; return a.View() }(),
	}
	for name, view := range views {
		// testApp disables colour, so any ESC here came from unsanitised
		// server text.
		if strings.ContainsRune(view, 0x1b) {
			t.Fatalf("%s view contains a raw escape sequence: %q", name, view)
		}
	}

	a.dialog.openPrompt(
		"Rename "+osc,
		"Rename file"+osc+" in dir"+csi+"red",
		"", "name", pendingAction{kind: actionRename})
	if view := a.View(); strings.ContainsRune(view, 0x1b) {
		t.Fatalf("dialog view contains a raw escape sequence: %q", view)
	}
}

func TestAccessDetailExplainsProbeState(t *testing.T) {
	state := smbclient.AccessState{Mounted: true, Read: true}
	if got := accessDetail(state); !strings.Contains(got, "write not tested") {
		t.Fatalf("no-probe detail = %q", got)
	}

	state = smbclient.AccessState{
		Mounted: true, Read: true, WriteTested: true, Write: true,
		Note: `probe file ".smblens-probe-abc" could not be deleted`,
	}
	if got := accessDetail(state); !strings.Contains(got, "could not be deleted") {
		t.Fatalf("probe note is not shown: %q", got)
	}

	state = smbclient.AccessState{Mounted: true, Note: "this share type does not support file listing"}
	if got := accessDetail(state); !strings.Contains(got, "does not support file listing") {
		t.Fatalf("share-type note is not shown: %q", got)
	}
}

func TestDownloadsDefaultToCwd(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	a := testApp()
	a.screen = screenBrowser
	a.browser.setData("", []smbclient.Entry{
		{Name: "report.txt", Path: "report.txt", Size: 10},
		{Name: "docs", Path: "docs", Dir: true},
	}, nil)
	// Directories sort first, so docs is row 0 and report.txt is row 1.
	a.browser.table.SetCursor(1)

	a.Update(keyRunes("d"))
	if a.dialog.kind != dialogPrompt {
		t.Fatalf("file download dialog = %v, want prompt", a.dialog.kind)
	}
	wantFile := filepath.Join(dir, "report.txt")
	if got := a.dialog.promptValue(); got != wantFile {
		t.Fatalf("file default = %q, want %q", got, wantFile)
	}

	a.dialog.close()
	a.browser.table.SetCursor(0)
	a.Update(keyRunes("d"))
	if a.dialog.kind != dialogPrompt || a.dialog.pending.kind != actionDownloadTree {
		t.Fatalf("folder download dialog = %v/%v", a.dialog.kind, a.dialog.pending.kind)
	}
	wantDir := filepath.Join(dir, "docs")
	if got := a.dialog.promptValue(); got != wantDir {
		t.Fatalf("folder default = %q, want %q", got, wantDir)
	}
	if !strings.Contains(a.dialog.title, "Download folder") {
		t.Fatalf("folder dialog title = %q", a.dialog.title)
	}
}

func TestFolderDownloadMergesIntoExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	a := testApp()
	a.screen = screenBrowser
	a.dialog.openPrompt(
		"Download folder", "body", dir, "local folder",
		pendingAction{kind: actionDownloadTree, entry: smbclient.Entry{Name: "docs", Path: "docs", Dir: true}},
	)
	a.dialog.prompt.SetValue(dir)
	a.submitPrompt()
	if a.dialog.kind != dialogConfirm {
		t.Fatalf("dialog = %v, want merge confirmation", a.dialog.kind)
	}
	if a.dialog.pending.kind != actionDownloadTree || a.dialog.pending.path != dir {
		t.Fatalf("pending = %+v", a.dialog.pending)
	}

	file := filepath.Join(t.TempDir(), "exists.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	a.dialog.openPrompt(
		"Download folder", "body", file, "local folder",
		pendingAction{kind: actionDownloadTree, entry: smbclient.Entry{Name: "docs", Path: "docs", Dir: true}},
	)
	a.dialog.prompt.SetValue(file)
	a.submitPrompt()
	if a.dialog.err == nil {
		t.Fatal("choosing an existing file as the folder destination should fail")
	}
}

func TestTreeDownloadView(t *testing.T) {
	state := &transferState{
		direction:  transferDownloadTree,
		host:       "srv",
		shareName:  "share",
		remote:     "docs",
		local:      "/tmp/docs",
		theme:      newTheme(),
		phase:      smbclient.TreePhaseDownloading,
		filesDone:  2,
		filesTotal: 5,
		done:       500,
		total:      1000,
		current:    "docs/a.txt",
	}
	view := state.View(70)
	for _, want := range []string{"Downloading", "file 3 of 5", "docs/a.txt"} {
		if !strings.Contains(view, want) {
			t.Fatalf("tree view missing %q:\n%s", want, view)
		}
	}

	state.finished = true
	state.failed = 1
	state.skipped = 1
	state.failures = []string{"docs/b.txt: access denied"}
	view = state.View(70)
	for _, want := range []string{"with problems", "Downloaded 2 of 5 files", "1 problem", "1 special entry", "docs/b.txt", "i for details"} {
		if !strings.Contains(view, want) {
			t.Fatalf("finished tree view missing %q:\n%s", want, view)
		}
	}
	if err := state.failureError(); err == nil || !strings.Contains(err.Error(), "docs/b.txt") {
		t.Fatalf("failureError = %v", err)
	}
}

func TestReparseEntryIsNotFollowed(t *testing.T) {
	a := testApp()
	a.screen = screenBrowser
	a.browser.setData("", []smbclient.Entry{{
		Name: "junction", Path: "junction", Mode: os.ModeIrregular,
	}}, nil)

	a.Update(keyRunes("d"))
	if a.dialog.active() {
		t.Fatal("a reparse point must not open a download dialog")
	}
	if !strings.Contains(strings.ToLower(a.toast), "reparse") {
		t.Fatalf("toast = %q, want a reparse-point refusal", a.toast)
	}
}

func TestPromptValidation(t *testing.T) {
	a := testApp()
	a.screen = screenBrowser
	a.dialog.openPrompt("New folder", "body", "", "name", pendingAction{kind: actionMkdir})

	// An empty name is rejected and the dialog stays open.
	a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !a.dialog.active() || a.dialog.err == nil {
		t.Fatal("empty folder name should keep the dialog open with an error")
	}

	// A name with a separator is rejected.
	a.dialog.prompt.SetValue("a/b")
	a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if a.dialog.err == nil {
		t.Fatal("a path separator should be rejected")
	}

	// A valid name closes the dialog. There is no mounted share in this test,
	// so the operation itself is a no-op.
	a.dialog.prompt.SetValue("reports")
	a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if a.dialog.active() {
		t.Fatal("a valid name should close the dialog")
	}
}

func TestTransferView(t *testing.T) {
	tm := newTheme()
	state := &transferState{
		direction: transferDownload,
		host:      "srv",
		shareName: "share",
		remote:    "docs/file.txt",
		local:     "/tmp/file.txt",
		done:      512,
		total:     1024,
		rate:      2048,
		theme:     tm,
	}
	view := state.View(70)
	for _, want := range []string{"Downloading", "docs", "50%", "/tmp/file.txt"} {
		if !strings.Contains(view, want) {
			t.Fatalf("transfer view does not contain %q:\n%s", want, view)
		}
	}

	state.finished = true
	state.err = errors.New("disk full")
	if !strings.Contains(state.View(70), "failed") {
		t.Fatal("failed transfer is not reported")
	}
}

func TestSmallHelpers(t *testing.T) {
	if got := formatSize(1536); got != "1.5 KB" {
		t.Fatalf("formatSize(1536) = %q", got)
	}
	if got := formatSize(0); got != "0 B" {
		t.Fatalf("formatSize(0) = %q", got)
	}
	if got := safeFilename("host/name:with*bad"); strings.ContainsAny(got, `/\:*`) {
		t.Fatalf("safeFilename = %q", got)
	}
	wrapped := wrapText("one two three four", 9)
	if !strings.Contains(wrapped, "\n") {
		t.Fatalf("wrapText did not wrap: %q", wrapped)
	}
}

func TestConnectHelpAdvertisesCtrlCQuit(t *testing.T) {
	keys := defaultKeys()
	for _, binding := range (connectKeys{keys}).ShortHelp() {
		if binding.Help().Key == "q" {
			t.Fatal("the login form must not advertise q as quit; q is text input")
		}
	}
	found := false
	for _, binding := range (connectKeys{keys}).ShortHelp() {
		if binding.Help().Key == "ctrl+c" && binding.Help().Desc == "quit" {
			found = true
		}
	}
	if !found {
		t.Fatal("the login form help does not advertise ctrl+c quit")
	}

	a := testApp()
	a.screen = screenConnect
	view := a.View()
	if !strings.Contains(view, "ctrl+c quit") {
		t.Fatalf("connect view does not show the quit key: %q", view)
	}
}

func TestKeyMapsAreComplete(t *testing.T) {
	keys := defaultKeys()
	maps := map[string]help.KeyMap{
		"shares":  sharesKeys{keys},
		"browser": browserKeys{keys},
		"tree":    treeKeys{keys},
		"viewer":  viewerKeys{keys},
		"connect": connectKeys{keys},
		"dialog":  dialogKeys{keys},
	}
	for name, km := range maps {
		groups := km.FullHelp()
		if len(groups) == 0 {
			t.Fatalf("%s key map returned no full help groups", name)
		}
		if len(km.ShortHelp()) == 0 {
			t.Fatalf("%s key map returned no short help", name)
		}
		for _, group := range groups {
			for _, binding := range group {
				if !binding.Enabled() {
					continue
				}
				if binding.Help().Key == "" || binding.Help().Desc == "" {
					t.Fatalf("%s has a binding without help text: %+v", name, binding)
				}
				if len(binding.Keys()) == 0 {
					t.Fatalf("%s has a binding without keys: %+v", name, binding)
				}
			}
		}
	}
}
