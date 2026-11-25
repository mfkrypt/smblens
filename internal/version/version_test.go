package version

import "testing"

// TestInfoString checks the formatting of version, commit, date and dirty metadata.
func TestInfoString(t *testing.T) {
	cases := []struct {
		info Info
		want string
	}{
		{Info{Version: "v1.2.3"}, "v1.2.3"},
		{Info{Version: "v1.2.3", Commit: "abcdef1234567890"}, "v1.2.3 (abcdef123456)"},
		{
			Info{Version: "v1.2.3", Commit: "abcdef1234567890", Date: "2026-11-21T10:00:00Z", Modified: true},
			"v1.2.3 (abcdef123456, 2026-11-21, dirty)",
		},
		{
			Info{Version: "v1.2.3+dirty", Commit: "abcdef1234567890", Date: "2026-11-21T10:00:00Z", Modified: true},
			"v1.2.3+dirty (abcdef123456, 2026-11-21)",
		},
		{Info{}, "devel"},
		{Info{Version: "devel", Date: "not-a-date"}, "devel (not-a-date)"},
	}
	for _, c := range cases {
		if got := c.info.String(); got != c.want {
			t.Fatalf("String(%+v) = %q, want %q", c.info, got, c.want)
		}
	}
}

// TestGetPrefersInjectedVersion verifies that -X build values take precedence over metadata.
func TestGetPrefersInjectedVersion(t *testing.T) {
	oldVersion, oldCommit, oldDate := Version, Commit, Date
	defer func() { Version, Commit, Date = oldVersion, oldCommit, oldDate }()

	Version = "v9.9.9"
	Commit = "abcdef1234567890"
	Date = "2026-11-21T10:00:00Z"

	got := Get()
	if got.Version != "v9.9.9" {
		t.Fatalf("Version = %q", got.Version)
	}
	if got.Commit != "abcdef1234567890" || got.Date != "2026-11-21T10:00:00Z" {
		t.Fatalf("metadata = %+v", got)
	}
}

// TestGetAlwaysHasVersion checks that Get never returns an empty version string.
func TestGetAlwaysHasVersion(t *testing.T) {
	oldVersion := Version
	defer func() { Version = oldVersion }()
	Version = ""

	if got := Get().Version; got == "" {
		t.Fatal("version must never be empty")
	}
}
