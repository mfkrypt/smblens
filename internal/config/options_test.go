package config

import (
	"strings"
	"testing"
)

// TestParseTargetForms covers every accepted target spelling, including UNC, smb://, IPv6 and a target port.
func TestParseTargetForms(t *testing.T) {
	cases := []struct {
		in          string
		host        string
		port        int
		share, path string
	}{
		{"fileserver", "fileserver", 0, "", ""},
		{"fileserver:1445", "fileserver", 1445, "", ""},
		{"fileserver/share", "fileserver", 0, "share", ""},
		{"fileserver/share/docs", "fileserver", 0, "share", "docs"},
		{`\\fileserver\share\docs`, "fileserver", 0, "share", "docs"},
		{"smb://fileserver/share", "fileserver", 0, "share", ""},
		{"smb://fileserver:1445/share/docs", "fileserver", 1445, "share", "docs"},
		{"[::1]:1445", "::1", 1445, "", ""},
		{"::1", "::1", 0, "", ""},
		{"[fe80::1]/share", "fe80::1", 0, "share", ""},
	}
	for _, c := range cases {
		host, port, share, path, err := ParseTarget(c.in)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", c.in, err)
		}
		if host != c.host || port != c.port || share != c.share || path != c.path {
			t.Fatalf("ParseTarget(%q) = (%q, %d, %q, %q), want (%q, %d, %q, %q)",
				c.in, host, port, share, path, c.host, c.port, c.share, c.path)
		}
	}

	if _, _, _, _, err := ParseTarget("host:abc"); err == nil {
		t.Fatal("a non-numeric port should be rejected")
	}
}

// TestParseFlagsMayFollowTarget checks that flags are reordered so they may appear after the positional target.
func TestParseFlagsMayFollowTarget(t *testing.T) {
	t.Setenv("SMBLENS_PASSWORD", "")
	t.Setenv("SMBLENS_NTHASH", "")

	opts, err := Parse([]string{"fileserver", "-u", "CORP\\alice", "-d", "CORP", "-p", "secret"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if opts.Config.Host != "fileserver" {
		t.Fatalf("host = %q", opts.Config.Host)
	}
	if opts.Config.Username != `CORP\alice` || opts.Config.Domain != "CORP" {
		t.Fatalf("identity = %q / %q", opts.Config.Username, opts.Config.Domain)
	}
	if opts.Config.Password != "secret" {
		t.Fatal("password was not parsed")
	}
	if opts.Config.Auth != "password" {
		t.Fatalf("auth = %q, want password", opts.Config.Auth)
	}
	if !opts.ReadyToConnect() {
		t.Fatal("ReadyToConnect = false for complete password details")
	}
}

// TestParseInfersAuth verifies that an NT hash or a Kerberos cache selects the authentication method automatically.
func TestParseInfersAuth(t *testing.T) {
	t.Setenv("SMBLENS_PASSWORD", "")
	t.Setenv("SMBLENS_NTHASH", "")

	opts, err := Parse([]string{"--hash", "0123456789abcdef0123456789abcdef", "-u", "alice", "host"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Config.Auth != "hash" {
		t.Fatalf("auth = %q, want hash", opts.Config.Auth)
	}

	opts, err = Parse([]string{"--ccache", "/tmp/krb5cc_test", "host"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Config.Auth != "kerberos" {
		t.Fatalf("auth = %q, want kerberos", opts.Config.Auth)
	}
	if !opts.ReadyToConnect() {
		t.Fatal("a ccache should be enough to connect")
	}
}

// TestParseKerberosSource checks --kerberos-source parsing and rejection of unknown sources.
func TestParseKerberosSource(t *testing.T) {
	t.Setenv("SMBLENS_PASSWORD", "")
	t.Setenv("KRB5CCNAME", "")

	opts, err := Parse([]string{"--kerberos-source", "ccache", "--ccache", "/tmp/cc", "host"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Config.Auth != "kerberos" || opts.Config.KerberosSource != "ccache" {
		t.Fatalf("auth=%q source=%q", opts.Config.Auth, opts.Config.KerberosSource)
	}

	if _, err := Parse([]string{"--kerberos-source", "magic", "host"}); err == nil {
		t.Fatal("an unknown Kerberos source should be rejected")
	}
}

// TestParsePasswordFromEnvironment verifies the SMBLENS_PASSWORD fallback when --password is absent.
func TestParsePasswordFromEnvironment(t *testing.T) {
	t.Setenv("SMBLENS_PASSWORD", "from-env")
	t.Setenv("SMBLENS_NTHASH", "")

	opts, err := Parse([]string{"-u", "alice", "host"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Config.Password != "from-env" {
		t.Fatalf("password = %q", opts.Config.Password)
	}
}

// TestParseTargetPortWins checks that a port in the target overrides --port.
func TestParseTargetPortWins(t *testing.T) {
	t.Setenv("SMBLENS_PASSWORD", "")
	opts, err := Parse([]string{"--port", "4450", "host:1445"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Config.Port != 1445 {
		t.Fatalf("port = %d, want 1445 from the target", opts.Config.Port)
	}
}

// TestParseRejections checks that invalid flags, credentials and positional arguments are rejected.
func TestParseRejections(t *testing.T) {
	t.Setenv("SMBLENS_PASSWORD", "")
	cases := [][]string{
		{"--auth", "magic", "host"},
		{"--depth", "-1", "host"},
		{"--hash", "not-a-hash", "host"},
		{"host", "other-host"},
		{"--bogus", "host"},
		{"--timeout", "0s", "host"},
	}
	for _, args := range cases {
		if _, err := Parse(args); err == nil {
			t.Fatalf("Parse(%v) should fail", args)
		}
	}
}

// TestParseHelpAndVersion verifies that --help and --version set their respective mode flags.
func TestParseHelpAndVersion(t *testing.T) {
	opts, err := Parse([]string{"--help"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.ShowHelp {
		t.Fatal("--help did not set ShowHelp")
	}

	opts, err = Parse([]string{"--version"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.ShowVersion {
		t.Fatal("--version did not set ShowVersion")
	}
}

// TestParseRecursiveAndDepth checks recursive mode, an unlimited depth value and share extraction.
func TestParseRecursiveAndDepth(t *testing.T) {
	t.Setenv("SMBLENS_PASSWORD", "")
	opts, err := Parse([]string{"--recursive", "--depth", "0", "host/share"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Recursive || opts.MaxDepth != 0 {
		t.Fatalf("recursive=%v depth=%d", opts.Recursive, opts.MaxDepth)
	}
	if opts.Config.Share != "share" {
		t.Fatalf("share = %q", opts.Config.Share)
	}
}

// TestFlagsWithValuesCoversEveryValueFlag guards the argument-reordering list against newly added value-taking flags.
func TestFlagsWithValuesCoversEveryValueFlag(t *testing.T) {
	// Guard against adding a value-taking flag and forgetting the list used by
	// the argument reordering.
	expected := []string{
		"u", "user", "d", "domain", "p", "password", "H", "hash", "a", "auth",
		"realm", "kdc", "spn", "ccache", "keytab", "krb5-conf", "kerberos-source",
		"share", "port", "timeout", "connect-timeout", "depth",
	}
	for _, name := range expected {
		if !flagsWithValues[name] {
			t.Fatalf("flagsWithValues is missing %q", name)
		}
	}
}

// TestUsageMentionsAuthAndProbe checks that help text documents authentication, probing and recursive options.
func TestUsageMentionsAuthAndProbe(t *testing.T) {
	usage := Usage()
	for _, want := range []string{"kerberos", "hash", "no-write-probe", "recursive", "SMBLENS_PASSWORD"} {
		if !strings.Contains(strings.ToLower(usage), strings.ToLower(want)) {
			t.Fatalf("usage text does not mention %q", want)
		}
	}
}
