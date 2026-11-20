package smbclient

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestKerberosRejectsIPWithoutSPN(t *testing.T) {
	cfg := Config{
		Auth:     AuthKerberos,
		Host:     "10.0.0.5",
		Username: "alice",
		Realm:    "CORP.EXAMPLE.COM",
		Password: "secret",
	}
	_, _, err := cfg.kerberosInitiator()
	if err == nil || !strings.Contains(err.Error(), "DNS name") {
		t.Fatalf("expected a DNS-name error, got %v", err)
	}

	// An explicit SPN makes an IP target usable.
	cfg.SPN = "cifs/server.example.com"
	_, _, err = cfg.kerberosInitiator()
	if err != nil && strings.Contains(err.Error(), "DNS name") {
		t.Fatalf("an explicit SPN should bypass the IP check, got %v", err)
	}
}

func TestKerberosSourceInference(t *testing.T) {
	t.Setenv("KRB5CCNAME", "")

	cfg := Config{}
	if got := cfg.kerberosSource(); got != KerbPassword {
		t.Fatalf("default source = %q", got)
	}

	cfg.CCachePath = "/tmp/cc"
	if got := cfg.kerberosSource(); got != KerbCCache {
		t.Fatalf("source with ccache = %q", got)
	}
	cfg.CCachePath = ""
	cfg.KeytabPath = "/tmp/kt"
	if got := cfg.kerberosSource(); got != KerbKeytab {
		t.Fatalf("source with keytab = %q", got)
	}

	t.Setenv("KRB5CCNAME", "FILE:/tmp/krb5cc_1000")
	cfg.KeytabPath = ""
	if got := cfg.kerberosSource(); got != KerbCCache {
		t.Fatalf("source with KRB5CCNAME = %q", got)
	}
	if got := cfg.ccachePath(); got != "/tmp/krb5cc_1000" {
		t.Fatalf("ccachePath = %q", got)
	}
}

func TestKerberosRealmResolution(t *testing.T) {
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{Realm: "corp.example.com."}, "CORP.EXAMPLE.COM"},
		{Config{Domain: "corp.example.com"}, "CORP.EXAMPLE.COM"},
		{Config{Realm: "one.example", Domain: "two.example"}, "ONE.EXAMPLE"},
		{Config{}, ""},
	}
	for _, c := range cases {
		if got := c.cfg.kerberosRealm(nil); got != c.want {
			t.Fatalf("kerberosRealm(%+v) = %q, want %q", c.cfg, got, c.want)
		}
	}
}

func TestKerberosMissingCacheIsFriendly(t *testing.T) {
	cfg := Config{
		Auth:           AuthKerberos,
		Host:           "server.example.com",
		CCachePath:     "/nonexistent/krb5cc",
		KerberosSource: KerbCCache,
	}
	_, _, err := cfg.kerberosInitiator()
	if err == nil || !strings.Contains(err.Error(), "credential cache") {
		t.Fatalf("expected a credential-cache error, got %v", err)
	}
}

func TestKerberosUnreachableKDCIsBounded(t *testing.T) {
	cfg := Config{
		Host:           "server.example.com",
		Port:           445,
		Auth:           AuthKerberos,
		Username:       "alice",
		Realm:          "CORP.LOCAL",
		Password:       "secret",
		KDC:            "127.0.0.1:1",
		ConnectTimeout: 2 * time.Second,
		OpTimeout:      2 * time.Second,
	}

	start := time.Now()
	_, err := Dial(context.Background(), cfg)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected Kerberos authentication to fail without a KDC")
	}
	if elapsed > 6*time.Second {
		t.Fatalf("Kerberos failure took %v; it should respect the connect timeout", elapsed.Round(time.Millisecond))
	}
	description := Describe(err)
	t.Logf("elapsed=%v describe=%s", elapsed.Round(time.Millisecond), description)
	if !strings.Contains(description, "KDC") {
		t.Fatalf("description should point at the KDC: %q", description)
	}
	if len(description) > 220 {
		t.Fatalf("description is too technical: %q", description)
	}
}

func TestNormalizeKDCAddress(t *testing.T) {
	cases := map[string]string{
		"":            "",
		"dc01":        "dc01:88",
		"dc01:88":     "dc01:88",
		"dc01:1088":   "dc01:1088",
		"10.0.0.5":    "10.0.0.5:88",
		"[::1]":       "[::1]:88",
		"[::1]:1088":  "[::1]:1088",
		"2001:db8::1": "[2001:db8::1]:88",
	}
	for input, want := range cases {
		if got := normalizeKDCAddress(input); got != want {
			t.Fatalf("normalizeKDCAddress(%q) = %q, want %q", input, got, want)
		}
	}
}
