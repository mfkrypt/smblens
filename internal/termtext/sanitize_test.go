package termtext

import "testing"

func TestCleanStripsEscapesAndControls(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain.txt", "plain.txt"},
		{"\x1b[31mred\x1b[0m", "red"},
		{"a\x1b]8;;http://evil.example\x07link\x1b]8;;\x07b", "alinkb"},
		{"a\x1bP1;2;3\x1b\\b", "ab"},
		{"tab\there", "tab?here"},
		{"line\nbreak", "line?break"},
		{"nul\x00byte", "nul?byte"},
		{"bell\x07", "bell?"},
		{"rtl‮gnp.exe", "rtl?gnp.exe"},
		{"zero​width", "zero?width"},
		{"soft­hyphen", "soft?hyphen"},
		{"bad\xffutf8", "bad�utf8"},
		{"Ångström", "Ångström"},
	}
	for _, c := range cases {
		if got := Clean(c.in); got != c.want {
			t.Fatalf("Clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanMultilineKeepsLayout(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"a\nb", "a\nb"},
		{"a\r\nb", "a\nb"},
		{"a\rb", "a\nb"},
		{"col1\tcol2", "col1    col2"},
		{"\x1b[32mgreen\x1b[0m\n", "green\n"},
		{"nul\x00byte", "nulbyte"},
		{"bidi‮text", "biditext"},
		{"bad\xffutf8", "bad�utf8"},
	}
	for _, c := range cases {
		if got := CleanMultiline(c.in); got != c.want {
			t.Fatalf("CleanMultiline(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanUnterminatedEscape(t *testing.T) {
	// An escape sequence that never terminates must not leak its payload.
	if got := Clean("visible\x1b[31"); got != "visible" {
		t.Fatalf("Clean = %q, want %q", got, "visible")
	}
	if got := Clean("a\x1b"); got != "a" {
		t.Fatalf("Clean = %q, want %q", got, "a")
	}
}
