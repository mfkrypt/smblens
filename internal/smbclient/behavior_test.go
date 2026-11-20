package smbclient

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeFS implements Lister for Walk tests.
type fakeFS struct {
	dirs   map[string][]Entry
	errors map[string]error
}

func (f *fakeFS) List(_ context.Context, dir string) ([]Entry, error) {
	if err, ok := f.errors[dir]; ok {
		return nil, err
	}
	entries, ok := f.dirs[dir]
	if !ok {
		return nil, os.ErrNotExist
	}
	return entries, nil
}

func entry(name string, dir bool, size int64) Entry {
	return Entry{Name: name, Path: name, Dir: dir, Size: size}
}

func TestWalkTraversesDepthFirst(t *testing.T) {
	fs := &fakeFS{dirs: map[string][]Entry{
		"": {
			{Name: "b.txt", Path: "b.txt", Size: 2},
			{Name: "a", Path: "a", Dir: true},
		},
		"a": {
			{Name: "inner.txt", Path: "a/inner.txt", Size: 5},
			{Name: "child", Path: "a/child", Dir: true},
		},
		"a/child": {
			{Name: "deep.txt", Path: "a/child/deep.txt", Size: 7},
		},
	}}

	var got []string
	var stats WalkStats
	err := Walk(context.Background(), fs, "", WalkOptions{
		MaxDepth: 0,
		Progress: func(s WalkStats) { stats = s },
	}, func(item WalkItem) {
		if item.Err != nil {
			t.Fatalf("unexpected error at %q: %v", item.Path, item.Err)
		}
		got = append(got, item.Path)
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	want := []string{"b.txt", "a", "a/inner.txt", "a/child", "a/child/deep.txt"}
	if len(got) != len(want) {
		t.Fatalf("walked %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("walked %v, want %v", got, want)
		}
	}
	if stats.Dirs != 2 || stats.Files != 3 || stats.Bytes != 14 {
		t.Fatalf("stats = %+v, want dirs=2 files=3 bytes=14", stats)
	}
}

func TestWalkHonoursMaxDepth(t *testing.T) {
	fs := &fakeFS{dirs: map[string][]Entry{
		"":    {{Name: "a", Path: "a", Dir: true}},
		"a":   {{Name: "b", Path: "a/b", Dir: true}, {Name: "f", Path: "a/f"}},
		"a/b": {{Name: "deep", Path: "a/b/deep"}},
	}}

	var got []string
	err := Walk(context.Background(), fs, "", WalkOptions{MaxDepth: 1}, func(item WalkItem) {
		got = append(got, item.Path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "a" {
		t.Fatalf("walk with MaxDepth=1 = %v, want [a]", got)
	}

	got = nil
	err = Walk(context.Background(), fs, "", WalkOptions{MaxDepth: 2, SkipDirs: true}, func(item WalkItem) {
		got = append(got, item.Path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "a/f" {
		t.Fatalf("walk with MaxDepth=2/SkipDirs = %v, want [a/f]", got)
	}
}

func TestWalkReportsDirectoryErrorsAndContinues(t *testing.T) {
	fs := &fakeFS{
		dirs: map[string][]Entry{
			"":   {{Name: "blocked", Path: "blocked", Dir: true}, {Name: "ok", Path: "ok", Dir: true}},
			"ok": {{Name: "f.txt", Path: "ok/f.txt"}},
		},
		errors: map[string]error{"blocked": os.ErrPermission},
	}

	var paths []string
	var errItems int
	err := Walk(context.Background(), fs, "", WalkOptions{}, func(item WalkItem) {
		if item.Err != nil {
			errItems++
			if !errors.Is(item.Err, os.ErrPermission) {
				t.Fatalf("unexpected error: %v", item.Err)
			}
			return
		}
		paths = append(paths, item.Path)
	})
	if err != nil {
		t.Fatalf("Walk should not fail on a subtree error: %v", err)
	}
	if errItems != 1 {
		t.Fatalf("error items = %d, want 1", errItems)
	}
	found := false
	for _, p := range paths {
		if p == "ok/f.txt" {
			found = true
		}
	}
	if len(paths) != 3 || !found {
		t.Fatalf("paths = %v, want the healthy branch to be walked", paths)
	}
}

func TestWalkRootErrorIsFatal(t *testing.T) {
	fs := &fakeFS{dirs: map[string][]Entry{}, errors: map[string]error{"": os.ErrPermission}}
	if err := Walk(context.Background(), fs, "", WalkOptions{}, func(WalkItem) {}); err == nil {
		t.Fatal("expected a root listing error")
	}
}

func TestWalkCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fs := &fakeFS{dirs: map[string][]Entry{"": {entry("a.txt", false, 1)}}}
	if err := Walk(ctx, fs, "", WalkOptions{}, func(WalkItem) {}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Walk with a cancelled context returned %v, want context.Canceled", err)
	}
}

func TestWalkRejectsParentTraversal(t *testing.T) {
	fs := &fakeFS{dirs: map[string][]Entry{}}
	if err := Walk(context.Background(), fs, "../etc", WalkOptions{}, func(WalkItem) {}); err == nil {
		t.Fatal("expected a traversal error")
	}
}

func TestCleanRemotePath(t *testing.T) {
	valid := map[string]string{
		"":             "",
		".":            "",
		"a/b":          "a/b",
		`a\b`:          "a/b",
		"/a//b/":       "a/b",
		"dir/file.txt": "dir/file.txt",
		"a/./b":        "a/b",
	}
	for input, want := range valid {
		got, err := cleanRemotePath(input)
		if err != nil {
			t.Fatalf("cleanRemotePath(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("cleanRemotePath(%q) = %q, want %q", input, got, want)
		}
	}

	invalid := []string{"..", "../x", "a/../../b", "a/..", "a\x00b"}
	for _, input := range invalid {
		if _, err := cleanRemotePath(input); err == nil {
			t.Fatalf("cleanRemotePath(%q) should fail", input)
		}
	}
}

func TestSafeEntryName(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b", `a\b`, "a\x00b"} {
		if _, ok := safeEntryName(name); ok {
			t.Fatalf("safeEntryName(%q) should be rejected", name)
		}
	}
	for _, name := range []string{"file.txt", "a b", ".hidden", "Ångström"} {
		if _, ok := safeEntryName(name); !ok {
			t.Fatalf("safeEntryName(%q) should be accepted", name)
		}
	}
}

func TestLocalDownloadPathWithoutShareComponent(t *testing.T) {
	if got := LocalDownloadPath("/tmp/downloads", "", "file.txt"); got != "/tmp/downloads/file.txt" {
		t.Fatalf("LocalDownloadPath = %q", got)
	}
}

func TestLocalTreePath(t *testing.T) {
	root := "/tmp/downloads"
	cases := map[string]string{
		"":                    "/tmp/downloads",
		"file.txt":            "/tmp/downloads/file.txt",
		"dir/file.txt":        "/tmp/downloads/dir/file.txt",
		"dir/subdir/file.txt": "/tmp/downloads/dir/subdir/file.txt",
		"../escape/file.txt":  "/tmp/downloads/escape/file.txt",
		"dir/../file.txt":     "/tmp/downloads/dir/file.txt",
		"dir\\file.txt":       "/tmp/downloads/dir/file.txt",
	}
	for input, want := range cases {
		if got := localTreePath(root, input); got != want {
			t.Fatalf("localTreePath(%q) = %q, want %q", input, got, want)
		}
	}

	if got := localTreePath(root, "dir/\x1b[31mevil"); strings.ContainsRune(got, 0x1b) {
		t.Fatalf("localTreePath kept an escape character: %q", got)
	}
}

func TestLocalDownloadPathCannotEscape(t *testing.T) {
	base := "/tmp/downloads"
	got := LocalDownloadPath(base, "../../etc", "../../../passwd")
	if got != "/tmp/downloads/etc/passwd" {
		t.Fatalf("LocalDownloadPath = %q, want it confined under the base directory", got)
	}
}

func TestLocalDownloadPathSanitisesControlCharacters(t *testing.T) {
	got := LocalDownloadPath("/tmp/downloads", "share\x1b]0;pwned\x07", "dir\x1b[31mred/file.txt")
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
		t.Fatalf("local path contains control characters: %q", got)
	}
	if !strings.Contains(got, "file.txt") {
		t.Fatalf("local path = %q", got)
	}
}

func TestLooksBinary(t *testing.T) {
	if looksBinary([]byte("plain text\n")) {
		t.Fatal("plain text detected as binary")
	}
	if !looksBinary([]byte{'a', 0, 'b'}) {
		t.Fatal("NUL byte not detected")
	}
}

func TestAccessLabel(t *testing.T) {
	cases := []struct {
		state AccessState
		want  string
	}{
		{AccessState{}, "-"},
		{AccessState{Denied: true}, "DENIED"},
		{AccessState{Err: errors.New("boom")}, "ERROR"},
		{AccessState{Mounted: true, Read: true, Write: true, WriteTested: true}, "RW"},
		{AccessState{Mounted: true, Read: true, WriteTested: true}, "R"},
		{AccessState{Mounted: true, Write: true, WriteTested: true}, "W"},
		{AccessState{Mounted: true, Read: true}, "R*"},
	}
	for _, c := range cases {
		if got := c.state.Label(); got != c.want {
			t.Fatalf("Label(%+v) = %q, want %q", c.state, got, c.want)
		}
	}
}

func TestWhitespaceInNamesIsPreserved(t *testing.T) {
	if got := JoinPath("dir", " report 2024.txt "); got != "dir/ report 2024.txt " {
		t.Fatalf("JoinPath = %q", got)
	}
	if got, err := cleanRemotePath("dir/ report 2024.txt "); err != nil || got != "dir/ report 2024.txt " {
		t.Fatalf("cleanRemotePath = %q, %v", got, err)
	}
}

func TestJoinAndParentPath(t *testing.T) {
	if got := JoinPath("a", "b", "c"); got != "a/b/c" {
		t.Fatalf("JoinPath = %q", got)
	}
	if got := JoinPath("", "a", ""); got != "a" {
		t.Fatalf("JoinPath = %q", got)
	}
	if got := ParentPath("a/b/c"); got != "a/b" {
		t.Fatalf("ParentPath = %q", got)
	}
	if got := ParentPath("a"); got != "" {
		t.Fatalf("ParentPath(a) = %q", got)
	}
	if got := ParentPath(""); got != "" {
		t.Fatalf("ParentPath() = %q", got)
	}
}
