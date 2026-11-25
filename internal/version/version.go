// Package version reports the version of the running SMBLens binary.
//
// Binaries installed with "go install github.com/mfkrypt/smblens@vX.Y.Z"
// carry the module version in their build metadata, so no hardcoded release
// string is needed. Source builds report "devel" together with the git
// revision, date, and dirty flag. A build may inject an explicit version:
//
//	go build -ldflags "-X github.com/mfkrypt/smblens/internal/version.Version=v0.1.1" .
package version

import (
	"runtime/debug"
	"strings"
	"time"
)

// Version, Commit and Date can be set at build time with -X. When Version is
// empty, the module version recorded by the Go toolchain is used.
var (
	Version string
	Commit  string
	Date    string
)

// Info describes the version embedded in the binary.
type Info struct {
	Version  string
	Commit   string
	Date     string
	Modified bool
}

// Get resolves the version information from build-time overrides and the Go
// build metadata.
func Get() Info {
	info := Info{Version: Version, Commit: Commit, Date: Date}

	if build, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "" {
			if v := build.Main.Version; v != "" && v != "(devel)" {
				info.Version = v
			}
		}
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = setting.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = setting.Value
				}
			case "vcs.modified":
				info.Modified = setting.Value == "true"
			}
		}
	}

	if info.Version == "" {
		info.Version = "devel"
	}
	return info
}

// String formats the version as "v1.2.3 (abc1234, 2026-11-21, dirty)".
func (i Info) String() string {
	version := i.Version
	if version == "" {
		version = "devel"
	}

	var meta []string
	if i.Commit != "" {
		commit := i.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		meta = append(meta, commit)
	}
	if i.Date != "" {
		meta = append(meta, formatDate(i.Date))
	}
	// Go's version stamp may already carry the "+dirty" suffix.
	if i.Modified && !strings.Contains(version, "+dirty") {
		meta = append(meta, "dirty")
	}

	if len(meta) == 0 {
		return version
	}
	return version + " (" + strings.Join(meta, ", ") + ")"
}

// formatDate renders an RFC3339 build timestamp as YYYY-MM-DD; values that do not parse are returned unchanged.
func formatDate(value string) string {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	return value
}
