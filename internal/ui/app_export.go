package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mfkrypt/smblens/internal/smbclient"
)

// shareReport is the JSON structure exported from the share list.
type shareReport struct {
	Host      string        `json:"host"`
	User      string        `json:"user"`
	Auth      string        `json:"auth"`
	Generated time.Time     `json:"generated"`
	Shares    []shareRecord `json:"shares"`
}

type shareRecord struct {
	Name    string       `json:"name"`
	Comment string       `json:"comment,omitempty"`
	Type    string       `json:"type"`
	Special bool         `json:"special"`
	Access  accessRecord `json:"access"`
}

type accessRecord struct {
	Connects    bool   `json:"connects"`
	Read        bool   `json:"read"`
	Write       bool   `json:"write"`
	WriteTested bool   `json:"write_tested"`
	Denied      bool   `json:"denied"`
	Note        string `json:"note,omitempty"`
	Error       string `json:"error,omitempty"`
}

type treeReport struct {
	Host      string       `json:"host"`
	Share     string       `json:"share"`
	Root      string       `json:"root"`
	Generated time.Time    `json:"generated"`
	Entries   []treeRecord `json:"entries"`
}

type treeRecord struct {
	Path     string    `json:"path"`
	Dir      bool      `json:"dir"`
	Symlink  bool      `json:"symlink,omitempty"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Error    string    `json:"error,omitempty"`
}

// writeShareReport writes the share enumeration as JSON with owner-only
// permissions, since the data maps the server's accessible surface.
func writeShareReport(path string, cfg smbclient.Config, shares []smbclient.ShareInfo) error {
	report := shareReport{
		Host:      cfg.Host,
		User:      cfg.UserLabel(),
		Auth:      string(cfg.Auth),
		Generated: time.Now(),
		Shares:    make([]shareRecord, 0, len(shares)),
	}
	for _, share := range shares {
		record := shareRecord{
			Name:    share.Name,
			Comment: share.Comment,
			Type:    string(share.Kind),
			Special: share.Special,
			Access: accessRecord{
				Connects:    share.Access.Mounted,
				Read:        share.Access.Read,
				Write:       share.Access.Write,
				WriteTested: share.Access.WriteTested,
				Denied:      share.Access.Denied,
				Note:        share.Access.Note,
			},
		}
		if share.Access.Err != nil {
			record.Access.Error = smbclient.Describe(share.Access.Err)
		}
		report.Shares = append(report.Shares, record)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding share report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// writeTreeReport writes a recursive scan as JSON.
func writeTreeReport(path, host, share, root string, items []smbclient.WalkItem) error {
	report := treeReport{
		Host:      host,
		Share:     share,
		Root:      root,
		Generated: time.Now(),
		Entries:   make([]treeRecord, 0, len(items)),
	}
	for _, item := range items {
		record := treeRecord{
			Path:     item.Path,
			Dir:      item.Dir,
			Symlink:  item.Symlink,
			Size:     item.Size,
			Modified: item.ModTime,
		}
		if item.Err != nil {
			record.Error = smbclient.Describe(item.Err)
		}
		report.Entries = append(report.Entries, record)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding scan report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// exportTimestamp formats the current local time for inclusion in export filenames.
func exportTimestamp() string {
	return time.Now().Format("20060102-150405")
}

// shareExportName builds the filename for a share enumeration export.
func shareExportName(host string) string {
	return fmt.Sprintf("smblens-shares-%s-%s.json", safeFilename(host), exportTimestamp())
}

// treeExportName builds the filename for a recursive scan export.
func treeExportName(host, share string) string {
	return fmt.Sprintf("smblens-tree-%s-%s-%s.json", safeFilename(host), safeFilename(share), exportTimestamp())
}
