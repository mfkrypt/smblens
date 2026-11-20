package smbclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cloudsoda/go-smb2"
)

// MaxViewBytes is the largest slice of a remote file the viewer will load.
const MaxViewBytes = 4 << 20 // 4 MiB

// ErrExists is returned when a transfer target already exists and overwriting
// was not requested.
var ErrExists = errors.New("the target already exists")

// ProgressFunc reports transfer progress. total may be zero if the size is
// unknown.
type ProgressFunc func(done, total int64)

// FileContent is a bounded read of a remote file for the text viewer.
type FileContent struct {
	Data      []byte
	Size      int64
	Truncated bool
	Binary    bool
}

// List returns the entries of a directory. The share root is the empty string.
func (s *Share) List(ctx context.Context, dir string) ([]Entry, error) {
	dir, err := cleanRemotePath(dir)
	if err != nil {
		return nil, err
	}

	var infos []os.FileInfo
	err = s.do(ctx, s.client.cfg.OpTimeout, func(share *smb2.Share) error {
		got, err := share.ReadDir(dir)
		if err != nil {
			return err
		}
		infos = got
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", s.displayPath(dir), err)
	}

	entries := make([]Entry, 0, len(infos))
	for _, info := range infos {
		name, ok := safeEntryName(info.Name())
		if !ok {
			// A conforming SMB server cannot return these, but a hostile one
			// can. Dropping the entry keeps paths unambiguous.
			continue
		}
		entries = append(entries, entryFromInfo(name, JoinPath(dir, name), info))
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries, nil
}

// ReadText loads up to limit bytes of a file for display. Binary detection is
// a NUL-byte scan over the data that was read.
func (s *Share) ReadText(ctx context.Context, remotePath string, limit int64) (FileContent, error) {
	remotePath, err := cleanRemotePath(remotePath)
	if err != nil {
		return FileContent{}, err
	}
	if limit <= 0 || limit > MaxViewBytes {
		limit = MaxViewBytes
	}

	var content FileContent
	err = s.do(ctx, s.client.cfg.OpTimeout, func(share *smb2.Share) error {
		file, err := share.OpenFile(remotePath, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer file.Close()

		if info, err := file.Stat(); err == nil {
			content.Size = info.Size()
		}

		buf := make([]byte, 0, limit)
		chunk := make([]byte, 64<<10)
		for int64(len(buf)) <= limit {
			n, readErr := file.Read(chunk)
			if n > 0 {
				remain := limit + 1 - int64(len(buf))
				if int64(n) > remain {
					n = int(remain)
				}
				buf = append(buf, chunk[:n]...)
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				return readErr
			}
			if n == 0 {
				break
			}
		}

		if int64(len(buf)) > limit {
			buf = buf[:limit]
			content.Truncated = true
		}
		content.Data = buf
		content.Binary = looksBinary(buf)
		return nil
	})
	if err != nil {
		return FileContent{}, fmt.Errorf("reading %s: %w", s.displayPath(remotePath), err)
	}
	return content, nil
}

// Download copies a remote file to localPath, creating parent directories.
// The data is written to a temporary file and renamed into place, so a failed
// or cancelled transfer never leaves a truncated destination file.
func (s *Share) Download(ctx context.Context, remotePath, localPath string, progress ProgressFunc) error {
	remotePath, err := cleanRemotePath(remotePath)
	if err != nil {
		return err
	}
	if localPath == "" {
		return errors.New("no local destination given")
	}

	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return fmt.Errorf("creating local directory: %w", err)
	}

	tempPath := localPath + ".part"
	localFile, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tempPath, err)
	}
	cleanup := func() {
		_ = localFile.Close()
		_ = os.Remove(tempPath)
	}

	err = s.do(ctx, 0, func(share *smb2.Share) error {
		remote, err := share.OpenFile(remotePath, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer remote.Close()

		var total int64
		if info, err := remote.Stat(); err == nil {
			total = info.Size()
		}

		tracker := newProgressTracker(total, progress)
		src := &progressReader{ctx: ctx, reader: remote, tracker: tracker}
		if _, err := io.CopyBuffer(localFile, src, make([]byte, 128<<10)); err != nil {
			return err
		}
		tracker.finish()

		if info, err := remote.Stat(); err == nil && !info.ModTime().IsZero() {
			_ = os.Chtimes(tempPath, info.ModTime(), info.ModTime())
		}
		return nil
	})
	if err != nil {
		cleanup()
		return fmt.Errorf("downloading %s: %w", s.displayPath(remotePath), err)
	}
	if err := localFile.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("writing %s: %w", tempPath, err)
	}
	if err := localFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("writing %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, localPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("saving %s: %w", localPath, err)
	}
	return nil
}

// Upload copies a local file to remotePath. If overwrite is false and the
// remote file exists, ErrExists is returned. A partial remote file is removed
// after a failure only when it did not exist before the upload started.
func (s *Share) Upload(ctx context.Context, localPath, remotePath string, overwrite bool, progress ProgressFunc) error {
	remotePath, err := cleanRemotePath(remotePath)
	if err != nil {
		return err
	}
	if remotePath == "" {
		return errors.New("no remote destination given")
	}

	local, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", localPath, err)
	}
	defer local.Close()

	var total int64
	if info, err := local.Stat(); err == nil {
		total = info.Size()
	}

	created := false
	err = s.do(ctx, 0, func(share *smb2.Share) error {
		if !overwrite {
			if _, statErr := share.Stat(remotePath); statErr == nil {
				return ErrExists
			} else if !IsNotFound(statErr) {
				return statErr
			}
		}

		remote, err := share.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if !overwrite {
			created = true
		}

		tracker := newProgressTracker(total, progress)
		src := &progressReader{ctx: ctx, reader: local, tracker: tracker}
		if _, err := io.CopyBuffer(remote, src, make([]byte, 128<<10)); err != nil {
			_ = remote.Close()
			return err
		}
		tracker.finish()
		return remote.Close()
	})
	if err != nil {
		if created {
			// Best effort: do not leave a half-written new file behind.
			_ = s.do(context.Background(), s.client.cfg.OpTimeout, func(share *smb2.Share) error {
				return share.Remove(remotePath)
			})
		}
		if errors.Is(err, ErrExists) {
			return ErrExists
		}
		return fmt.Errorf("uploading %s: %w", s.displayPath(remotePath), err)
	}
	return nil
}

// Mkdir creates a directory.
func (s *Share) Mkdir(ctx context.Context, remotePath string) error {
	remotePath, err := cleanRemotePath(remotePath)
	if err != nil {
		return err
	}
	if remotePath == "" {
		return errors.New("no directory name given")
	}
	err = s.do(ctx, s.client.cfg.OpTimeout, func(share *smb2.Share) error {
		return share.Mkdir(remotePath, 0o755)
	})
	if err != nil {
		return fmt.Errorf("creating folder %s: %w", s.displayPath(remotePath), err)
	}
	return nil
}

// Remove deletes a file or an empty directory.
func (s *Share) Remove(ctx context.Context, remotePath string) error {
	remotePath, err := cleanRemotePath(remotePath)
	if err != nil {
		return err
	}
	if remotePath == "" {
		return errors.New("refusing to delete the share root")
	}
	err = s.do(ctx, s.client.cfg.OpTimeout, func(share *smb2.Share) error {
		return share.Remove(remotePath)
	})
	if err != nil {
		return fmt.Errorf("deleting %s: %w", s.displayPath(remotePath), err)
	}
	return nil
}

// Rename moves or renames a file or directory. An existing destination is
// replaced, matching the SMB semantics of the underlying request.
func (s *Share) Rename(ctx context.Context, oldPath, newPath string) error {
	oldPath, err := cleanRemotePath(oldPath)
	if err != nil {
		return err
	}
	newPath, err = cleanRemotePath(newPath)
	if err != nil {
		return err
	}
	if oldPath == "" || newPath == "" {
		return errors.New("both the old and new names are required")
	}
	err = s.do(ctx, s.client.cfg.OpTimeout, func(share *smb2.Share) error {
		return share.Rename(oldPath, newPath)
	})
	if err != nil {
		return fmt.Errorf("renaming %s: %w", s.displayPath(oldPath), err)
	}
	return nil
}

// displayPath formats a share-relative path as \\host\share\path.
func (s *Share) displayPath(p string) string {
	if p == "" {
		return uncPath(s.Host(), s.Name())
	}
	return uncPath(s.Host(), s.Name()) + `\` + strings.ReplaceAll(p, "/", `\`)
}

func entryFromInfo(name, entryPath string, info os.FileInfo) Entry {
	mode := info.Mode()
	hidden := strings.HasPrefix(name, ".")
	if stat, ok := info.(*smb2.FileStat); ok && stat.FileAttributes&0x2 != 0 {
		hidden = true // FILE_ATTRIBUTE_HIDDEN
	}
	return Entry{
		Name:    name,
		Path:    entryPath,
		Dir:     mode.IsDir(),
		Symlink: mode&os.ModeSymlink != 0,
		Hidden:  hidden,
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Mode:    mode,
	}
}

// cleanRemotePath normalises a share-relative path and refuses traversal.
func cleanRemotePath(p string) (string, error) {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.Trim(p, "/")
	if p == "" {
		return "", nil
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return "", fmt.Errorf("invalid path %q: parent traversal is not allowed", p)
		}
		if part == "." || part == "" {
			continue
		}
		if strings.ContainsRune(part, 0) {
			return "", fmt.Errorf("invalid path %q: it contains a NUL byte", p)
		}
	}
	return JoinPath(p), nil
}

// safeEntryName accepts a name returned by the server only if it cannot
// change the meaning of the path it is joined to.
func safeEntryName(name string) (string, bool) {
	switch {
	case name == "", name == ".", name == "..":
		return "", false
	case strings.ContainsAny(name, `/\`):
		return "", false
	case strings.ContainsRune(name, 0):
		return "", false
	}
	return name, true
}

// looksBinary reports whether data appears to be binary, based on NUL bytes.
func looksBinary(data []byte) bool {
	if len(data) > 8<<10 {
		data = data[:8<<10]
	}
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

// progressReader reports read progress and honours context cancellation.
type progressReader struct {
	ctx     context.Context
	reader  io.Reader
	tracker *progressTracker
}

func (r *progressReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if n > 0 {
		r.tracker.add(int64(n))
	}
	return n, err
}

// progressTracker throttles progress notifications.
type progressTracker struct {
	total   int64
	done    int64
	last    time.Time
	report  ProgressFunc
	started time.Time
}

func newProgressTracker(total int64, report ProgressFunc) *progressTracker {
	t := &progressTracker{total: total, report: report, started: time.Now()}
	if report != nil {
		report(0, total)
	}
	return t
}

func (t *progressTracker) add(n int64) {
	t.done += n
	if t.report == nil {
		return
	}
	if time.Since(t.last) >= 100*time.Millisecond {
		t.last = time.Now()
		t.report(t.done, t.total)
	}
}

func (t *progressTracker) finish() {
	if t.report != nil {
		t.report(t.done, t.total)
	}
}

// LocalDownloadPath builds a safe local destination for a remote entry under
// baseDir. Every remote component is reduced to a base name, so a hostile
// server cannot escape baseDir with "..".
func LocalDownloadPath(baseDir, shareName, remotePath string) string {
	parts := []string{baseDir}
	if shareName != "" {
		parts = append(parts, sanitizeLocalComponent(shareName))
	}
	for _, part := range strings.Split(strings.ReplaceAll(remotePath, `\`, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			continue
		}
		parts = append(parts, sanitizeLocalComponent(part))
	}
	return filepath.Join(parts...)
}

func sanitizeLocalComponent(s string) string {
	s = path.Base(strings.ReplaceAll(s, `\`, "/"))
	s = strings.ReplaceAll(s, string(os.PathSeparator), "_")

	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			b.WriteByte('_')
		case r == 0x00ad, r == 0x061c, r == 0x180e, r == 0xfeff,
			r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e,
			r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x2069:
			b.WriteByte('_') // invisible formatting characters
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		return "_"
	}
	return out
}
