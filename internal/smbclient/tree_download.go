package smbclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Tree download phases reported in TreeDownloadProgress.
const (
	TreePhaseScanning    = "scanning"
	TreePhaseDownloading = "downloading"
)

// MaxTreeDownloadFiles bounds a recursive download. A folder containing more
// files is rejected rather than silently partially downloaded.
const MaxTreeDownloadFiles = 200_000

// maxTreeDownloadErrors bounds the error list kept for the summary dialog.
const maxTreeDownloadErrors = 500

// TreeDownloadProgress reports recursive download progress. During scanning,
// FilesDone/BytesDone count what has been found so far and the totals are
// zero; during downloading they are exact.
type TreeDownloadProgress struct {
	Phase      string
	FilesDone  int
	FilesTotal int
	BytesDone  int64
	BytesTotal int64
	Current    string
}

// TreeDownloadResult summarises a recursive download.
type TreeDownloadResult struct {
	Files      int   // files downloaded successfully
	FilesTotal int   // files found during the scan
	Bytes      int64 // bytes downloaded successfully
	BytesTotal int64 // bytes found during the scan
	Failed     int   // file or folder problems
	Skipped    int   // symlinks skipped
	Errors     []string
}

// addProblem records a failed path in the result, bounding the retained error list.
func (r *TreeDownloadResult) addProblem(path string, err error) {
	r.Failed++
	if len(r.Errors) >= maxTreeDownloadErrors {
		return
	}
	if err == nil {
		r.Errors = append(r.Errors, path)
		return
	}
	r.Errors = append(r.Errors, path+": "+Describe(err))
}

// addSkipped records a symlink or reparse point that was deliberately not downloaded.
func (r *TreeDownloadResult) addSkipped(path, kind string) {
	r.Skipped++
	if len(r.Errors) < maxTreeDownloadErrors {
		r.Errors = append(r.Errors, path+": "+kind+" skipped")
	}
}

// DownloadTree copies a remote folder and everything under it into localRoot.
// The remote directory structure is preserved, including empty folders.
//
// Per-file errors are recorded in the result and do not stop the download.
// The operation stops early only when the context is cancelled, the remote
// root cannot be listed, or the folder exceeds MaxTreeDownloadFiles.
func (s *Share) DownloadTree(ctx context.Context, remoteRoot, localRoot string, progress func(TreeDownloadProgress)) (TreeDownloadResult, error) {
	var result TreeDownloadResult

	remoteRoot, err := cleanRemotePath(remoteRoot)
	if err != nil {
		return result, err
	}
	localRoot = strings.TrimSpace(localRoot)
	if localRoot == "" {
		return result, errors.New("no local destination folder given")
	}

	report := func(p TreeDownloadProgress) {
		if progress != nil {
			progress(p)
		}
	}

	type fileItem struct {
		remote string
		rel    string
	}

	var (
		files      []fileItem
		dirs       []string
		totalBytes int64
		tooMany    bool
	)

	scanCtx, stop := context.WithCancel(ctx)
	defer stop()

	// Pass 1: list the tree so totals and empty folders are known before any
	// file is transferred.
	walkErr := Walk(scanCtx, s, remoteRoot, WalkOptions{}, func(item WalkItem) {
		if item.Err != nil {
			result.addProblem(item.Path, item.Err)
			return
		}

		rel := item.Path
		if remoteRoot != "" {
			rel = strings.TrimPrefix(rel, remoteRoot+"/")
		}
		if item.Dir {
			dirs = append(dirs, rel)
			return
		}
		if item.Symlink {
			result.addSkipped(item.Path, "symlink")
			return
		}
		if item.IsSpecial() {
			result.addSkipped(item.Path, "reparse point")
			return
		}
		if len(files) >= MaxTreeDownloadFiles {
			tooMany = true
			stop()
			return
		}

		files = append(files, fileItem{remote: item.Path, rel: rel})
		totalBytes += item.Size
		report(TreeDownloadProgress{
			Phase:     TreePhaseScanning,
			FilesDone: len(files),
			BytesDone: totalBytes,
			Current:   rel,
		})
	})
	if tooMany {
		return result, fmt.Errorf("the folder contains more than %d files; choose a smaller folder", MaxTreeDownloadFiles)
	}
	if walkErr != nil {
		return result, walkErr
	}

	result.FilesTotal = len(files)
	result.BytesTotal = totalBytes

	if err := os.MkdirAll(localRoot, 0o755); err != nil {
		return result, fmt.Errorf("creating local folder %s: %w", localRoot, err)
	}
	for _, rel := range dirs {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if rel == "" {
			continue
		}
		if err := os.MkdirAll(localTreePath(localRoot, rel), 0o755); err != nil {
			result.addProblem(rel, fmt.Errorf("creating local folder: %w", err))
		}
	}

	// Pass 2: download every file, continuing past per-file failures.
	var (
		filesDone int
		bytesDone int64
	)
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		localPath := localTreePath(localRoot, file.rel)
		report(TreeDownloadProgress{
			Phase:      TreePhaseDownloading,
			FilesDone:  filesDone,
			FilesTotal: len(files),
			BytesDone:  bytesDone,
			BytesTotal: totalBytes,
			Current:    file.rel,
		})

		var fileDone int64
		err := s.Download(ctx, file.remote, localPath, func(done, total int64) {
			fileDone = done
			report(TreeDownloadProgress{
				Phase:      TreePhaseDownloading,
				FilesDone:  filesDone,
				FilesTotal: len(files),
				BytesDone:  bytesDone + done,
				BytesTotal: totalBytes,
				Current:    file.rel,
			})
		})
		if err != nil {
			if ctx.Err() != nil {
				return result, err
			}
			result.addProblem(file.rel, err)
			continue
		}

		filesDone++
		bytesDone += fileDone
		result.Files = filesDone
		result.Bytes = bytesDone
		report(TreeDownloadProgress{
			Phase:      TreePhaseDownloading,
			FilesDone:  filesDone,
			FilesTotal: len(files),
			BytesDone:  bytesDone,
			BytesTotal: totalBytes,
			Current:    file.rel,
		})
	}

	return result, nil
}

// localTreePath maps a share-relative path into root, sanitising each
// component so a hostile name cannot escape the destination or inject
// terminal control characters into later output.
func localTreePath(root, rel string) string {
	parts := []string{root}
	for _, part := range strings.Split(strings.ReplaceAll(rel, `\`, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			continue
		}
		parts = append(parts, sanitizeLocalComponent(part))
	}
	return filepath.Join(parts...)
}
