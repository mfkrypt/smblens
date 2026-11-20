package smbclient

import (
	"context"
	"fmt"
)

// Lister is the part of *Share that Walk needs. It is an interface so the
// traversal can be tested without a server.
type Lister interface {
	List(ctx context.Context, dir string) ([]Entry, error)
}

// WalkOptions controls a recursive listing.
type WalkOptions struct {
	// MaxDepth limits recursion. Zero means unlimited; 1 lists only the root.
	MaxDepth int
	// SkipDirs omits directory entries from the results (they are still
	// traversed).
	SkipDirs bool
	// Progress, if set, is called after each directory is listed.
	Progress func(WalkStats)
}

// WalkStats summarises a recursive listing so far.
type WalkStats struct {
	Dirs   int
	Files  int
	Bytes  int64
	Errors int
}

// WalkItem is one entry discovered by Walk, or an error for a directory that
// could not be listed.
type WalkItem struct {
	Entry
	Depth int
	Err   error
}

// Walk performs a depth-first recursive listing starting at root (the share
// root is ""). Directory-level errors are reported as WalkItems with Err set
// and do not stop the walk. Walk returns an error only when the root cannot be
// listed or ctx is cancelled.
func Walk(ctx context.Context, lister Lister, root string, opts WalkOptions, visit func(WalkItem)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if visit == nil {
		visit = func(WalkItem) {}
	}
	root, err := cleanRemotePath(root)
	if err != nil {
		return err
	}

	var stats WalkStats

	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		entries, err := lister.List(ctx, dir)
		if err != nil {
			if depth == 0 {
				return err
			}
			stats.Errors++
			visit(WalkItem{
				Entry: Entry{Path: dir, Name: BaseName(dir), Dir: true},
				Depth: depth,
				Err:   err,
			})
			return nil
		}

		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			childDepth := depth + 1
			item := WalkItem{Entry: entry, Depth: childDepth}

			if entry.Dir {
				stats.Dirs++
				if !opts.SkipDirs {
					visit(item)
				}
				if opts.MaxDepth <= 0 || childDepth < opts.MaxDepth {
					if err := walk(entry.Path, childDepth); err != nil {
						return err
					}
				}
				continue
			}

			stats.Files++
			stats.Bytes += entry.Size
			visit(item)
		}

		if opts.Progress != nil {
			opts.Progress(stats)
		}
		return nil
	}

	if err := walk(root, 0); err != nil {
		return err
	}
	return ctx.Err()
}

// WalkShare runs Walk against a mounted share.
func (s *Share) WalkShare(ctx context.Context, root string, opts WalkOptions, visit func(WalkItem)) error {
	if err := Walk(ctx, s, root, opts, visit); err != nil {
		return fmt.Errorf("walking %s: %w", s.displayPath(root), err)
	}
	return nil
}
