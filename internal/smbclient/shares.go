package smbclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cloudsoda/go-smb2"
)

// probeFilePrefix names the temporary file used to test write access. The
// random suffix prevents collisions with real data and with concurrent runs.
const probeFilePrefix = ".smblens-probe-"

// ListShares asks the server service for its share list.
func (c *Client) ListShares(ctx context.Context) ([]ShareInfo, error) {
	var reported []smb2.ShareInfo
	err := c.do(ctx, c.cfg.OpTimeout, func(session *smb2.Session) error {
		shares, err := session.ListShares()
		if err != nil {
			return err
		}
		reported = shares
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing shares on %s: %w", c.cfg.Host, err)
	}

	infos := make([]ShareInfo, 0, len(reported))
	for _, share := range reported {
		infos = append(infos, ShareInfo{
			Name:      share.Name,
			Comment:   share.Comment,
			Kind:      shareKind(share.Type()),
			Special:   share.IsSpecial(),
			Temporary: share.IsTemporary(),
		})
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].Special != infos[j].Special {
			return !infos[i].Special // regular shares first
		}
		return strings.ToLower(infos[i].Name) < strings.ToLower(infos[j].Name)
	})
	return infos, nil
}

// EnumerateShares lists shares and probes the access level of each one.
//
// If ctx is cancelled part-way through, the shares examined so far are
// returned together with the context error.
func (c *Client) EnumerateShares(ctx context.Context, probeWrite bool) ([]ShareInfo, error) {
	infos, err := c.ListShares(ctx)
	if err != nil {
		return nil, err
	}
	for i := range infos {
		if err := ctx.Err(); err != nil {
			return infos, err
		}
		infos[i].Access = c.probeShare(ctx, infos[i], probeWrite)
	}
	return infos, nil
}

// probeShare mounts the share, lists its root, and optionally creates and
// deletes a probe file to determine whether the account can write.
func (c *Client) probeShare(ctx context.Context, info ShareInfo, probeWrite bool) AccessState {
	state := AccessState{}

	if err := validateShareName(info.Name); err != nil {
		state.Err = err
		return state
	}

	timeout := c.cfg.OpTimeout
	if timeout <= 0 || timeout > 15*time.Second {
		timeout = 15 * time.Second
	}

	err := c.do(ctx, timeout, func(session *smb2.Session) error {
		mounted, err := session.Mount(uncPath(c.cfg.Host, info.Name))
		if err != nil {
			return fmt.Errorf("mounting: %w", err)
		}
		defer func() { _ = mounted.Umount() }()
		state.Mounted = true

		// Non-disk shares have no browsable file root, but a successful tree
		// connect is still share-level access. Tools such as NetExec report
		// this as READ; there is no file listing or write test to perform.
		if info.Kind != ShareDisk {
			state.Read = true
			state.WriteTested = true
			switch info.Kind {
			case ShareIPC:
				state.Note = "named-pipe share; file listing and write probing do not apply"
			case SharePrint:
				state.Note = "print queue; file listing and write probing do not apply"
			default:
				state.Note = "device share; file listing and write probing do not apply"
			}
			return nil
		}

		if _, err := mounted.ReadDir(""); err != nil {
			if IsPermission(err) {
				state.Note = "the share root cannot be listed"
			} else {
				state.Err = fmt.Errorf("listing the share root: %w", err)
				return nil
			}
		} else {
			state.Read = true
		}

		if !probeWrite {
			return nil
		}

		state.WriteTested = true
		probeName := probeFilePrefix + randomSuffix()
		file, err := mounted.OpenFile(probeName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if !IsPermission(err) {
				state.Note = fmt.Sprintf("write probe failed: %s", Describe(err))
			}
			return nil
		}

		_, writeErr := file.Write([]byte("smblens"))
		closeErr := file.Close()
		removeErr := mounted.Remove(probeName)

		switch {
		case writeErr != nil && IsPermission(writeErr):
			// Created but could not write: the directory allows file creation
			// but not data writes. Report read-only.
		case writeErr != nil:
			state.Note = fmt.Sprintf("write probe failed: %s", Describe(writeErr))
		case closeErr != nil:
			state.Note = fmt.Sprintf("closing the probe file failed: %s", Describe(closeErr))
		default:
			state.Write = true
		}

		if removeErr != nil {
			note := fmt.Sprintf("probe file %q could not be deleted", probeName)
			if state.Note == "" {
				state.Note = note
			} else {
				state.Note += "; " + note
			}
		}
		return nil
	})

	if err != nil {
		state.Err = err
		state.Denied = IsPermission(err)
		if state.Mounted {
			// Mounting succeeded; the failure came from a later step and is
			// already recorded above.
			state.Err = err
		}
	}
	return state
}

// shareKind converts an SMB share type into the model's ShareKind for display and non-disk handling.
func shareKind(t smb2.ShareType) ShareKind {
	switch t {
	case smb2.ShareTypeDiskTree:
		return ShareDisk
	case smb2.ShareTypePrintQueue:
		return SharePrint
	case smb2.ShareTypeDevice:
		return ShareDevice
	case smb2.ShareTypeIPC:
		return ShareIPC
	default:
		return ShareUnknown
	}
}

// randomSuffix returns a short random hex string for probe file names.
func randomSuffix() string {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand failing is extraordinarily unlikely; fall back to time.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}
