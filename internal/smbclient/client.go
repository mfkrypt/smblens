package smbclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cloudsoda/go-smb2"
)

// Default timeouts used when Config leaves them unset.
const (
	DefaultConnectTimeout = 15 * time.Second
	DefaultOpTimeout      = 45 * time.Second
)

// Client is a single authenticated SMB session. Its methods are safe to call
// from multiple goroutines; operations are serialised because an SMB session
// carries one request stream.
type Client struct {
	cfg     Config
	session *smb2.Session
	cleanup func()

	mu     sync.Mutex
	closed bool
	lost   bool
}

// Dial connects and authenticates to the server described by cfg.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Host == "" {
		return nil, errors.New("no server address given")
	}
	if cfg.Port == 0 {
		cfg.Port = 445
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = DefaultOpTimeout
	}

	connectCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()

	// Kerberos login talks to the KDC and gokrb5 does not take a context, so
	// run initiator construction in a goroutine and stop waiting when the
	// connection deadline passes. A late result is cleaned up on arrival.
	type initResult struct {
		initiator smb2.Initiator
		cleanup   func()
		err       error
	}
	resultCh := make(chan initResult, 1)
	go func() {
		initiator, cleanup, err := cfg.initiator()
		resultCh <- initResult{initiator: initiator, cleanup: cleanup, err: err}
	}()

	var (
		initiator smb2.Initiator
		cleanup   func()
	)
	select {
	case result := <-resultCh:
		if result.err != nil {
			return nil, result.err
		}
		initiator, cleanup = result.initiator, result.cleanup
	case <-connectCtx.Done():
		go func() {
			result := <-resultCh
			if result.cleanup != nil {
				result.cleanup()
			}
		}()
		if cfg.Auth == AuthKerberos {
			return nil, fmt.Errorf("connecting to %s: Kerberos setup did not finish in time (check --kdc and --realm): %w", cfg.Address(), connectCtx.Err())
		}
		return nil, fmt.Errorf("connecting to %s: %w", cfg.Address(), connectCtx.Err())
	}

	dialer := &smb2.Dialer{Initiator: initiator}
	session, err := dialer.Dial(connectCtx, cfg.Address())
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("connecting to %s: %w", cfg.Address(), err)
	}

	return &Client{cfg: cfg, session: session, cleanup: cleanup}, nil
}

// Close logs off and releases credentials. It is safe to call more than once.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true

	var err error
	if !c.lost {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = c.session.WithContext(ctx).Logoff()
		cancel()
	}
	if c.cleanup != nil {
		c.cleanup()
		c.cleanup = nil
	}
	return err
}

// acquire takes the session lock, honouring ctx while waiting is not possible
// with a plain mutex, so the context is checked before and after locking.
func (c *Client) acquire(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrSessionClosed
	}
	if c.lost {
		c.mu.Unlock()
		return ErrConnectionLost
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return err
	}
	return nil
}

// do runs fn under the session lock with a per-operation timeout. A timeout of
// zero means the caller's context alone bounds the operation (used for
// transfers so that they can run as long as they need).
func (c *Client) do(ctx context.Context, timeout time.Duration, fn func(*smb2.Session) error) error {
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.mu.Unlock()

	opCtx, cancel := opContext(ctx, timeout)
	defer cancel()

	err := fn(c.session.WithContext(opCtx))
	if err != nil && IsConnectionLost(err) {
		c.lost = true
	}
	return err
}

// Share is a mounted share. Call Close when done with it.
type Share struct {
	client *Client
	name   string
	share  *smb2.Share
}

// Name returns the share name without the \\server\ prefix.
func (s *Share) Name() string { return s.name }

// Host returns the server hostname from the client configuration.
func (s *Share) Host() string { return s.client.cfg.Host }

// Mount connects a tree to the named share.
func (c *Client) Mount(ctx context.Context, name string) (*Share, error) {
	name = strings.TrimSpace(name)
	if err := validateShareName(name); err != nil {
		return nil, err
	}

	var mounted *smb2.Share
	err := c.do(ctx, c.cfg.OpTimeout, func(session *smb2.Session) error {
		var err error
		mounted, err = session.Mount(`\\` + c.cfg.Host + `\` + name)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("mounting %s: %w", uncPath(c.cfg.Host, name), err)
	}
	return &Share{client: c, name: name, share: mounted}, nil
}

// Close disconnects the tree. It is safe to call more than once.
func (s *Share) Close() error {
	if s == nil || s.share == nil {
		return nil
	}
	c := s.client
	if err := c.acquire(context.Background()); err != nil {
		// The session is already gone; there is nothing to unmount.
		return nil
	}
	defer c.mu.Unlock()

	err := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return s.share.WithContext(ctx).Umount()
	}()
	if err != nil && IsConnectionLost(err) {
		c.lost = true
	}
	s.share = nil
	return err
}

// do runs fn against this share under the session lock.
func (s *Share) do(ctx context.Context, timeout time.Duration, fn func(*smb2.Share) error) error {
	if s == nil || s.share == nil {
		return ErrSessionClosed
	}
	c := s.client
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.mu.Unlock()

	opCtx, cancel := opContext(ctx, timeout)
	defer cancel()

	err := fn(s.share.WithContext(opCtx))
	if err != nil && IsConnectionLost(err) {
		c.lost = true
	}
	return err
}

// opContext bounds an operation by timeout, or only by parent when timeout is
// zero.
func opContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

// validateShareName rejects names that could confuse the UNC mount path.
func validateShareName(name string) error {
	switch {
	case name == "":
		return errors.New("share name is empty")
	case name == "." || name == "..":
		return fmt.Errorf("invalid share name %q", name)
	case strings.ContainsAny(name, `/\`):
		return fmt.Errorf("invalid share name %q: it contains a path separator", name)
	}
	return nil
}

// uncPath formats \\host\share for display.
func uncPath(host, share string) string {
	return `\\` + host + `\` + share
}
