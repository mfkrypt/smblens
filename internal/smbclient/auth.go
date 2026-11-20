package smbclient

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudsoda/go-smb2"
)

// initiator builds the SMB authentication initiator for cfg. The returned
// cleanup function releases any credentials held by the initiator.
func (c *Config) initiator() (smb2.Initiator, func(), error) {
	switch c.Auth {
	case "", AuthPassword, AuthHash:
		initiator, err := c.ntlmInitiator()
		return initiator, func() {}, err
	case AuthKerberos:
		return c.kerberosInitiator()
	default:
		return nil, nil, fmt.Errorf("unsupported authentication method %q", c.Auth)
	}
}

// ntlmInitiator builds an NTLMv2 initiator from either a password or an NT hash.
func (c *Config) ntlmInitiator() (*smb2.NTLMInitiator, error) {
	user, domain := SplitIdentity(c.Username, c.Domain)
	if user == "" {
		return nil, errors.New("a username is required")
	}

	initiator := &smb2.NTLMInitiator{
		User:        user,
		Domain:      domain,
		Workstation: workstationName(),
	}

	switch c.Auth {
	case AuthHash:
		hash, err := ParseNTHash(c.NTHash)
		if err != nil {
			return nil, err
		}
		initiator.Hash = hash
	default:
		if c.Password == "" {
			return nil, errors.New("a password is required")
		}
		initiator.Password = c.Password
	}

	return initiator, nil
}

// SplitIdentity separates a username into account and domain. It accepts
// DOMAIN\user, user@domain, and separate --user / --domain values. An explicit
// domain embedded in the username wins over domain.
func SplitIdentity(user, domain string) (account, netbiosDomain string) {
	user = strings.TrimSpace(user)
	domain = strings.TrimSpace(domain)

	if i := strings.IndexByte(user, '\\'); i >= 0 {
		if d := strings.TrimSpace(user[:i]); d != "" {
			domain = d
		}
		user = strings.TrimSpace(user[i+1:])
	} else if i := strings.LastIndex(user, "@"); i > 0 {
		if d := strings.TrimSpace(user[i+1:]); d != "" {
			domain = d
		}
		user = strings.TrimSpace(user[:i])
	}

	if domain == "" {
		domain = "."
	}
	return user, domain
}

// ParseNTHash parses an NT hash for pass-the-hash authentication. It accepts a
// bare 32-character hex string, a 0x-prefixed string, or an LM:NT pair as
// printed by common credential-dumping tools (the LM half is ignored).
func ParseNTHash(s string) ([]byte, error) {
	original := s
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")

	if len(s) != 32 {
		return nil, fmt.Errorf("NT hash must be 32 hexadecimal characters (got %d in %q)", len(s), original)
	}
	hash, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("NT hash is not valid hexadecimal: %w", err)
	}
	return hash, nil
}

// workstationName returns a NetBIOS-safe local hostname for the NTLM
// workstation field.
func workstationName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "SMBLENS"
	}
	host = strings.ToUpper(host)
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	if len(host) > 15 {
		host = host[:15]
	}
	return host
}
