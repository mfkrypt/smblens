// Package config parses SMBLens command-line options.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mfkrypt/smblens/internal/smbclient"
)

// Defaults for the tunable options.
const (
	DefaultDepth          = 10
	DefaultOpTimeout      = smbclient.DefaultOpTimeout
	DefaultConnectTimeout = smbclient.DefaultConnectTimeout
)

// Options is the complete command-line configuration.
type Options struct {
	Config smbclient.Config

	Recursive    bool // run a recursive scan when a share is opened
	MaxDepth     int  // recursion limit for scans; 0 means unlimited
	NoWriteProbe bool // do not create probe files when testing share access
	NoColor      bool
	ShowVersion  bool
	ShowHelp     bool
}

// flagsWithValues lists every option that consumes the following argument.
// It lets the parser accept the server argument anywhere on the command line.
var flagsWithValues = map[string]bool{
	"u": true, "user": true,
	"d": true, "domain": true,
	"p": true, "password": true,
	"H": true, "hash": true,
	"a": true, "auth": true,
	"realm": true, "kdc": true, "spn": true,
	"ccache": true, "keytab": true, "krb5-conf": true, "kerberos-source": true,
	"share": true, "port": true, "timeout": true, "connect-timeout": true,
	"depth": true,
}

// Parse parses args (without the program name).
func Parse(args []string) (*Options, error) {
	opts := &Options{MaxDepth: DefaultDepth}
	cfg := &opts.Config

	var (
		target         string
		auth           string
		kerberosSource string
		port           int
		opTimeout      = DefaultOpTimeout
		connectTimeout = DefaultConnectTimeout
	)

	fs := flag.NewFlagSet("smblens", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	addString := func(short, long string, dst *string) {
		if short != "" {
			fs.StringVar(dst, short, *dst, "")
		}
		fs.StringVar(dst, long, *dst, "")
	}
	addBool := func(short, long string, dst *bool) {
		if short != "" {
			fs.BoolVar(dst, short, *dst, "")
		}
		fs.BoolVar(dst, long, *dst, "")
	}

	addString("u", "user", &cfg.Username)
	addString("d", "domain", &cfg.Domain)
	addString("p", "password", &cfg.Password)
	addString("H", "hash", &cfg.NTHash)
	addString("a", "auth", &auth)
	addString("", "realm", &cfg.Realm)
	addString("", "kdc", &cfg.KDC)
	addString("", "spn", &cfg.SPN)
	addString("", "ccache", &cfg.CCachePath)
	addString("", "keytab", &cfg.KeytabPath)
	addString("", "krb5-conf", &cfg.Krb5ConfPath)
	addString("", "kerberos-source", &kerberosSource)
	addString("", "share", &cfg.Share)
	fs.IntVar(&port, "port", 0, "")
	fs.DurationVar(&opTimeout, "timeout", DefaultOpTimeout, "")
	fs.DurationVar(&connectTimeout, "connect-timeout", DefaultConnectTimeout, "")
	addBool("r", "recursive", &opts.Recursive)
	fs.IntVar(&opts.MaxDepth, "depth", DefaultDepth, "")
	addBool("", "no-write-probe", &opts.NoWriteProbe)
	addBool("", "no-color", &opts.NoColor)
	addBool("", "version", &opts.ShowVersion)
	addBool("h", "help", &opts.ShowHelp)

	if err := fs.Parse(prioritiseFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return nil, cleanFlagError(err)
	}
	if opts.ShowHelp || opts.ShowVersion {
		return opts, nil
	}

	if rest := fs.Args(); len(rest) > 0 {
		if len(rest) > 1 {
			return nil, fmt.Errorf("expected one server, got %d arguments: %s", len(rest), strings.Join(rest, " "))
		}
		target = rest[0]
	}

	// A password on the command line is convenient but visible in process
	// listings; the environment variable is safer and is used when -p is
	// absent.
	if cfg.Password == "" {
		cfg.Password = os.Getenv("SMBLENS_PASSWORD")
	}
	if cfg.NTHash == "" {
		cfg.NTHash = os.Getenv("SMBLENS_NTHASH")
	}

	host, targetPort, share, initialPath, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}
	cfg.Host = host
	if targetPort != 0 {
		port = targetPort
	}
	cfg.Port = port
	if share != "" && cfg.Share == "" {
		cfg.Share = share
	}
	cfg.Path = initialPath
	cfg.ConnectTimeout = connectTimeout
	cfg.OpTimeout = opTimeout

	if v := strings.ToLower(strings.TrimSpace(kerberosSource)); v != "" {
		cfg.KerberosSource = smbclient.KerberosSource(v)
	}
	cfg.Auth, err = resolveAuth(auth, cfg)
	if err != nil {
		return nil, err
	}
	if err := validate(opts, port); err != nil {
		return nil, err
	}
	return opts, nil
}

// prioritiseFlags moves the positional target to the end so options may appear
// before or after it. Go's flag package stops at the first non-flag argument;
// this preprocessing keeps the command line natural.
func prioritiseFlags(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}

		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			continue // value was attached to the flag
		}
		if flagsWithValues[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

// resolveAuth picks the authentication method from --auth or from which
// credential flags were supplied.
func resolveAuth(explicit string, cfg *smbclient.Config) (smbclient.AuthMethod, error) {
	if explicit != "" {
		method := smbclient.AuthMethod(strings.ToLower(strings.TrimSpace(explicit)))
		if !method.Valid() {
			return "", fmt.Errorf("unknown auth method %q (use password, hash, or kerberos)", explicit)
		}
		return method, nil
	}
	switch {
	case cfg.NTHash != "":
		return smbclient.AuthHash, nil
	case cfg.CCachePath != "" || cfg.KeytabPath != "" || cfg.KerberosSource != "":
		return smbclient.AuthKerberos, nil
	default:
		return smbclient.AuthPassword, nil
	}
}

// validate checks option values that the flag package cannot express, such as port ranges, timeouts and credential syntax.
func validate(opts *Options, port int) error {
	cfg := &opts.Config
	if port < 0 || port > 65535 {
		return fmt.Errorf("port %d is out of range (1-65535)", port)
	}
	if opts.MaxDepth < 0 {
		return errors.New("depth cannot be negative (0 means unlimited)")
	}
	if cfg.OpTimeout <= 0 {
		return errors.New("timeout must be greater than zero")
	}
	if cfg.ConnectTimeout <= 0 {
		return errors.New("connect-timeout must be greater than zero")
	}
	if cfg.NTHash != "" {
		if _, err := smbclient.ParseNTHash(cfg.NTHash); err != nil {
			return err
		}
	}
	if cfg.KerberosSource != "" {
		switch cfg.KerberosSource {
		case smbclient.KerbPassword, smbclient.KerbCCache, smbclient.KerbKeytab:
		default:
			return fmt.Errorf("unknown Kerberos source %q", cfg.KerberosSource)
		}
	}
	return nil
}

// ParseTarget understands host, host:port, host/share, \\host\share, and
// smb://host/share/path. It returns the host, an optional port, and an
// optional share and initial path.
func ParseTarget(raw string) (host string, port int, share, initialPath string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, "", "", nil
	}

	if strings.HasPrefix(strings.ToLower(raw), "smb://") {
		raw = raw[len("smb://"):]
	}
	raw = strings.TrimPrefix(raw, `\\`)
	raw = strings.TrimPrefix(raw, "//")
	raw = strings.TrimSuffix(raw, "/")

	hostPart := raw
	rest := ""
	if i := strings.IndexAny(raw, `/\`); i >= 0 {
		hostPart = raw[:i]
		rest = raw[i+1:]
	}

	host, port, err = splitHostPort(hostPart)
	if err != nil {
		return "", 0, "", "", err
	}
	if host == "" {
		return "", 0, "", "", fmt.Errorf("invalid target %q: the server name is empty", raw)
	}

	if rest != "" {
		parts := strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == '\\' })
		if len(parts) > 0 {
			share = parts[0]
		}
		if len(parts) > 1 {
			initialPath = smbclient.JoinPath(parts[1:]...)
		}
	}
	return host, port, share, initialPath, nil
}

// splitHostPort separates a host from an optional port, supporting bracketed and bare IPv6 literals.
func splitHostPort(s string) (string, int, error) {
	if s == "" {
		return "", 0, nil
	}

	if strings.HasPrefix(s, "[") {
		// Bracketed IPv6, optionally with a port.
		if host, portStr, err := net.SplitHostPort(s); err == nil {
			p, err := strconv.Atoi(portStr)
			if err != nil || p < 1 || p > 65535 {
				return "", 0, fmt.Errorf("invalid port %q", portStr)
			}
			return host, p, nil
		}
		return strings.Trim(s, "[]"), 0, nil
	}

	if strings.Count(s, ":") == 1 {
		if host, portStr, err := net.SplitHostPort(s); err == nil {
			p, err := strconv.Atoi(portStr)
			if err != nil || p < 1 || p > 65535 {
				return "", 0, fmt.Errorf("invalid port %q", portStr)
			}
			return host, p, nil
		}
	}

	// Bare hostname or unbracketed IPv6 literal.
	return s, 0, nil
}

// cleanFlagError turns flag's "flag provided but not defined: -x" into a
// friendlier message.
func cleanFlagError(err error) error {
	msg := strings.TrimPrefix(err.Error(), "flag provided but not defined: ")
	if strings.HasPrefix(msg, "-") {
		return fmt.Errorf("unknown option %s (try --help)", msg)
	}
	return err
}

// ReadyToConnect reports whether the options contain enough information to
// connect without showing the login form.
func (o *Options) ReadyToConnect() bool {
	cfg := &o.Config
	if cfg.Host == "" {
		return false
	}
	switch cfg.Auth {
	case smbclient.AuthPassword:
		return cfg.Username != "" && cfg.Password != ""
	case smbclient.AuthHash:
		return cfg.Username != "" && cfg.NTHash != ""
	case smbclient.AuthKerberos:
		source := cfg.KerberosSource
		if source == "" {
			switch {
			case cfg.CCachePath != "":
				source = smbclient.KerbCCache
			case cfg.KeytabPath != "":
				source = smbclient.KerbKeytab
			default:
				source = smbclient.KerbPassword
			}
		}
		switch source {
		case smbclient.KerbCCache:
			return cfg.CCachePath != "" || os.Getenv("KRB5CCNAME") != ""
		case smbclient.KerbKeytab:
			return cfg.Username != "" && cfg.KeytabPath != "" && (cfg.Realm != "" || cfg.Domain != "")
		default:
			return cfg.Username != "" && cfg.Password != "" && (cfg.Realm != "" || cfg.Domain != "")
		}
	}
	return false
}

// Usage returns the command help text.
func Usage() string {
	return `SMBLens — an interactive SMB client for Active Directory share enumeration

Usage:
  smblens [options] [host[/share[/path]]]

Target:
  host                 Hostname or IP address (port 445 is assumed)
  host:445             Explicit port
  host/share           Open a share directly and skip the share list
  \\host\share\path    Windows UNC form; a path may follow the share
  smb://host/share     URL form

Authentication:
  -a, --auth METHOD    password | hash | kerberos  (default: inferred below)
  -u, --user NAME      Username. DOMAIN\user and user@domain are accepted
  -d, --domain NAME    Domain (optional; NetBIOS or DNS name; "." = local)
  -p, --password PASS  Password (or set SMBLENS_PASSWORD)
  -H, --hash HEX       NT hash for pass-the-hash (32 hex, or LM:NT)
      --realm REALM    Kerberos realm (defaults to --domain, upper-cased)
      --kdc ADDRESS    KDC host[:port] (port 88 assumed; default: krb5.conf or DNS SRV)
      --spn SPN        Service principal (default: cifs/<host>)
      --ccache PATH    Kerberos credential cache (default: $KRB5CCNAME)
      --keytab PATH    Kerberos keytab
      --kerberos-source SOURCE   password | ccache | keytab (default: inferred)
      --krb5-conf PATH Kerberos configuration (default: $KRB5_CONFIG or /etc/krb5.conf)

Behaviour:
  -r, --recursive         Scan a share recursively when it is opened
      --depth N           Recursion limit for scans (0 = unlimited, default 10)
      --no-write-probe    Skip the automatic create/write/delete probe; explicit
                          uploads, renames and deletes are still possible
      --port PORT         TCP port (default 445; target:port wins)
      --timeout DURATION  Per-operation timeout (default 45s)
      --connect-timeout DUR  TCP and authentication timeout (default 15s)
      --no-color          Disable colour
      --version           Print the version
  -h, --help              Show this help
`
}
