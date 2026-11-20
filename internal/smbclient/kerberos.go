package smbclient

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cloudsoda/go-smb2"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// kerberosInitiator builds a Kerberos (GSSAPI/SPNEGO) initiator for SMB.
//
// Exactly one credential source is used, in this order: an explicit
// KerberosSource, a credential cache (--ccache or $KRB5CCNAME), a keytab
// (--keytab), or a password.
func (c *Config) kerberosInitiator() (smb2.Initiator, func(), error) {
	host := strings.TrimSpace(c.Host)
	if host == "" {
		return nil, nil, errors.New("Kerberos needs a server hostname")
	}
	if net.ParseIP(host) != nil && strings.TrimSpace(c.SPN) == "" {
		return nil, nil, fmt.Errorf("Kerberos requires the server's DNS name, not the IP address %q (the service ticket is issued for cifs/<hostname>); pass --spn to use a name with an IP address", host)
	}

	source := c.kerberosSource()

	cachePath := c.ccachePath()
	var ccache *credentials.CCache
	if source == KerbCCache {
		if cachePath == "" {
			return nil, nil, errors.New("Kerberos ccache source selected, but no credential cache was given (use --ccache or $KRB5CCNAME)")
		}
		var err error
		ccache, err = credentials.LoadCCache(cachePath)
		if err != nil {
			return nil, nil, fmt.Errorf("loading Kerberos credential cache %q: %w", cachePath, err)
		}
	}

	user, identityDomain := SplitIdentity(c.Username, c.Domain)
	realm := c.kerberosRealm(ccache)
	if realm == "" && identityDomain != "" && identityDomain != "." {
		// user@REALM carries its realm in the username.
		realm = strings.ToUpper(strings.TrimSuffix(identityDomain, "."))
	}

	if source != KerbCCache && user == "" {
		return nil, nil, errors.New("a username is required for Kerberos password or keytab authentication")
	}
	if source != KerbCCache && realm == "" {
		return nil, nil, errors.New("a Kerberos realm is required: pass --realm (for Active Directory this is usually the DNS domain in upper case, e.g. CORP.EXAMPLE.COM)")
	}

	cfg, err := loadKrb5Config(c, realm)
	if err != nil {
		return nil, nil, err
	}

	var krb *krbclient.Client
	switch source {
	case KerbCCache:
		krb, err = krbclient.NewFromCCache(ccache, cfg)
	case KerbKeytab:
		if c.KeytabPath == "" {
			return nil, nil, errors.New("Kerberos keytab source selected, but no keytab path was given (use --keytab)")
		}
		kt, kerr := keytab.Load(c.KeytabPath)
		if kerr != nil {
			return nil, nil, fmt.Errorf("loading Kerberos keytab %q: %w", c.KeytabPath, kerr)
		}
		krb = krbclient.NewWithKeytab(user, realm, kt, cfg, krbclient.DisablePAFXFAST(true))
	default:
		if c.Password == "" {
			return nil, nil, errors.New("a password is required for Kerberos password authentication")
		}
		krb = krbclient.NewWithPassword(user, realm, c.Password, cfg, krbclient.DisablePAFXFAST(true))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("Kerberos client setup failed: %w", err)
	}

	// Login validates the credentials (or an unexpired ccache session) against
	// the KDC before the SMB session is attempted.
	if err := krb.Login(); err != nil {
		krb.Destroy()
		return nil, nil, fmt.Errorf("Kerberos login failed: %w", err)
	}

	spn := strings.TrimSpace(c.SPN)
	if spn == "" {
		spn = "cifs/" + host
	}

	initiator := &smb2.Krb5Initiator{
		Client:    krb,
		TargetSPN: spn,
	}
	return initiator, krb.Destroy, nil
}

// kerberosSource resolves which credential source to use.
func (c *Config) kerberosSource() KerberosSource {
	if c.KerberosSource != "" {
		return c.KerberosSource
	}
	if c.CCachePath != "" || os.Getenv("KRB5CCNAME") != "" {
		return KerbCCache
	}
	if c.KeytabPath != "" {
		return KerbKeytab
	}
	return KerbPassword
}

// ccachePath returns the credential-cache file path, expanding the FILE: form
// of KRB5CCNAME.
func (c *Config) ccachePath() string {
	p := strings.TrimSpace(c.CCachePath)
	if p == "" {
		p = strings.TrimSpace(os.Getenv("KRB5CCNAME"))
	}
	p = strings.TrimPrefix(p, "FILE:")
	return p
}

// kerberosRealm determines the realm from --realm, --domain, or the principal
// inside a credential cache.
func (c *Config) kerberosRealm(ccache *credentials.CCache) string {
	realm := strings.TrimSpace(c.Realm)
	if realm == "" {
		domain := strings.TrimSpace(c.Domain)
		if domain != "" && domain != "." {
			realm = domain
		}
	}
	if realm == "" && ccache != nil {
		realm = ccache.DefaultPrincipal.Realm
	}
	return strings.ToUpper(strings.TrimSuffix(realm, "."))
}

// loadKrb5Config loads krb5.conf if one is available, otherwise it builds a
// minimal configuration. DNS SRV discovery is enabled when no KDC is supplied.
func loadKrb5Config(c *Config, realm string) (*krbconfig.Config, error) {
	path := strings.TrimSpace(c.Krb5ConfPath)
	explicit := path != ""
	if path == "" {
		path = strings.TrimSpace(os.Getenv("KRB5_CONFIG"))
		explicit = path != ""
	}
	if path == "" {
		if _, err := os.Stat("/etc/krb5.conf"); err == nil {
			path = "/etc/krb5.conf"
		}
	}

	var cfg *krbconfig.Config
	if path != "" {
		var err error
		cfg, err = krbconfig.Load(path)
		if err != nil {
			if explicit {
				return nil, fmt.Errorf("reading Kerberos configuration %q: %w", path, err)
			}
			return nil, fmt.Errorf("reading %q: %w (use --krb5-conf to choose another file)", path, err)
		}
		if realm != "" {
			cfg.LibDefaults.DefaultRealm = realm
		}
	} else {
		if realm == "" {
			return nil, errors.New("no krb5.conf found and no realm given: pass --realm and either --kdc or a DNS domain that publishes KDC SRV records")
		}
		cfg = krbconfig.New()
		cfg.LibDefaults.DefaultRealm = realm
	}

	if kdc := strings.TrimSpace(c.KDC); kdc != "" {
		setRealmKDC(cfg, realm, kdc)
	} else {
		// gokrb5 consults configured KDCs first and only falls back to DNS
		// when this is enabled.
		cfg.LibDefaults.DNSLookupKDC = true
	}

	return cfg, nil
}

// setRealmKDC pins the KDC for realm, replacing any KDC list already present.
func setRealmKDC(cfg *krbconfig.Config, realm, kdc string) {
	kdc = normalizeKDCAddress(kdc)
	target := realm
	if target == "" {
		target = cfg.LibDefaults.DefaultRealm
	}
	for i := range cfg.Realms {
		if cfg.Realms[i].Realm == target {
			cfg.Realms[i].KDC = []string{kdc}
			return
		}
	}
	cfg.Realms = append(cfg.Realms, krbconfig.Realm{
		Realm:         target,
		KDC:           []string{kdc},
		DefaultDomain: strings.ToLower(target),
	})
}

// normalizeKDCAddress adds the default Kerberos port (88) when the address
// does not name one. gokrb5's krb5.conf parser does this for file entries but
// a KDC supplied programmatically must be complete.
func normalizeKDCAddress(kdc string) string {
	kdc = strings.TrimSpace(kdc)
	if kdc == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(kdc); err == nil {
		return kdc
	}
	if strings.HasPrefix(kdc, "[") && strings.HasSuffix(kdc, "]") {
		return kdc + ":88"
	}
	return net.JoinHostPort(kdc, "88")
}
