package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func loadFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

//********** ProtocolVersion

type TLSProtocolVersion uint16

func (pv TLSProtocolVersion) String() string {
	switch pv {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return "unknown tls protocol"
}

func (pv *TLSProtocolVersion) FromString(str string) (err error) {
	switch strings.ToUpper(str) {
	case "SSLV3":
		*pv = tls.VersionSSL30
	case "TLSV1":
		*pv = tls.VersionTLS10
	case "TLSV1.1":
		*pv = tls.VersionTLS11
	case "TLSV1.2":
		*pv = tls.VersionTLS12
	case "TLSV1.3":
		*pv = tls.VersionTLS13
	default:
		return fmt.Errorf("invalid tls protocol version: '" + str + "'")
	}
	return
}

func (pv TLSProtocolVersion) MarshalText() (data []byte, err error) {
	data = []byte(pv.String())
	return
}

func (pv *TLSProtocolVersion) UnmarshalText(data []byte) (err error) {
	return pv.FromString(string(data))
}

//********** CipherSuite

type TLSCipherSuite uint16

func (cs TLSCipherSuite) String() string {
	switch uint16(cs) {
	// TLS 1.0 - 1.2 cipher suites.
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	// TLS 1.3 cipher suites.
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	}
	return "unknown tls cipher suite"
}

func (cs *TLSCipherSuite) FromString(str string) (err error) {
	switch strings.Replace(strings.ToUpper(str), "-", "_", -1) {
	// TLS 1.0 - 1.2 cipher suites.
	case "RSA_WITH_RC4_128_SHA":
		*cs = TLSCipherSuite(tls.TLS_RSA_WITH_RC4_128_SHA)
	case "RSA_WITH_3DES_EDE_CBC_SHA":
		*cs = TLSCipherSuite(tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
	case "RSA_WITH_AES_128_CBC_SHA":
		*cs = TLSCipherSuite(tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	case "RSA_WITH_AES_256_CBC_SHA":
		*cs = TLSCipherSuite(tls.TLS_RSA_WITH_AES_256_CBC_SHA)
	case "RSA_WITH_AES_128_CBC_SHA256":
		*cs = TLSCipherSuite(tls.TLS_RSA_WITH_AES_128_CBC_SHA256)
	case "RSA_WITH_AES_128_GCM_SHA256":
		*cs = TLSCipherSuite(tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
	case "RSA_WITH_AES_256_GCM_SHA384":
		*cs = TLSCipherSuite(tls.TLS_RSA_WITH_AES_256_GCM_SHA384)
	case "ECDHE_ECDSA_WITH_RC4_128_SHA":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
	case "ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
	case "ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
	case "ECDHE_RSA_WITH_RC4_128_SHA":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA)
	case "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
	case "ECDHE_RSA_WITH_AES_128_CBC_SHA":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
	case "ECDHE_RSA_WITH_AES_256_CBC_SHA":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
	case "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
	case "ECDHE_RSA_WITH_AES_128_CBC_SHA256":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
	case "ECDHE_RSA_WITH_AES_128_GCM_SHA256":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	case "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	case "ECDHE_RSA_WITH_AES_256_GCM_SHA384":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
	case "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
	case "ECDHE_RSA_WITH_CHACHA20_POLY1305":
		fallthrough
	case "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
	case "ECDHE_ECDSA_WITH_CHACHA20_POLY1305":
		fallthrough
	case "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
		*cs = TLSCipherSuite(tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
	// TLS 1.3 cipher suites.
	case "TLS_AES_128_GCM_SHA256":
		*cs = TLSCipherSuite(tls.TLS_AES_128_GCM_SHA256)
	case "TLS_AES_256_GCM_SHA384":
		*cs = TLSCipherSuite(tls.TLS_AES_256_GCM_SHA384)
	case "TLS_CHACHA20_POLY1305_SHA256":
		*cs = TLSCipherSuite(tls.TLS_CHACHA20_POLY1305_SHA256)
	default:
		return fmt.Errorf("invalid tls cipher suite: '" + str + "'")
	}
	return
}

func (cs TLSCipherSuite) MarshalText() (data []byte, err error) {
	data = []byte(cs.String())
	return
}

func (cs *TLSCipherSuite) UnmarshalText(data []byte) (err error) {
	return cs.FromString(string(data))
}

//********** TLSCurve

type TLSCurve tls.CurveID

func (c TLSCurve) String() string {
	switch tls.CurveID(c) {
	case tls.CurveP256:
		return "secp256r1"
	case tls.CurveP384:
		return "secp384r1"
	case tls.CurveP521:
		return "secp521r1"
	case tls.X25519:
		return "x25519"
	}
	return "unknown tls echd curve"
}

func (c *TLSCurve) FromString(str string) (err error) {
	switch strings.ToLower(str) {
	case "prime256v1":
		fallthrough
	case "secp256r1":
		*c = TLSCurve(tls.CurveP256)
	case "prime384v1":
		fallthrough
	case "secp384r1":
		*c = TLSCurve(tls.CurveP384)
	case "prime521v1":
		fallthrough
	case "secp521r1":
		*c = TLSCurve(tls.CurveP521)
	case "x25519":
		*c = TLSCurve(tls.X25519)
	default:
		return fmt.Errorf("invalid tls ecdh curve: '" + str + "'")
	}
	return
}

func (c TLSCurve) MarshalText() (data []byte, err error) {
	data = []byte(c.String())
	return
}

func (c *TLSCurve) UnmarshalText(data []byte) (err error) {
	return c.FromString(string(data))
}

//********** TLSSessionTicketKey

type TLSSessionTicketKey [32]byte

func (stk TLSSessionTicketKey) String() string {
	return hex.EncodeToString([]byte(stk[:]))
}

func (stk *TLSSessionTicketKey) FromString(str string) error {
	key, err := hex.DecodeString(str)
	if err != nil {
		return fmt.Errorf("invalid tls session ticket key: %v", err)
	}
	if len(key) != len(stk) {
		return fmt.Errorf("invalid tls session ticket key length: got %d bytes, expected %d bytes", len(key), len(stk))
	}
	copy(stk[:], key)
	return nil
}

func (stk TLSSessionTicketKey) MarshalText() (data []byte, err error) {
	data = []byte(stk.String())
	return
}

func (stk *TLSSessionTicketKey) UnmarshalText(data []byte) (err error) {
	return stk.FromString(string(data))
}

//********** TLSConfig

type TLSConfig struct {
	CertFile                 string              `json:"certificate" yaml:"certificate" toml:"certificate"`
	CertData                 string              `json:"certificate-data" yaml:"certificate-data" toml:"certificate-data"`
	KeyFile                  string              `json:"certificate-key" yaml:"certificate-key" toml:"certificate-key"`
	KeyData                  string              `json:"certificate-key-data" yaml:"certificate-key-data" toml:"certificate-key-data"`
	MinVersion               TLSProtocolVersion  `json:"min-protocol-version" yaml:"min-protocol-version" toml:"min-protocol-version"`
	MaxVersion               TLSProtocolVersion  `json:"max-protocol-version" yaml:"max-protocol-version" toml:"max-protocol-version"`
	CipherSuites             []TLSCipherSuite    `json:"ciphers" yaml:"ciphers" toml:"ciphers"`
	PreferServerCipherSuites bool                `json:"prefer-server-ciphers" yaml:"prefer-server-ciphers" toml:"prefer-server-ciphers"`
	CurvePreferences         []TLSCurve          `json:"ecdh-curves" yaml:"ecdh-curves" toml:"ecdh-curves"`
	SessionTickets           bool                `json:"session-tickets" yaml:"session-tickets" toml:"session-tickets"`
	SessionTicketKey         TLSSessionTicketKey `json:"session-ticket-key" yaml:"session-ticket-key" toml:"session-ticket-key"`
	InsecureSkipVerify       bool                `json:"insecure-skip-verify" yaml:"insecure-skip-verify" toml:"insecure-skip-verify"`
	CACertificatesFile       []string            `json:"ca-certificates" yaml:"ca-certificates" toml:"ca-certificates"`
	CACertificatesData       string              `json:"ca-certificates-data" yaml:"ca-certificates-data" toml:"ca-certificates-data`
	ServerName               string              `json:"server-name" yaml:"server-name" toml:"server-name`
}

func (t TLSConfig) ToGoTLSConfig() (*tls.Config, error) {
	if t.CertFile != "" && t.CertData != "" {
		return nil, fmt.Errorf("certifcate and certificate-data are mutual exclusive")
	}
	if t.KeyFile != "" && t.KeyData != "" {
		return nil, fmt.Errorf("certifcate-key and certificate-key-data are mutual exclusive")
	}

	cfg := &tls.Config{}
	if t.CertFile != "" && t.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate and or key: %s", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if t.CertData != "" && t.KeyData != "" {
		cert, err := tls.X509KeyPair([]byte(t.CertData), []byte(t.KeyData))
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate-data and or key-data: %s", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	cfg.MinVersion = uint16(t.MinVersion)
	cfg.MaxVersion = uint16(t.MaxVersion)
	for _, cs := range t.CipherSuites {
		cfg.CipherSuites = append(cfg.CipherSuites, uint16(cs))
	}
	cfg.PreferServerCipherSuites = t.PreferServerCipherSuites
	for _, cp := range t.CurvePreferences {
		cfg.CurvePreferences = append(cfg.CurvePreferences, tls.CurveID(cp))
	}
	cfg.SessionTicketsDisabled = !t.SessionTickets
	cfg.SessionTicketKey = [32]byte(t.SessionTicketKey)
	cfg.InsecureSkipVerify = t.InsecureSkipVerify
	for _, cert := range t.CACertificatesFile {
		cfg.RootCAs = x509.NewCertPool()
		pemData, err := loadFile(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to load ca-certificate: %v", err)
		}

		ok := cfg.RootCAs.AppendCertsFromPEM(pemData)
		if !ok {
			return nil, fmt.Errorf("no ca-certificates found in file '%s'", cert)
		}
	}
	if t.CACertificatesData != "" {
		if cfg.RootCAs == nil {
			cfg.RootCAs = x509.NewCertPool()
		}
		if ok := cfg.RootCAs.AppendCertsFromPEM([]byte(t.CACertificatesData)); !ok {
			return nil, fmt.Errorf("no certificates found in ca-certificates-data")
		}
	}
	cfg.ServerName = t.ServerName

	return cfg, nil
}
