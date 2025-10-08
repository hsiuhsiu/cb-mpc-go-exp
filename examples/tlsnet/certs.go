package tlsnet

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GenerateCertificates writes a demo CA and per-party certificates to outputDir.
// The certificates support both server and client authentication and include
// localhost/IP SAN entries for convenience.
func GenerateCertificates(names []string, outputDir string) error {
	if len(names) < 2 {
		return fmt.Errorf("tlsnet: provide at least two party names (got %v)", names)
	}

	absDir, err := securePath(outputDir)
	if err != nil {
		return fmt.Errorf("resolve output dir: %w", err)
	}
	if err := os.MkdirAll(absDir, 0o750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	outputDir = absDir

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cb-mpc-go-demo-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}
	if err := writeCert(filepath.Join(outputDir, "rootCA.pem"), caDER); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(outputDir, "rootCA-key.pem"), caKey); err != nil {
		return err
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	for i, name := range names {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate key for %s: %w", name, err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			DNSNames:     []string{name, "localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			return fmt.Errorf("create cert for %s: %w", name, err)
		}
		if err := writeCert(filepath.Join(outputDir, fmt.Sprintf("%s-cert.pem", name)), der); err != nil {
			return err
		}
		if err := writeKey(filepath.Join(outputDir, fmt.Sprintf("%s-key.pem", name)), key); err != nil {
			return err
		}
	}

	return nil
}

func writeCert(path string, der []byte) error {
	cleanPath, err := securePath(path)
	if err != nil {
		return fmt.Errorf("sanitize cert path %s: %w", path, err)
	}
	f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- cleanPath validated by securePath
	if err != nil {
		return fmt.Errorf("open cert %s: %w", cleanPath, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return fmt.Errorf("encode cert %s: %w", cleanPath, err)
	}
	return nil
}

func writeKey(path string, key *rsa.PrivateKey) error {
	cleanPath, err := securePath(path)
	if err != nil {
		return fmt.Errorf("sanitize key path %s: %w", path, err)
	}
	f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- cleanPath validated by securePath
	if err != nil {
		return fmt.Errorf("open key %s: %w", cleanPath, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return fmt.Errorf("encode key %s: %w", cleanPath, err)
	}
	return nil
}

func securePath(path string) (string, error) {
	clean := filepath.Clean(path)
	absPath, err := filepath.Abs(clean)
	if err != nil {
		return "", err
	}
	base, err := os.Getwd()
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, absPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes working directory", path)
	}
	return absPath, nil
}
