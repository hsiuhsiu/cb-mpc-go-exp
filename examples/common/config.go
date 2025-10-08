package common

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PartyConfig describes a single party in a cluster.
type PartyConfig struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
}

// ClusterConfig describes the full cluster topology and TLS certificates.
type ClusterConfig struct {
	CACert  string        `json:"ca_cert"`
	Parties []PartyConfig `json:"parties"`
}

// LoadConfig reads and parses a cluster configuration JSON file.
func LoadConfig(path string) (*ClusterConfig, error) {
	absPath, err := SecurePath(path)
	if err != nil {
		return nil, fmt.Errorf("secure path: %w", err)
	}
	data, err := os.ReadFile(absPath) // #nosec G304 -- absPath validated by SecurePath
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var cfg ClusterConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal JSON: %w", err)
	}
	if len(cfg.Parties) < 2 {
		return nil, errors.New("cluster must contain at least two parties")
	}
	return &cfg, nil
}

// LoadCertPool loads a PEM-encoded CA certificate pool from the given path.
func LoadCertPool(path string) (*x509.CertPool, error) {
	absPath, err := SecurePath(path)
	if err != nil {
		return nil, fmt.Errorf("secure path: %w", err)
	}
	pemData, err := os.ReadFile(absPath) // #nosec G304 -- absPath validated by SecurePath
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("failed to parse CA certificate")
	}
	return pool, nil
}

// LoadKeyPair loads a TLS certificate and private key from the given paths.
func LoadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}
	return cert, nil
}

// SecurePath validates that a file path doesn't escape the working directory.
// This prevents path traversal attacks when loading user-specified config files.
func SecurePath(path string) (string, error) {
	clean := filepath.Clean(path)
	absPath, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("absolute path: %w", err)
	}
	base, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	rel, err := filepath.Rel(base, absPath)
	if err != nil {
		return "", fmt.Errorf("relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes working directory", path)
	}
	return absPath, nil
}
