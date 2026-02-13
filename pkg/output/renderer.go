/*
Copyright 2026 openUKR Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package output

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/openukr/openukr/pkg/crypto"
)

// Format constants
const (
	FormatSplitPEM  = "split-pem"
	FormatSinglePEM = "single-pem"
	FormatJKS       = "jks"
)

// RenderOptions specifies parameters for rendering the key output.
type RenderOptions struct {
	// Format is the output format (split-pem, single-pem, jks).
	Format string

	// Password is used for JKS encryption.
	// If empty, a default password might be used or error returned.
	Password string

	// Alias is the alias for the key in JKS.
	// Defaults to "openukr-key" if empty.
	Alias string
}

// FormatRenderer converts a KeyPair into a map of files (bytes) ready for Secret storage.
type FormatRenderer interface {
	Render(kp *crypto.KeyPair, opts RenderOptions) (map[string][]byte, error)
}

// NewRenderer creates a new FormatRenderer.
func NewRenderer() FormatRenderer {
	return &defaultRenderer{}
}

type defaultRenderer struct{}

func (r *defaultRenderer) Render(kp *crypto.KeyPair, opts RenderOptions) (map[string][]byte, error) {
	if kp == nil {
		return nil, fmt.Errorf("cannot render nil KeyPair")
	}

	// Always encode to PEM first as intermediate format
	encoder, err := crypto.NewKeyEncoder("PEM")
	if err != nil {
		return nil, fmt.Errorf("failed to create PEM encoder: %w", err)
	}

	privPEM, err := encoder.EncodePrivate(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	pubPEM, err := encoder.EncodePublic(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	switch opts.Format {
	case FormatSplitPEM:
		return map[string][]byte{
			"tls.key":    privPEM,
			"tls.crt":    pubPEM, // Using .crt for consistency, though it's a raw public key
			"public.pem": pubPEM,
		}, nil

	case FormatSinglePEM:
		// Concatenate: Private + Public
		// Commonly used for haproxy or similar which expect one file
		combined := append(privPEM, pubPEM...)
		return map[string][]byte{
			"keypair.pem": combined,
		}, nil

	case FormatJKS:
		return r.renderJKS(kp, opts)

	default:
		return nil, fmt.Errorf("unsupported output format: %s", opts.Format)
	}
}

// renderJKS creates a Java KeyStore containing the key pair.
// Since JKS requires a certificate chain, we generate a self-signed certificate
// on the fly wrapping the public key. This certificate is valid for 100 years
// as it is only a container for the key material.
func (r *defaultRenderer) renderJKS(kp *crypto.KeyPair, opts RenderOptions) (map[string][]byte, error) {
	if opts.Password == "" {
		return nil, fmt.Errorf("password is required for JKS format")
	}

	alias := opts.Alias
	if alias == "" {
		alias = "openukr-key"
	}

	// 1. Generate self-signed certificate
	certBytes, err := generateSelfSignedCert(kp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate self-signed cert for JKS: %w", err)
	}

	// 2. Create JKS
	ks := keystore.New()

	// 3. Add Private Key Entry
	// JKS requires the private key (PKCS8) + certificate chain
	privKeyData, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key for JKS: %w", err)
	}

	entry := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   privKeyData,
		CertificateChain: []keystore.Certificate{
			{
				Type:    "X.509",
				Content: certBytes,
			},
		},
	}

	if err := ks.SetPrivateKeyEntry(alias, entry, []byte(opts.Password)); err != nil {
		return nil, fmt.Errorf("failed to set private key entry in JKS: %w", err)
	}

	// 4. Store JKS
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(opts.Password)); err != nil {
		return nil, fmt.Errorf("failed to store JKS: %w", err)
	}

	return map[string][]byte{
		"keystore.jks": buf.Bytes(),
	}, nil
}

// generateSelfSignedCert creates a minimal self-signed certificate for the given KeyPair.
func generateSelfSignedCert(kp *crypto.KeyPair) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "openUKR Generated Key",
			Organization: []string{"openUKR"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(100 * 365 * 24 * time.Hour), // 100 years

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return certBytes, nil
}
