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

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// KeyGenerator generates asymmetric key pairs.
// This is the primary interface for key material creation.
type KeyGenerator interface {
	// Generate creates a new key pair according to the given options.
	// Callers MUST call KeyPair.Wipe() when the key material is no longer needed.
	Generate(opts GenerateOptions) (*KeyPair, error)
}

// GenerateOptions specifies parameters for key generation.
type GenerateOptions struct {
	// Algorithm: "EC" or "RSA"
	Algorithm string
	// Params: algorithm-specific parameters (e.g., "curve": "P-256", "keySize": "3072")
	Params map[string]string
	// AllowLegacyKeySize permits RSA < 3072 (BSI TR-02102-1 G-1)
	AllowLegacyKeySize bool
}

// KeyPair holds generated key material.
// SECURITY: Call Wipe() when done to zero out private key material from memory.
// [SEC:I-2]
type KeyPair struct {
	// KeyID is a unique identifier for this key pair.
	// Format: {alg}-{param}-{YYYYMMDD}-{6hex}
	KeyID string

	// PrivateKey is the generated private key (crypto.PrivateKey).
	PrivateKey crypto.PrivateKey

	// PublicKey is the generated public key (crypto.PublicKey).
	PublicKey crypto.PublicKey

	// Algorithm is the algorithm used (EC or RSA).
	Algorithm string

	// CreatedAt is the creation timestamp.
	CreatedAt time.Time

	// rawPrivateBytes holds the DER encoding for Wipe().
	rawPrivateBytes []byte
}

// Wipe zeroes out private key material from memory.
// [SEC:I-2] This MUST be called via defer after every Generate().
func (kp *KeyPair) Wipe() {
	if kp == nil {
		return
	}

	// Zero raw DER bytes
	for i := range kp.rawPrivateBytes {
		kp.rawPrivateBytes[i] = 0
	}
	kp.rawPrivateBytes = nil

	// Zero key struct internals where possible
	switch k := kp.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		if k != nil && k.D != nil {
			k.D.SetInt64(0)
		}
	case *rsa.PrivateKey:
		if k != nil && k.D != nil {
			k.D.SetInt64(0)
		}
		for i := range k.Primes {
			if k.Primes[i] != nil {
				k.Primes[i].SetInt64(0)
			}
		}
	}

	kp.PrivateKey = nil
	kp.PublicKey = nil
}

// defaultGenerator is the standard KeyGenerator implementation
// using exclusively Go standard library crypto.
type defaultGenerator struct{}

// NewKeyGenerator creates a new KeyGenerator.
func NewKeyGenerator() KeyGenerator {
	return &defaultGenerator{}
}

// Generate creates a new key pair.
// It validates the key spec using the shared ValidateKeySpec function (DRY).
func (g *defaultGenerator) Generate(opts GenerateOptions) (*KeyPair, error) {
	// DRY: Use shared validation from pkg/crypto/validate.go
	if _, err := ValidateKeySpec(opts.Algorithm, opts.Params, opts.AllowLegacyKeySize); err != nil {
		return nil, fmt.Errorf("key generation validation failed: %w", err)
	}

	switch opts.Algorithm {
	case AlgorithmEC:
		return g.generateEC(opts)
	case AlgorithmRSA:
		return g.generateRSA(opts)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", opts.Algorithm)
	}
}

func (g *defaultGenerator) generateEC(opts GenerateOptions) (*KeyPair, error) {
	curveName := opts.Params["curve"]
	curve, err := parseCurve(curveName)
	if err != nil {
		return nil, fmt.Errorf("EC key generation failed: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey failed: %w", err)
	}

	rawBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key for wipe tracking: %w", err)
	}

	keyID, err := generateKeyID("ec", curveName)
	if err != nil {
		return nil, fmt.Errorf("key ID generation failed: %w", err)
	}

	return &KeyPair{
		KeyID:           keyID,
		PrivateKey:      privateKey,
		PublicKey:       &privateKey.PublicKey,
		Algorithm:       AlgorithmEC,
		CreatedAt:       time.Now(),
		rawPrivateBytes: rawBytes,
	}, nil
}

func (g *defaultGenerator) generateRSA(opts GenerateOptions) (*KeyPair, error) {
	keySizeStr := opts.Params["keySize"]
	keySize, err := strconv.Atoi(keySizeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA keySize %q: %w", keySizeStr, err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("rsa.GenerateKey failed: %w", err)
	}

	rawBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	keyID, err := generateKeyID("rsa", keySizeStr)
	if err != nil {
		return nil, fmt.Errorf("key ID generation failed: %w", err)
	}

	return &KeyPair{
		KeyID:           keyID,
		PrivateKey:      privateKey,
		PublicKey:       &privateKey.PublicKey,
		Algorithm:       AlgorithmRSA,
		CreatedAt:       time.Now(),
		rawPrivateBytes: rawBytes,
	}, nil
}

// parseCurve maps curve name strings to elliptic.Curve.
func parseCurve(name string) (elliptic.Curve, error) {
	switch name {
	case CurveP256:
		return elliptic.P256(), nil
	case CurveP384:
		return elliptic.P384(), nil
	case CurveP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

// generateKeyID creates a unique key identifier.
// Format: {alg}-{param}-{YYYYMMDD}-{6hex}
func generateKeyID(alg, param string) (string, error) {
	randomBytes := make([]byte, 3) // 6 hex chars
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generating random bytes for key ID: %w", err)
	}

	date := time.Now().Format("20060102")
	return fmt.Sprintf("%s-%s-%s-%s", alg, param, date, hex.EncodeToString(randomBytes)), nil
}
