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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
)

// KeyEncoder encodes key material into the specified format.
type KeyEncoder interface {
	// EncodePrivate encodes a private key.
	EncodePrivate(key crypto.PrivateKey) ([]byte, error)
	// EncodePublic encodes a public key.
	EncodePublic(key crypto.PublicKey) ([]byte, error)
}

// NewKeyEncoder creates a KeyEncoder for the given encoding format.
func NewKeyEncoder(encoding string) (KeyEncoder, error) {
	switch encoding {
	case "PEM":
		return &pemEncoder{}, nil
	case "DER":
		return &derEncoder{}, nil
	case "JWK":
		return &jwkEncoder{}, nil
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// --- PEM Encoder ---

type pemEncoder struct{}

func (e *pemEncoder) EncodePrivate(key crypto.PrivateKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key to PKCS8: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

func (e *pemEncoder) EncodePublic(key crypto.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal public key to PKIX: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

// --- DER Encoder ---

type derEncoder struct{}

func (e *derEncoder) EncodePrivate(key crypto.PrivateKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key to PKCS8 DER: %w", err)
	}
	return derBytes, nil
}

func (e *derEncoder) EncodePublic(key crypto.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal public key to PKIX DER: %w", err)
	}
	return derBytes, nil
}

// --- JWK Encoder ---

type jwkEncoder struct{}

// jwk represents a JSON Web Key (RFC 7517).
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid,omitempty"`

	// RSA fields
	N *string `json:"n,omitempty"`
	E *string `json:"e,omitempty"`
	D *string `json:"d,omitempty"`
	P *string `json:"p,omitempty"`
	Q *string `json:"q,omitempty"`

	// EC fields
	Crv *string `json:"crv,omitempty"`
	X   *string `json:"x,omitempty"`
	Y   *string `json:"y,omitempty"`
	// EC private: D reused
}

func (e *jwkEncoder) EncodePrivate(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return encodeECPrivateJWK(k)
	case *rsa.PrivateKey:
		return encodeRSAPrivateJWK(k)
	default:
		return nil, fmt.Errorf("unsupported key type for JWK: %T", key)
	}
}

func (e *jwkEncoder) EncodePublic(key crypto.PublicKey) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return encodeECPublicJWK(k)
	case *rsa.PublicKey:
		return encodeRSAPublicJWK(k)
	default:
		return nil, fmt.Errorf("unsupported key type for JWK: %T", key)
	}
}

func encodeECPublicJWK(pub *ecdsa.PublicKey) ([]byte, error) {
	crv := curveName(pub.Curve)
	if crv == "" {
		return nil, fmt.Errorf("unsupported EC curve for JWK")
	}

	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := base64Url(padLeft(pub.X.Bytes(), byteLen))
	y := base64Url(padLeft(pub.Y.Bytes(), byteLen))

	j := jwk{
		Kty: "EC",
		Use: "sig",
		Crv: &crv,
		X:   &x,
		Y:   &y,
	}
	return json.Marshal(j)
}

func encodeECPrivateJWK(priv *ecdsa.PrivateKey) ([]byte, error) {
	crv := curveName(priv.Curve)
	if crv == "" {
		return nil, fmt.Errorf("unsupported EC curve for JWK")
	}

	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	x := base64Url(padLeft(priv.X.Bytes(), byteLen))
	y := base64Url(padLeft(priv.Y.Bytes(), byteLen))
	d := base64Url(padLeft(priv.D.Bytes(), byteLen))

	j := jwk{
		Kty: "EC",
		Use: "sig",
		Crv: &crv,
		X:   &x,
		Y:   &y,
		D:   &d,
	}
	return json.Marshal(j)
}

func encodeRSAPublicJWK(pub *rsa.PublicKey) ([]byte, error) {
	n := base64Url(pub.N.Bytes())
	e := base64Url(big.NewInt(int64(pub.E)).Bytes())

	j := jwk{
		Kty: "RSA",
		Use: "sig",
		N:   &n,
		E:   &e,
	}
	return json.Marshal(j)
}

func encodeRSAPrivateJWK(priv *rsa.PrivateKey) ([]byte, error) {
	n := base64Url(priv.N.Bytes())
	e := base64Url(big.NewInt(int64(priv.E)).Bytes())
	d := base64Url(priv.D.Bytes())

	j := jwk{
		Kty: "RSA",
		Use: "sig",
		N:   &n,
		E:   &e,
		D:   &d,
	}

	if len(priv.Primes) >= 2 {
		p := base64Url(priv.Primes[0].Bytes())
		q := base64Url(priv.Primes[1].Bytes())
		j.P = &p
		j.Q = &q
	}

	return json.Marshal(j)
}

func curveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return ""
	}
}

func base64Url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func padLeft(data []byte, size int) []byte {
	if len(data) >= size {
		return data
	}
	pad := make([]byte, size)
	copy(pad[size-len(data):], data)
	return pad
}
