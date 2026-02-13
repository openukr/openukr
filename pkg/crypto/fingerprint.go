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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// FingerprintPrefix is the canonical prefix for fingerprints.
// This format is FIXED and must NEVER change (API versioning invariant).
const FingerprintPrefix = "SHA256:"

// ComputeFingerprint computes a deterministic fingerprint for a public key.
// Format: "SHA256:{base64url(SHA-256(DER(pubkey)))}"
//
// This is used for integrity verification: the controller stores the fingerprint
// in the CRD status and verifies it against the Secret content on every reconcile.
// [SEC:T-1]
func ComputeFingerprint(pubKey crypto.PublicKey) (string, error) {
	if pubKey == nil {
		return "", fmt.Errorf("cannot compute fingerprint: public key is nil")
	}

	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key to DER: %w", err)
	}

	hash := sha256.Sum256(derBytes)
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])

	return FingerprintPrefix + encoded, nil
}
