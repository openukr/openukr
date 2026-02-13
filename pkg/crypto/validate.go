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

// Package crypto provides cryptographic primitives for key generation,
// encoding, fingerprinting, and validation. All cryptographic operations
// use exclusively the Go standard library — no external dependencies.
package crypto

import (
	"fmt"
	"strconv"
)

// Supported algorithms.
const (
	AlgorithmEC  = "EC"
	AlgorithmRSA = "RSA"
)

// Supported EC curves.
const (
	CurveP256 = "P-256"
	CurveP384 = "P-384"
	CurveP521 = "P-521"
)

// RSA key size thresholds.
const (
	// RSAMinKeySize is the absolute minimum accepted key size.
	RSAMinKeySize = 2048

	// RSARecommendedMinKeySize is the minimum per BSI TR-02102-1 (2025+).
	// Keys below this require AllowLegacyKeySize=true.
	// [COMP:G-1]
	RSARecommendedMinKeySize = 3072
)

// validCurves is the set of accepted NIST curves.
var validCurves = map[string]bool{
	CurveP256: true,
	CurveP384: true,
	CurveP521: true,
}

// validRSAKeySizes is the set of accepted RSA key sizes.
var validRSAKeySizes = map[int]bool{
	2048: true,
	3072: true,
	4096: true,
}

// ValidateKeySpec validates the cryptographic parameters for key generation.
// This is the single source of truth for algorithm validation — used by both
// the admission webhook and the key generator.
//
// [COMP:G-1]: RSA < 3072 requires allowLegacy=true.
func ValidateKeySpec(algorithm string, params map[string]string, allowLegacy bool) (warnings []string, err error) {
	switch algorithm {
	case AlgorithmEC:
		return validateEC(params)
	case AlgorithmRSA:
		return validateRSA(params, allowLegacy)
	default:
		return nil, fmt.Errorf("unsupported algorithm %q, must be one of: EC, RSA", algorithm)
	}
}

func validateEC(params map[string]string) ([]string, error) {
	curve, ok := params["curve"]
	if !ok || curve == "" {
		return nil, fmt.Errorf("EC algorithm requires 'curve' parameter")
	}

	if !validCurves[curve] {
		return nil, fmt.Errorf("unsupported EC curve %q, must be one of: P-256, P-384, P-521", curve)
	}

	return nil, nil
}

func validateRSA(params map[string]string, allowLegacy bool) ([]string, error) {
	keySizeStr, ok := params["keySize"]
	if !ok || keySizeStr == "" {
		return nil, fmt.Errorf("RSA algorithm requires 'keySize' parameter")
	}

	keySize, err := strconv.Atoi(keySizeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA keySize %q: %w", keySizeStr, err)
	}

	if !validRSAKeySizes[keySize] {
		return nil, fmt.Errorf("unsupported RSA keySize %d, must be one of: 2048, 3072, 4096", keySize)
	}

	if keySize < RSAMinKeySize {
		return nil, fmt.Errorf("RSA keySize %d is below absolute minimum %d", keySize, RSAMinKeySize)
	}

	// [COMP:G-1] BSI TR-02102-1: RSA < 3072 deprecated since 2025
	if keySize < RSARecommendedMinKeySize {
		if !allowLegacy {
			return nil, fmt.Errorf(
				"RSA keySize %d is deprecated per BSI TR-02102-1 (2025): "+
					"set allowLegacyKeySize=true to override, or use >= %d",
				keySize, RSARecommendedMinKeySize,
			)
		}
		return []string{
			fmt.Sprintf(
				"RSA keySize %d is deprecated per BSI TR-02102-1 (2025). "+
					"Migrate to >= %d or EC P-256.",
				keySize, RSARecommendedMinKeySize,
			),
		}, nil
	}

	return nil, nil
}
