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

// Package validation provides shared validation functions used by both
// the admission webhook and the controller reconciler. This ensures DRY
// compliance — validation logic exists in exactly one place.
package validation

import (
	"fmt"
	"time"
)

// MinGracePeriod is the minimum allowed grace period per NIST SP 800-57.
// [COMP:G-4]
const MinGracePeriod = 5 * time.Minute

// MinIntervalToGraceRatio is the minimum ratio of interval to grace period.
const MinIntervalToGraceRatio = 3

// ValidateNamespaceMatch ensures the serviceAccountRef namespace matches
// the object namespace. This prevents cross-namespace key requests.
// [SEC:S-1]
func ValidateNamespaceMatch(objectNamespace, specNamespace string) error {
	if objectNamespace != specNamespace {
		return fmt.Errorf(
			"serviceAccountRef.namespace %q must match KeyProfile namespace %q",
			specNamespace, objectNamespace,
		)
	}
	return nil
}

// ValidateRotationPolicy validates the rotation interval and grace period.
// Rules:
//   - GracePeriod must be >= MinGracePeriod (5m) [COMP:G-4]
//   - Interval must be >= MinIntervalToGraceRatio × GracePeriod
func ValidateRotationPolicy(interval, gracePeriod time.Duration) error {
	if gracePeriod < MinGracePeriod {
		return fmt.Errorf(
			"gracePeriod %s is below minimum %s (NIST SP 800-57)",
			gracePeriod, MinGracePeriod,
		)
	}

	minInterval := time.Duration(MinIntervalToGraceRatio) * gracePeriod
	if interval < minInterval {
		return fmt.Errorf(
			"interval %s must be at least %d× gracePeriod (%s), minimum: %s",
			interval, MinIntervalToGraceRatio, gracePeriod, minInterval,
		)
	}

	return nil
}
