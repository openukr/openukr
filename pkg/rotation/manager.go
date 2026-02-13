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

package rotation

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"

	openukrv1alpha1 "github.com/openukr/openukr/api/v1alpha1"
	"github.com/openukr/openukr/pkg/crypto"
	"github.com/openukr/openukr/pkg/metrics"
	"github.com/openukr/openukr/pkg/output"
)

// RotationResult contains information about the outcome of a rotation check.
type RotationResult struct {
	// Rotated indicates if a new key was generated and written.
	Rotated bool
	// KeyID of the active key (new or existing).
	KeyID string
	// RotationTime is when the rotation occurred (or last rotation if not rotated).
	RotationTime time.Time
	// NextRotation is the calculated time for the next scheduled rotation.
	NextRotation time.Time
	// Fingerprint of the active key [SEC:T-1]
	Fingerprint string
}

// RotationManager handles the lifecycle of keys: checking rotation schedules,
// generating new keys, and persisting them via SecretWriter.
type RotationManager interface {
	// EnsureKey checks if a key needs to be generated or rotated for the given profile.
	EnsureKey(ctx context.Context, profile *openukrv1alpha1.KeyProfile) (*RotationResult, error)
}

// Publisher abstracts the publishing of public keys to external targets.
type Publisher interface {
	PublishAll(ctx context.Context, targets []openukrv1alpha1.PublishTarget, kp *crypto.KeyPair) error
}

// NewManager creates a new RotationManager.
func NewManager(
	log logr.Logger,
	keygen crypto.KeyGenerator,
	writer output.SecretWriter,
	publisher Publisher,
) RotationManager {
	return &manager{
		log:       log,
		keygen:    keygen,
		writer:    writer,
		publisher: publisher,
	}
}

type manager struct {
	log       logr.Logger
	keygen    crypto.KeyGenerator
	writer    output.SecretWriter
	publisher Publisher
}

func (m *manager) EnsureKey(ctx context.Context, profile *openukrv1alpha1.KeyProfile) (*RotationResult, error) {
	log := m.log.WithValues("keyprofile", types.NamespacedName{Name: profile.Name, Namespace: profile.Namespace})

	// 1. Check if rotation is needed
	needsRotation, reason := m.checkRotationNeeded(profile)
	if !needsRotation {
		// Calculate next rotation for status
		nextRot := calculateNextRotation(profile.Status.LastRotation.Time, profile.Spec.Rotation.Interval.Duration)
		return &RotationResult{
			Rotated:      false,
			KeyID:        profile.Status.CurrentKeyID,
			RotationTime: profile.Status.LastRotation.Time,
			NextRotation: nextRot,
			Fingerprint:  profile.Status.CurrentKeyFingerprint,
		}, nil
	}

	log.Info("Rotation needed", "reason", reason)

	// 2. Generate new KeyPair [SEC:I-2]
	// Using configured algorithm and parameters
	// Also passing AllowLegacyKeySize for BSI compliance check override
	opts := crypto.GenerateOptions{
		Algorithm:          profile.Spec.KeySpec.Algorithm,
		Params:             profile.Spec.KeySpec.Params,
		AllowLegacyKeySize: profile.Spec.KeySpec.AllowLegacyKeySize,
	}

	start := time.Now()
	kp, err := m.keygen.Generate(opts)
	duration := time.Since(start).Seconds()

	metrics.KeyGenerationDuration.WithLabelValues(opts.Algorithm).Observe(duration)

	if err != nil {
		metrics.RotationErrorsTotal.WithLabelValues("keygen", profile.Namespace).Inc()
		return nil, fmt.Errorf("key generation failed: %w", err)
	}
	// [SEC:I-2] Memory Wipe guaranteed via defer
	defer kp.Wipe()

	// Compute Fingerprint [SEC:T-1]
	// Must be done before Wipe()
	fingerprint, err := crypto.ComputeFingerprint(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("fingerprint computation failed: %w", err)
	}

	// 3. Publish Public Key [SEC:S-2.4]
	// Publish BEFORE distribution to ensure validators receive key first
	if err := m.publisher.PublishAll(ctx, profile.Spec.Publish, kp); err != nil {
		metrics.RotationErrorsTotal.WithLabelValues("publish", profile.Namespace).Inc()
		return nil, fmt.Errorf("failed to publish public key: %w", err)
	}

	// 4. Persist KeyPair to Secret [SEC:S-1]
	// SecretWriter handles formatting, ownerRef, and atomic update
	if err := m.writer.Write(ctx, profile, kp); err != nil {
		metrics.RotationErrorsTotal.WithLabelValues("persist", profile.Namespace).Inc()
		return nil, fmt.Errorf("failed to persist key material: %w", err)
	}

	now := time.Now()
	nextRot := calculateNextRotation(now, profile.Spec.Rotation.Interval.Duration)

	metrics.RotationsTotal.WithLabelValues(kp.Algorithm, profile.Namespace).Inc()
	log.Info("Key rotated successfully", "keyID", kp.KeyID, "nextRotation", nextRot)

	// 4. Return result for Status update
	return &RotationResult{
		Rotated:      true,
		KeyID:        kp.KeyID,
		RotationTime: now,
		NextRotation: nextRot,
		Fingerprint:  fingerprint,
	}, nil
}

func (m *manager) checkRotationNeeded(profile *openukrv1alpha1.KeyProfile) (bool, string) {
	// Case 0: No Key yet
	if profile.Status.CurrentKeyID == "" || profile.Status.LastRotation.IsZero() {
		return true, "initial key generation"
	}

	// Case 1: Time-based rotation
	interval := profile.Spec.Rotation.Interval.Duration
	if interval == 0 {
		return false, "rotation disabled (interval=0)"
	}

	now := time.Now()
	nextRotation := profile.Status.LastRotation.Time.Add(interval)

	if now.After(nextRotation) {
		return true, fmt.Sprintf("interval %s expired (due: %s)", interval, nextRotation)
	}

	// Case 2: Spec change? (Algorithm change requires rotation)
	// This usually requires comparing stored key metadata vs spec.
	// Since we don't track *stored* algorithm in Status (yet, only KeyID),
	// detecting spec change might require inspecting the Secret or adding fields to Status.
	// For MVP (M1), we rely on time-based or manual trigger (delete Secret or Status).
	// [Enhancement]: Add 'Status.Algorithm' to detect changes.
	// Status.LastRotation covers the timing.

	return false, ""
}

func calculateNextRotation(lastRot time.Time, interval time.Duration) time.Time {
	if interval == 0 {
		return time.Time{} // Forever
	}
	return lastRot.Add(interval)
}
