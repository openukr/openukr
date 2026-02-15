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

package publish

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	openukrv1alpha1 "github.com/openukr/openukr/api/v1alpha1"
	"github.com/openukr/openukr/pkg/crypto"
)

// FilesystemPublisher publishes public keys to the local filesystem.
type FilesystemPublisher struct{}

// NewFilesystemPublisher creates a new filesystem publisher.
func NewFilesystemPublisher() *FilesystemPublisher {
	return &FilesystemPublisher{}
}

// Publish writes the public key (PEM format) to the configured path.
// Config required: "path" (directory).
// Output file: {path}/{KeyID}.pub
func (p *FilesystemPublisher) Publish(ctx context.Context, target openukrv1alpha1.PublishTarget, kp *crypto.KeyPair) error {
	path, ok := target.Config["path"]
	if !ok || path == "" {
		return fmt.Errorf("missing 'path' in config")
	}

	// [SEC:S-3] Path traversal protection
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		return fmt.Errorf("publish path must be absolute, got: %s", path)
	}
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("publish path must not contain '..': %s", path)
	}

	// Ensure directory exists — 0750: owner rwx, group rx, others none
	if err := os.MkdirAll(cleanPath, 0750); err != nil {
		return fmt.Errorf("failed to ensure directory %s: %w", cleanPath, err)
	}

	// Default to PEM encoding for filesystem
	encoder, err := crypto.NewKeyEncoder("PEM")
	if err != nil {
		return err
	}

	pubPEM, err := encoder.EncodePublic(kp.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	filename := filepath.Join(cleanPath, fmt.Sprintf("%s.pub", kp.KeyID))

	// [SEC:S-3] Atomic write: write to temp file, then rename.
	// This prevents partial writes from being observable.
	tmpFile := filename + ".tmp"
	if err := os.WriteFile(tmpFile, pubPEM, 0600); err != nil {
		return fmt.Errorf("failed to write temp file %s: %w", tmpFile, err)
	}
	if err := os.Rename(tmpFile, filename); err != nil {
		_ = os.Remove(tmpFile) // Best-effort cleanup
		return fmt.Errorf("failed to rename %s → %s: %w", tmpFile, filename, err)
	}

	return nil
}
