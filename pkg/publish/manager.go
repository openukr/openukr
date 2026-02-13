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

	"sigs.k8s.io/controller-runtime/pkg/client"

	openukrv1alpha1 "github.com/openukr/openukr/api/v1alpha1"
	"github.com/openukr/openukr/pkg/crypto"
)

// Manager orchestrates key publishing to multiple targets.
type Manager struct {
	publishers map[string]Publisher
}

// NewManager creates a new Manager.
func NewManager(k8sClient client.Client) *Manager {
	return &Manager{
		publishers: map[string]Publisher{
			"filesystem": NewFilesystemPublisher(),
			"http":       NewHTTPPublisher(k8sClient),
		},
	}
}

// PublishAll publishes the key pair to all configured targets.
// It iterates over targets and delegates to the appropriate publisher implementation.
func (m *Manager) PublishAll(ctx context.Context, targets []openukrv1alpha1.PublishTarget, kp *crypto.KeyPair) error {
	var errs []error
	for i, target := range targets {
		pub, ok := m.publishers[target.Type]
		if !ok {
			errs = append(errs, fmt.Errorf("target[%d]: unknown publisher type %q", i, target.Type))
			continue
		}

		if err := pub.Publish(ctx, target, kp); err != nil {
			errs = append(errs, fmt.Errorf("target[%d] (%s) failed: %w", i, target.Type, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("publish errors: %v", errs)
	}
	return nil
}
