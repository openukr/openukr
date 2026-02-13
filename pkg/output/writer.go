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
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	openukrv1alpha1 "github.com/openukr/openukr/api/v1alpha1"
	"github.com/openukr/openukr/pkg/crypto"
)

// SecretWriter manages the lifecycle of Kubernetes Secrets containing key material.
type SecretWriter interface {
	// Write creates or updates the Secret for the given KeyProfile and KeyPair.
	// It handles:
	// - Rendering the key material (via FormatRenderer)
	// - Setting OwnerReference
	// - Atomic Secret update
	Write(ctx context.Context, profile *openukrv1alpha1.KeyProfile, kp *crypto.KeyPair) error
}

// NewSecretWriter creates a new SecretWriter.
func NewSecretWriter(client client.Client, scheme *runtime.Scheme, renderer FormatRenderer) SecretWriter {
	return &kubeSecretWriter{
		client:   client,
		scheme:   scheme,
		renderer: renderer,
	}
}

type kubeSecretWriter struct {
	client   client.Client
	scheme   *runtime.Scheme
	renderer FormatRenderer
}

func (w *kubeSecretWriter) Write(ctx context.Context, profile *openukrv1alpha1.KeyProfile, kp *crypto.KeyPair) error {
	if profile == nil {
		return fmt.Errorf("profile cannot be nil")
	}
	if kp == nil {
		return fmt.Errorf("keyPair cannot be nil")
	}

	// 1. Render data
	// TODO: Password/Alias handling from profile.Spec.Output (not yet in CRD spec, defaulting to empty/default)
	// For JKS, future iterations will need to read password from another Secret.
	// For now, we assume defaults or empty password (which errors for JKS).
	// [Gap]: JKS Password support in CRD needed.
	opts := RenderOptions{
		Format: profile.Spec.Output.Format,
		// Password: "", // TODO: Fetch from SecretRef defined in CRD
		// Alias: "",    // TODO: Define in CRD or default
	}

	// If using JKS, we need a password hardcoded or mocked for now until CRD update.
	// But let's stick to what's possible. If JKS is selected but no password provided, Renderer will error.
	// We proceed, error propagation handles it.

	data, err := w.renderer.Render(kp, opts)
	if err != nil {
		return fmt.Errorf("failed to render key material: %w", err)
	}

	// 2. Prepare Secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      profile.Spec.Output.SecretName,
			Namespace: profile.Namespace, // [SEC:S-1] Enforce same namespace
		},
	}

	// 3. Create or Update (CreateOrUpdate is not ideal for Secrets due to potential data races, but good for simplicity here)
	// A better approach for atomicity is strictly ensuring we own it.
	op, err := controllerutil.CreateOrUpdate(ctx, w.client, secret, func() error {
		// Set OwnerReference [SEC:S-1]
		if err := ctrl.SetControllerReference(profile, secret, w.scheme); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}

		// Apply Labels
		if secret.Labels == nil {
			secret.Labels = make(map[string]string)
		}
		// Merge user labels
		for k, v := range profile.Spec.Output.Labels {
			secret.Labels[k] = v
		}
		// Enforce management label
		secret.Labels["app.kubernetes.io/managed-by"] = "openukr"
		secret.Labels["openukr.io/key-profile"] = profile.Name

		// Set Data
		secret.Data = data
		secret.Type = corev1.SecretTypeOpaque // or corev1.SecretTypeTLS if split-pem

		// Optimization: if format is split-pem, we can use SecretTypeTLS
		if profile.Spec.Output.Format == FormatSplitPEM {
			secret.Type = corev1.SecretTypeTLS
		}

		// Set Annotations for audit/metadata
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations["openukr.io/last-rotation"] = kp.CreatedAt.Format(time.RFC3339)
		secret.Annotations["openukr.io/key-id"] = kp.KeyID
		secret.Annotations["openukr.io/algorithm"] = kp.Algorithm

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to apply secret: %w", err)
	}

	_ = op // "created" or "updated" - could log this

	return nil
}
