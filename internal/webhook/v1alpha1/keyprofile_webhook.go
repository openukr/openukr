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

package v1alpha1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	openukrv1alpha1 "github.com/openukr/openukr/api/v1alpha1"
	pkgcrypto "github.com/openukr/openukr/pkg/crypto"
	"github.com/openukr/openukr/pkg/validation"
)

var keyprofilelog = logf.Log.WithName("keyprofile-webhook") //nolint:unused

// SetupKeyProfileWebhookWithManager registers the webhook for KeyProfile in the manager.
func SetupKeyProfileWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&openukrv1alpha1.KeyProfile{}).
		WithValidator(&KeyProfileCustomValidator{}).
		WithDefaulter(&KeyProfileCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-openukr-openukr-io-v1alpha1-keyprofile,mutating=true,failurePolicy=fail,sideEffects=None,groups=openukr.openukr.io,resources=keyprofiles,verbs=create;update,versions=v1alpha1,name=mkeyprofile-v1alpha1.kb.io,admissionReviewVersions=v1

// KeyProfileCustomDefaulter sets defaults on KeyProfile resources.
type KeyProfileCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &KeyProfileCustomDefaulter{}

// Default sets default values for KeyProfile fields.
func (d *KeyProfileCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	keyprofile, ok := obj.(*openukrv1alpha1.KeyProfile)
	if !ok {
		return fmt.Errorf("webhook defaulter: expected KeyProfile but got %T", obj)
	}

	// Default encoding to PEM if not set
	if keyprofile.Spec.KeySpec.Encoding == "" {
		keyprofile.Spec.KeySpec.Encoding = "PEM"
	}

	// Default output format to split-pem if not set
	if keyprofile.Spec.Output.Format == "" {
		keyprofile.Spec.Output.Format = "split-pem"
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-openukr-openukr-io-v1alpha1-keyprofile,mutating=false,failurePolicy=fail,sideEffects=None,groups=openukr.openukr.io,resources=keyprofiles,verbs=create;update,versions=v1alpha1,name=vkeyprofile-v1alpha1.kb.io,admissionReviewVersions=v1

// KeyProfileCustomValidator validates KeyProfile resources.
type KeyProfileCustomValidator struct{}

var _ webhook.CustomValidator = &KeyProfileCustomValidator{}

// ValidateCreate validates a KeyProfile upon creation.
func (v *KeyProfileCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	keyprofile, ok := obj.(*openukrv1alpha1.KeyProfile)
	if !ok {
		return nil, fmt.Errorf("webhook validator: expected KeyProfile but got %T", obj)
	}
	return validateKeyProfile(keyprofile)
}

// ValidateUpdate validates a KeyProfile upon update.
func (v *KeyProfileCustomValidator) ValidateUpdate(_ context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	keyprofile, ok := newObj.(*openukrv1alpha1.KeyProfile)
	if !ok {
		return nil, fmt.Errorf("webhook validator: expected KeyProfile but got %T", newObj)
	}
	return validateKeyProfile(keyprofile)
}

// ValidateDelete validates a KeyProfile upon deletion.
func (v *KeyProfileCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	// No validation needed on delete
	return nil, nil
}

// validateKeyProfile runs all validation rules against a KeyProfile.
// All validation is delegated to shared packages (DRY):
//   - pkg/validation — namespace match, rotation policy
//   - pkg/crypto     — algorithm/key spec validation
func validateKeyProfile(kp *openukrv1alpha1.KeyProfile) (admission.Warnings, error) {
	var allWarnings admission.Warnings

	// [SEC:S-1] Namespace match — prevents cross-namespace key requests
	if err := validation.ValidateNamespaceMatch(
		kp.Namespace,
		kp.Spec.ServiceAccountRef.Namespace,
	); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// [COMP:G-4] Rotation policy — interval/gracePeriod constraints
	if err := validation.ValidateRotationPolicy(
		kp.Spec.Rotation.Interval.Duration,
		kp.Spec.Rotation.GracePeriod.Duration,
	); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// [COMP:G-1] Key spec — algorithm/parameters, BSI TR-02102-1 compliance
	warnings, err := pkgcrypto.ValidateKeySpec(
		kp.Spec.KeySpec.Algorithm,
		kp.Spec.KeySpec.Params,
		kp.Spec.KeySpec.AllowLegacyKeySize,
	)
	if err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	allWarnings = append(allWarnings, warnings...)

	// [SEC:T-2] TLS configuration warnings for HTTP publishers
	for i, pub := range kp.Spec.Publish {
		if pub.Type == "http" && pub.TLS != nil && pub.TLS.InsecureSkipVerify {
			allWarnings = append(allWarnings, fmt.Sprintf(
				"publish[%d]: insecureSkipVerify=true disables TLS verification — not recommended for production", i))
		}
	}

	return allWarnings, nil
}
