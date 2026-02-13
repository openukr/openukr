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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeyProfileSpec defines the desired state of a key identity managed by openUKR.
type KeyProfileSpec struct {
	// ServiceAccountRef identifies the Kubernetes ServiceAccount this key identity is bound to.
	ServiceAccountRef ServiceAccountReference `json:"serviceAccountRef"`

	// KeySpec defines the cryptographic parameters for key generation.
	KeySpec KeySpec `json:"keySpec"`

	// Rotation defines the rotation policy for this key identity.
	Rotation RotationPolicy `json:"rotation"`

	// Output defines how the generated key material is stored as a Kubernetes Secret.
	Output OutputConfig `json:"output"`

	// Publish defines optional targets where public keys are published.
	// +optional
	Publish []PublishTarget `json:"publish,omitempty"`
}

// ServiceAccountReference identifies a Kubernetes ServiceAccount.
type ServiceAccountReference struct {
	// Name of the ServiceAccount.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the ServiceAccount. Must match the KeyProfile's namespace (enforced by webhook).
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// KeySpec defines cryptographic key parameters.
type KeySpec struct {
	// Algorithm specifies the asymmetric key algorithm.
	// +kubebuilder:validation:Enum=EC;RSA
	Algorithm string `json:"algorithm"`

	// Params holds algorithm-specific parameters.
	// For EC: {"curve": "P-256"|"P-384"|"P-521"}
	// For RSA: {"keySize": "2048"|"3072"|"4096"}
	Params map[string]string `json:"params"`

	// Encoding specifies the key encoding format.
	// +kubebuilder:validation:Enum=PEM;DER;JWK
	// +kubebuilder:default=PEM
	Encoding string `json:"encoding,omitempty"`

	// AllowLegacyKeySize permits RSA key sizes below 3072 bits.
	// RSA < 3072 is deprecated per BSI TR-02102-1 (2025) and rejected by default.
	// Set to true only for documented legacy compatibility requirements.
	// [COMP:G-1]
	// +optional
	AllowLegacyKeySize bool `json:"allowLegacyKeySize,omitempty"`
}

// RotationPolicy defines the key rotation schedule.
type RotationPolicy struct {
	// Interval specifies how often the key is rotated.
	// Must be at least 3× GracePeriod.
	Interval metav1.Duration `json:"interval"`

	// GracePeriod specifies how long the previous key remains valid after rotation.
	// Must be at least 5 minutes (NIST SP 800-57).
	// [COMP:G-4]
	GracePeriod metav1.Duration `json:"gracePeriod"`

	// TriggerOnStartup forces an immediate rotation when the controller starts.
	// +optional
	TriggerOnStartup bool `json:"triggerOnStartup,omitempty"`
}

// OutputConfig defines how key material is stored as a Kubernetes Secret.
type OutputConfig struct {
	// SecretName is the name of the Kubernetes Secret to create/update.
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`

	// Format defines the Secret data layout.
	// +kubebuilder:validation:Enum=split-pem;bundle-json;jwks
	// +kubebuilder:default=split-pem
	Format string `json:"format,omitempty"`

	// Labels are additional labels applied to the managed Secret.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

// PublishTarget defines a target where the public key is published.
type PublishTarget struct {
	// Type specifies the publisher implementation.
	// +kubebuilder:validation:Enum=http;filesystem
	Type string `json:"type"`

	// Config holds publisher-specific configuration.
	// For http: {"endpoint": "https://..."}
	// For filesystem: {"path": "/var/keys/"}
	Config map[string]string `json:"config"`

	// TLS configures transport security for HTTP publishers.
	// [SEC:T-2]
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`
}

// TLSConfig configures transport-layer security for publishers.
// [SEC:T-2] Transport integrity for HTTP Publisher.
type TLSConfig struct {
	// CACertSecretRef references a Kubernetes Secret containing the CA certificate bundle.
	CACertSecretRef string `json:"caCertSecretRef"`

	// ClientCertSecretRef references a Kubernetes Secret containing the mTLS client certificate.
	// +optional
	ClientCertSecretRef string `json:"clientCertSecretRef,omitempty"`

	// InsecureSkipVerify disables TLS certificate verification.
	// WARNING: Must be false in production environments.
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Algorithm",type=string,JSONPath=`.spec.keySpec.algorithm`
// +kubebuilder:printcolumn:name="KeyID",type=string,JSONPath=`.status.currentKeyID`
// +kubebuilder:printcolumn:name="LastRotation",type=date,JSONPath=`.status.lastRotation`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// KeyProfile is the Schema for the keyprofiles API.
// It defines a declarative key identity managed by openUKR.
type KeyProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeyProfileSpec   `json:"spec,omitempty"`
	Status KeyProfileStatus `json:"status,omitempty"`
}

// KeyProfileStatus defines the observed state of a KeyProfile.
type KeyProfileStatus struct {
	// Phase indicates the current rotation phase.
	// +kubebuilder:validation:Enum=Idle;Active;Generating;Publishing;Distributing;GracePeriod;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// CurrentKeyID is the identifier of the currently active key.
	// +optional
	CurrentKeyID string `json:"currentKeyID,omitempty"`

	// PreviousKeyID is the identifier of the previous key (during grace period).
	// +optional
	PreviousKeyID string `json:"previousKeyID,omitempty"`

	// CurrentKeyFingerprint is the SHA-256 fingerprint of the current key's public component.
	// Used for integrity verification against Secret tampering.
	// [SEC:T-1]
	// +optional
	CurrentKeyFingerprint string `json:"currentKeyFingerprint,omitempty"`

	// PreviousKeyFingerprint is the SHA-256 fingerprint of the previous key's public component.
	// [SEC:T-1]
	// +optional
	PreviousKeyFingerprint string `json:"previousKeyFingerprint,omitempty"`

	// LastRotation is the timestamp of the last successful rotation.
	// +optional
	LastRotation *metav1.Time `json:"lastRotation,omitempty"`

	// NextRotation is the timestamp of the next scheduled rotation.
	// +optional
	NextRotation *metav1.Time `json:"nextRotation,omitempty"`

	// Conditions represent the latest available observations of the KeyProfile's state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// KeyProfileList contains a list of KeyProfile.
type KeyProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeyProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeyProfile{}, &KeyProfileList{})
}
