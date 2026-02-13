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

package validation

import (
	"testing"
	"time"
)

func TestValidateNamespaceMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		objectNamespace string
		specNamespace   string
		wantErr         bool
	}{
		{
			name:            "matching namespaces",
			objectNamespace: "finance",
			specNamespace:   "finance",
			wantErr:         false,
		},
		{
			name:            "mismatched namespaces",
			objectNamespace: "finance",
			specNamespace:   "kube-system",
			wantErr:         true,
		},
		{
			name:            "empty object namespace",
			objectNamespace: "",
			specNamespace:   "finance",
			wantErr:         true,
		},
		{
			name:            "both empty",
			objectNamespace: "",
			specNamespace:   "",
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateNamespaceMatch(tt.objectNamespace, tt.specNamespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNamespaceMatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRotationPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		interval    time.Duration
		gracePeriod time.Duration
		wantErr     bool
	}{
		{
			name:        "valid: 24h interval, 2h grace",
			interval:    24 * time.Hour,
			gracePeriod: 2 * time.Hour,
			wantErr:     false,
		},
		{
			name:        "valid: exact 3x ratio",
			interval:    15 * time.Minute,
			gracePeriod: 5 * time.Minute,
			wantErr:     false,
		},
		{
			name:        "invalid: grace period below minimum",
			interval:    15 * time.Minute,
			gracePeriod: 1 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "invalid: interval below 3x grace",
			interval:    10 * time.Minute,
			gracePeriod: 5 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "invalid: grace period zero",
			interval:    24 * time.Hour,
			gracePeriod: 0,
			wantErr:     true,
		},
		{
			name:        "valid: large values",
			interval:    720 * time.Hour,
			gracePeriod: 24 * time.Hour,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateRotationPolicy(tt.interval, tt.gracePeriod)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRotationPolicy(%s, %s) error = %v, wantErr %v",
					tt.interval, tt.gracePeriod, err, tt.wantErr)
			}
		})
	}
}
