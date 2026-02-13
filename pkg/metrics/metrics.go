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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// RotationsTotal counts the number of successful key rotations.
	RotationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openukr_rotations_total",
			Help: "Number of successful key rotations",
		},
		[]string{"algorithm", "namespace"},
	)

	// RotationErrorsTotal counts the number of failed rotation attempts.
	RotationErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openukr_rotation_errors_total",
			Help: "Number of failed rotation attempts",
		},
		[]string{"reason", "namespace"},
	)

	// KeyGenerationDuration tracks the latency of cryptographic key generation.
	KeyGenerationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "openukr_key_generation_duration_seconds",
			Help:    "Latency of cryptographic key generation",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"algorithm"},
	)
)

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(RotationsTotal, RotationErrorsTotal, KeyGenerationDuration)
}
