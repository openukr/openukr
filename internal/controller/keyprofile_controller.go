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

package controller

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	openukrv1alpha1 "github.com/openukr/openukr/api/v1alpha1"
	"github.com/openukr/openukr/pkg/rotation"
)

// KeyProfileReconciler reconciles a KeyProfile object
type KeyProfileReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	RotationManager rotation.RotationManager
}

// +kubebuilder:rbac:groups=openukr.openukr.io,resources=keyprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=openukr.openukr.io,resources=keyprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=openukr.openukr.io,resources=keyprofiles/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *KeyProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// 1. Fetch KeyProfile
	var profile openukrv1alpha1.KeyProfile
	if err := r.Get(ctx, req.NamespacedName, &profile); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Ensure Key (Rotate if needed)
	res, err := r.RotationManager.EnsureKey(ctx, &profile)
	if err != nil {
		log.Error(err, "Failed to ensure key")
		// Exponential backoff via controller-runtime default
		return ctrl.Result{}, err
	}

	// 3. Update Status
	if r.needsStatusUpdate(&profile, res) {
		profile.Status.LastRotation = &metav1.Time{Time: res.RotationTime}
		profile.Status.NextRotation = &metav1.Time{Time: res.NextRotation}
		profile.Status.CurrentKeyID = res.KeyID
		profile.Status.CurrentKeyFingerprint = res.Fingerprint

		// Set Phase
		profile.Status.Phase = "Active" // Simplified for MVP

		if err := r.Status().Update(ctx, &profile); err != nil {
			log.Error(err, "Failed to update KeyProfile status")
			return ctrl.Result{}, err
		}
	}

	// 4. Schedule Requeue
	if !res.NextRotation.IsZero() {
		requeueAfter := time.Until(res.NextRotation)
		if requeueAfter < 0 {
			requeueAfter = 1 * time.Second // Retry immediately if overdue
		}
		log.V(1).Info("Requeue scheduled", "after", requeueAfter)
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	return ctrl.Result{}, nil
}

func (r *KeyProfileReconciler) needsStatusUpdate(profile *openukrv1alpha1.KeyProfile, res *rotation.RotationResult) bool {
	if profile.Status.CurrentKeyID != res.KeyID {
		return true
	}
	if profile.Status.CurrentKeyFingerprint != res.Fingerprint {
		return true
	}
	if profile.Status.LastRotation == nil || !profile.Status.LastRotation.Time.Equal(res.RotationTime) {
		return true
	}
	if profile.Status.NextRotation == nil || !profile.Status.NextRotation.Time.Equal(res.NextRotation) {
		return true
	}
	if profile.Status.Phase == "" {
		return true
	}
	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeyProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&openukrv1alpha1.KeyProfile{}).
		Named("keyprofile").
		Complete(r)
}
