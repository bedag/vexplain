/*
Copyright 2026.

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

// Package conditions sets the conditions that every kind which a controller of vexplain reconciles
// carries for kstatus (decision 0036): Ready, of positive polarity, and Reconciling and Stalled, of
// abnormal-true polarity, present only while True. GitOps tools such as Flux read the last two to tell
// a resource in progress from one that is stuck.
package conditions

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// Progress says what a Ready condition that isn't True means: that the controller is still at work, that
// it is stuck, or neither.
type Progress int

const (
	// None sets neither Reconciling nor Stalled.
	None Progress = iota
	// Reconciling means the controller works towards the current generation, retries something that may
	// pass, or waits on something that passes, such as a rollout, the grace for health after a start, or
	// a probe that it repeats.
	Reconciling
	// Stalled means the controller can't go on without a change of the object, or of something that it
	// names, such as a missing Collector or a rule that doesn't compile.
	Stalled
)

// SetReady sets ready in conditions, and Reconciling or Stalled with it as progress says, with the
// reason, message and observed generation of ready. It removes the one that doesn't hold, so that the
// three never contradict:
//   - Ready True has neither, whatever progress says.
//   - Stalled comes only with Ready False. A Ready that is Unknown isn't known to be stuck, so Stalled
//     sets Reconciling for it.
//   - Reconciling comes with Ready False or Unknown.
//
// It leaves every other condition as it is, and returns whether it changed any.
func SetReady(conditions *[]metav1.Condition, ready metav1.Condition, progress Progress) bool {
	ready.Type = configv1alpha1.ConditionReady
	changed := meta.SetStatusCondition(conditions, ready)
	present := ""
	switch {
	case ready.Status == metav1.ConditionTrue || progress == None:
	case progress == Stalled && ready.Status == metav1.ConditionFalse:
		present = configv1alpha1.ConditionStalled
	default:
		present = configv1alpha1.ConditionReconciling
	}
	for _, conditionType := range []string{configv1alpha1.ConditionReconciling, configv1alpha1.ConditionStalled} {
		if conditionType != present {
			changed = meta.RemoveStatusCondition(conditions, conditionType) || changed
			continue
		}
		changed = meta.SetStatusCondition(conditions, metav1.Condition{
			Type:               conditionType,
			Status:             metav1.ConditionTrue,
			Reason:             ready.Reason,
			Message:            ready.Message,
			ObservedGeneration: ready.ObservedGeneration,
		}) || changed
	}
	return changed
}

// Observe sets observed, a status.observedGeneration, to generation, the generation that the controller
// acted on, and returns whether that changed it. kstatus reads a status whose observedGeneration differs
// from metadata.generation as in progress.
func Observe(observed **int64, generation int64) bool {
	if *observed != nil && **observed == generation {
		return false
	}
	*observed = &generation
	return true
}
