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

package conditions_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/conditions"
)

const generation = 3

func ready(status metav1.ConditionStatus, reason string) metav1.Condition {
	return metav1.Condition{Type: configv1alpha1.ConditionReady, Status: status, Reason: reason,
		Message: "The message of " + reason + ".", ObservedGeneration: generation}
}

// types returns the types of the conditions, each with its status.
func types(list []metav1.Condition) map[string]metav1.ConditionStatus {
	out := map[string]metav1.ConditionStatus{}
	for _, c := range list {
		out[c.Type] = c.Status
	}
	return out
}

func TestSetReadyKeepsTheThreeConditionsConsistent(t *testing.T) {
	yes, no, unknown := metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionUnknown
	readyType, reconcilingType, stalledType := configv1alpha1.ConditionReady, configv1alpha1.ConditionReconciling, configv1alpha1.ConditionStalled
	for name, tc := range map[string]struct {
		ready    metav1.ConditionStatus
		progress conditions.Progress
		want     map[string]metav1.ConditionStatus
	}{
		"Ready has neither, whatever progress says": {yes, conditions.Stalled, map[string]metav1.ConditionStatus{readyType: yes}},
		"Ready has neither, nor while reconciling":  {yes, conditions.Reconciling, map[string]metav1.ConditionStatus{readyType: yes}},
		"not Ready and stalled":                     {no, conditions.Stalled, map[string]metav1.ConditionStatus{readyType: no, stalledType: yes}},
		"not Ready and reconciling":                 {no, conditions.Reconciling, map[string]metav1.ConditionStatus{readyType: no, reconcilingType: yes}},
		"not Ready, and neither":                    {no, conditions.None, map[string]metav1.ConditionStatus{readyType: no}},
		"Unknown and reconciling":                   {unknown, conditions.Reconciling, map[string]metav1.ConditionStatus{readyType: unknown, reconcilingType: yes}},
		"Unknown is never stalled, but reconciling": {unknown, conditions.Stalled, map[string]metav1.ConditionStatus{readyType: unknown, reconcilingType: yes}},
		"Unknown, and neither":                      {unknown, conditions.None, map[string]metav1.ConditionStatus{readyType: unknown}},
	} {
		t.Run(name, func(t *testing.T) {
			// Every start: the conditions of the other kind of progress are there, and must go when they no
			// longer hold.
			for _, before := range [][]metav1.Condition{
				nil,
				{ready(no, "Before"), {Type: configv1alpha1.ConditionStalled, Status: yes, Reason: "Before"}},
				{ready(unknown, "Before"), {Type: configv1alpha1.ConditionReconciling, Status: yes, Reason: "Before"}},
			} {
				list := append([]metav1.Condition(nil), before...)
				in := ready(tc.ready, "Now")
				conditions.SetReady(&list, in, tc.progress)

				require.Equal(t, tc.want, types(list))
				for _, c := range list {
					require.Equal(t, in.Reason, c.Reason, "%s gives the reason of Ready", c.Type)
					require.Equal(t, in.Message, c.Message, "%s gives the message of Ready", c.Type)
					require.Equal(t, int64(generation), c.ObservedGeneration, "%s is at the generation of Ready", c.Type)
				}
			}
		})
	}
}

func TestSetReadyKeepsOtherConditions(t *testing.T) {
	list := []metav1.Condition{{Type: configv1alpha1.ConditionEvaluated, Status: metav1.ConditionTrue, Reason: "NoEvaluationErrors"}}

	conditions.SetReady(&list, ready(metav1.ConditionFalse, "Invalid"), conditions.Stalled)

	require.NotNil(t, meta.FindStatusCondition(list, configv1alpha1.ConditionEvaluated))
	require.True(t, meta.IsStatusConditionTrue(list, configv1alpha1.ConditionStalled))
}

func TestSetReadySaysWhetherItChangedAnything(t *testing.T) {
	var list []metav1.Condition
	require.True(t, conditions.SetReady(&list, ready(metav1.ConditionFalse, "Invalid"), conditions.Stalled))
	require.False(t, conditions.SetReady(&list, ready(metav1.ConditionFalse, "Invalid"), conditions.Stalled),
		"the same conditions again")
	require.True(t, conditions.SetReady(&list, ready(metav1.ConditionFalse, "Invalid"), conditions.Reconciling),
		"Stalled goes and Reconciling comes")
	require.True(t, conditions.SetReady(&list, ready(metav1.ConditionTrue, "Valid"), conditions.Reconciling),
		"Reconciling goes")
	require.False(t, conditions.SetReady(&list, ready(metav1.ConditionTrue, "Valid"), conditions.Stalled))

	stalled := []metav1.Condition{ready(metav1.ConditionFalse, "Invalid"),
		{Type: configv1alpha1.ConditionStalled, Status: metav1.ConditionTrue, Reason: "Invalid", Message: "The message of Invalid.",
			ObservedGeneration: generation}}
	require.False(t, conditions.SetReady(&stalled, ready(metav1.ConditionFalse, "Invalid"), conditions.Stalled))
	require.True(t, conditions.SetReady(&stalled, ready(metav1.ConditionFalse, "Other"), conditions.Stalled),
		"Stalled follows the reason of Ready")
}

func TestObserveSetsTheGenerationAndSaysWhetherItChanged(t *testing.T) {
	var observed *int64
	require.True(t, conditions.Observe(&observed, 1), "none was observed")
	require.Equal(t, int64(1), *observed)
	require.False(t, conditions.Observe(&observed, 1))
	require.True(t, conditions.Observe(&observed, 2))
	require.Equal(t, int64(2), *observed)
}
