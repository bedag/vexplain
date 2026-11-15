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

package spoke

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

func TestTheSummaryRanksTheHighestUrgencyFromOneAsTheMostUrgent(t *testing.T) {
	for urgency, want := range map[triagev1alpha1.SSVCOutcome]int32{
		triagev1alpha1.SSVCOutcomeImmediate: 1, triagev1alpha1.SSVCOutcomeOutOfCycle: 2,
		triagev1alpha1.SSVCOutcomeScheduled: 3, triagev1alpha1.SSVCOutcomeDefer: 4,
		"SomethingNew": 0, // an outcome that the renderer doesn't know counts as the most urgent
	} {
		summary := summaryOf([]triagev1alpha1.ResourceAction{{Step: triagev1alpha1.ResourceStepUpdate, Urgency: ptr.To(urgency)}}, unsettled{})
		require.Equal(t, ptr.To(want), summary.UrgencyRank, string(urgency))
	}
	require.Nil(t, summaryOf(nil, unsettled{}).UrgencyRank, "no urgency, no rank")
}
