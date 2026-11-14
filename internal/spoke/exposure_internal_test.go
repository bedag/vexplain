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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
)

// A report's unseen holds 8 values at most, the first in their order, as its schema allows, whatever the collectors
// name together. The schema of exposure lets fewer values through today, but a status past the limit would be refused
// whole.
func TestAReportShowsAtMost8UnseenValues(t *testing.T) {
	web := evidence.PresenceWorkload{Kind: "Deployment", Namespace: "team-a", Name: "web"}
	e := NewExposure()
	var want []triagev1alpha1.ReachUnseen
	for i := range 10 {
		unseen := triagev1alpha1.ReachUnseen(fmt.Sprintf("Kind%d", i))
		e.delivered[fmt.Sprintf("collector-%d", i)] = map[workloadKey]said{keyOf(web): {
			ssvc: configv1alpha1.SSVCExposureSmall, reach: string(triagev1alpha1.InternalReachCluster),
			unseen: []triagev1alpha1.ReachUnseen{unseen},
		}}
		if i < 8 {
			want = append(want, unseen)
		}
	}

	require.Equal(t, want, e.ForReport(web).Reach.Unseen)
}
