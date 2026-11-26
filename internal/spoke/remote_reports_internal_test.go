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
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
)

// The remote renderer's own tests build it around a hub whose own cluster has the name of a remote cluster, cluster-a,
// as after a rename of the hub onto a Spoke's name.

// cluster2 is a remote cluster whose name the hub's own cluster doesn't have.
const cluster2 = "cluster-b"

// hubNamed returns a client of the hub whose OperatorConfig names its own cluster cluster.
func hubNamed(t *testing.T, cluster string) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(&configv1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName},
		Spec:       configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(cluster)},
	}).Build()
}

// playbooksOf are the Playbooks of the names.
type playbooksOf []string

func (p playbooksOf) List(context.Context) ([]configv1alpha1.Playbook, error) {
	out := make([]configv1alpha1.Playbook, 0, len(p))
	for _, name := range p {
		out = append(out, configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: name}})
	}
	return out, nil
}

func (p playbooksOf) Source(handler.EventHandler) source.Source { return nil }

// deletions is a counts store that records the counts that it deletes, as playbook.cluster.
type deletions struct {
	inventory.CountsStore
	deleted []string
}

func (d *deletions) Delete(_ context.Context, playbook, cluster string) error {
	d.deleted = append(d.deleted, inventory.CountsName(playbook, cluster))
	return nil
}

// While a rename of the hub onto a remote cluster's name reaches the remote renderer, the hub's own renderer already
// sends the series of that name, and a scrape refuses a series sent twice: the remote source leaves that name out. A
// name that can't be read, as before the manager's cache starts, has the source send nothing, rather than fail the
// whole scrape.
func TestTheRemoteSeriesLeaveOutTheHubsOwnName(t *testing.T) {
	r := &RemoteReports{client: hubNamed(t, cluster1), series: NewReportsCollector(), log: logr.Discard()}
	key := types.NamespacedName{Namespace: teamA, Name: webReport}
	r.series.set(cluster1, key, seriesOf(cluster1, deploymentKind, webName, counted(1, 0, 0, 0)))
	r.series.set(cluster2, key, seriesOf(cluster2, deploymentKind, webName, counted(1, 0, 0, 0)))

	funnel := gather(t, remoteSource{r})["vexplain_funnel"]

	require.NotEmpty(t, funnel)
	for _, series := range funnel {
		require.Equal(t, cluster2, series[clusterLabel], "only the remote cluster's series")
	}

	r.client = fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	require.Empty(t, gather(t, remoteSource{r}), "nothing, when the hub's own name can't be read")
}

// A remote cluster that the hub no longer renders has its series forgotten, and the counts of each playbook for it
// deleted, but under the name of the hub's own cluster: those are the hub's own, which its own renderer writes from the
// rename on, and wouldn't write again.
func TestForgettingAClusterOfTheHubsOwnNameLeavesItsCounts(t *testing.T) {
	counts := &deletions{}
	r := &RemoteReports{client: hubNamed(t, cluster1), playbooks: playbooksOf{metricsPlaybook}, counts: counts,
		series: NewReportsCollector(), known: map[string]*remoteState{}}
	key := types.NamespacedName{Namespace: teamA, Name: webReport}
	for _, cluster := range []string{cluster1, cluster2} {
		r.mu.Lock()
		r.state(cluster)
		r.mu.Unlock()
		r.series.set(cluster, key, seriesOf(cluster, deploymentKind, webName, counted(1, 0, 0, 0)))
	}

	require.NoError(t, r.forgetGone(t.Context(), nil))

	require.Equal(t, []string{inventory.CountsName(metricsPlaybook, cluster2)}, counts.deleted)
	require.Empty(t, r.known)
	require.Empty(t, gather(t, r.series), "every series of both")
}
