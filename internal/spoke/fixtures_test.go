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

package spoke_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/spoke"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// The tests run the spoke's presence against an API server of envtest with the operator's CRDs. Each test runs a
// manager of its own with the controller of a Presence, as the operator's process does, for a cluster of its own, and
// hands the Presence what the streams of presence collectors would. They read the ImageInventory objects from the API
// server.

const (
	// operatorNamespace is the namespace of the operator, where the collectors' TLS Secrets are.
	operatorNamespace = "vexplain-system"

	// wait bounds how long a test waits for what must happen, and tick is how often it looks. quiet is how long a
	// test watches for what must not happen.
	wait  = 20 * time.Second
	tick  = 20 * time.Millisecond
	quiet = time.Second

	// repository is where the images of the tests come from.
	repository = "artifacts.example/team-a/app"
	// deployment is the kind of the workloads of the tests.
	deployment = "Deployment"
	// appsGroup is the API group of the Deployments, teamA a namespace and clusterA a cluster of the tests, and
	// reachCluster the internal reach of a workload that the whole cluster reaches.
	appsGroup    = "apps"
	teamA        = "team-a"
	clusterA     = "cluster-a"
	reachCluster = "Cluster"
	// notCheckedYet is the message of the Ready condition that the deployer gives a Collector before its first check.
	notCheckedYet = "The collector has not been checked yet."
	// workloadsName is the name of the Collector that streams presence in the tests, which startSpoke makes.
	workloadsName = "workloads"
	// The platforms that the pods of the tests run on.
	linuxAMD64 = "linux/amd64"
	linuxARM64 = "linux/arm64"
)

// scheme holds the kinds of the tests: the built-in ones and the operator's.
var scheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme, configv1alpha1.AddToScheme, inventoryv1alpha1.AddToScheme, triagev1alpha1.AddToScheme,
	} {
		if err := add(s); err != nil {
			panic(err)
		}
	}
	return s
}()

// api is the API server of the tests. It starts when the first test needs it, and TestMain stops it.
var api struct {
	once   sync.Once
	env    *envtest.Environment
	cfg    *rest.Config
	client client.Client
	err    error
}

func TestMain(m *testing.M) {
	// The SDK's servers log through slog, and the spoke's presence and executor through controller-runtime's logger.
	// Their lines would only crowd the output of a test that fails.
	slog.SetDefault(slog.New(slog.DiscardHandler))
	logf.SetLogger(logr.Discard())
	code := m.Run()
	if api.env != nil {
		if err := api.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping the API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// startAPI returns the configuration and a direct client of the API server, which it starts once, with the
// operator's CRDs and its namespace.
func startAPI(t *testing.T) (*rest.Config, client.Client) {
	t.Helper()
	api.once.Do(func() {
		api.env = &envtest.Environment{
			CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
			ErrorIfCRDPathMissing: true,
			BinaryAssetsDirectory: assetsDirectory(),
		}
		if api.cfg, api.err = api.env.Start(); api.err != nil {
			return
		}
		if api.client, api.err = client.New(api.cfg, client.Options{Scheme: scheme}); api.err != nil {
			return
		}
		api.err = api.client.Create(context.Background(),
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})
	})
	require.NoError(t, api.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	return api.cfg, api.client
}

// assetsDirectory is where the binaries of the API server are when KUBEBUILDER_ASSETS, which `make test` sets, is
// not: the repository's bin/k8s, which `make setup-envtest` fills. The tests then also run from an editor.
func assetsDirectory() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	root := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(root, entry.Name())
		}
	}
	return ""
}

// cluster is a cluster of the tests, by its name and ID. Each test has clusters of its own, so that what one test
// forgets of a cluster is never another test's.
type cluster struct{ name, id string }

// newCluster returns a cluster that no other test has.
func newCluster() cluster {
	name := "cluster-" + rand.String(6)
	return cluster{name: name, id: name + "-id"}
}

// spokeOf is a spoke of a cluster: a manager that runs the controller of a Presence, as the operator's process runs
// it, until it stops.
type spokeOf struct {
	cluster  cluster
	presence *spoke.Presence
	exposure *spoke.Exposure
	manager  ctrl.Manager
	stop     func()
}

// startSpoke starts a spoke of the cluster, which stops when the test ends, unless the test stops it before.
func startSpoke(t *testing.T, c cluster) *spokeOf {
	t.Helper()
	return startSpokeAs(t, func() cluster { return c })
}

// startSpokeAs is startSpoke for a cluster whose name and ID identity gives at each call, as the OperatorConfig
// gives the name.
func startSpokeAs(t *testing.T, identity func() cluster) *spokeOf {
	t.Helper()
	return startSpokeWith(t, identity, false)
}

// startSpokeWith is startSpokeAs that also runs the controller of the reports when reporting is set, with the
// stores that the operator's process gives it.
func startSpokeWith(t *testing.T, identity func() cluster, reporting bool) *spokeOf {
	t.Helper()
	c := identity()
	cfg, _ := startAPI(t)
	presenceCollector(t, workloadsName)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Logger:  testr.New(t),
		// Each test runs a manager of its own, whose controllers have the names of the others'.
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
	})
	require.NoError(t, err)
	store := inventory.NewCRDStore(mgr.GetClient(), mgr.GetCache(), func() string { return identity().name })
	exposure := spoke.NewExposure()
	presence := spoke.NewPresence(store, func(context.Context) (string, string, error) {
		now := identity()
		return now.name, now.id, nil
	}, exposure, mgr.GetClient())
	require.NoError(t, presence.SetupWithManager(mgr))
	if reporting {
		verdicts := inventory.NewCRDVerdictsStore(mgr.GetClient(), func() string { return identity().name })
		reports := spoke.NewReports(mgr, presence, store, verdicts)
		require.NoError(t, reports.SetupWithManager(mgr))
	}
	ctx, cancel := context.WithCancel(logf.IntoContext(context.Background(), testr.New(t)))
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	var once sync.Once
	s := &spokeOf{cluster: c, presence: presence, exposure: exposure, manager: mgr}
	s.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				assert.NoError(t, err, "the manager stops once its context ends")
			case <-time.After(wait):
				assert.Fail(t, "the manager didn't stop")
			}
		})
	}
	t.Cleanup(s.stop)
	return s
}

// digestCount counts the digests of the tests, so that each is new.
var digestCount atomic.Int64

// newDigest returns a digest that no other test runs, and deletes its ImageInventory when the test ends.
func newDigest(t *testing.T) string {
	t.Helper()
	digest := fmt.Sprintf("sha256:%064x", 0x5b0e000+digestCount.Add(1))
	t.Cleanup(func() {
		_, c := startAPI(t)
		obj := &inventoryv1alpha1.ImageInventory{ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(digest)}}
		assert.NoError(t, client.IgnoreNotFound(c.Delete(context.Background(), obj)))
	})
	return digest
}

// running is a workload that runs an image: a Deployment in namespace, with one pod on each of the platforms.
func running(namespace, name string, platforms ...string) evidence.PresenceWorkload {
	w := evidence.PresenceWorkload{APIGroup: appsGroup, Kind: deployment, Namespace: namespace, Name: name,
		UID: "uid-" + namespace + "-" + name}
	for i, platform := range platforms {
		w.Pods = append(w.Pods, evidence.PresencePod{
			Name: fmt.Sprintf("%s-%d", name, i), Node: fmt.Sprintf("node-%d", i), Platform: platform,
		})
	}
	return w
}

// presenceEvent returns the event of a presence collector about the image of digest, pulled from repository, which
// the workloads run.
func presenceEvent(t *testing.T, digest string, workloads ...evidence.PresenceWorkload) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(evidence.TypePresence, subject.Image(digest), evidence.Presence{
		DigestKind: "RepoDigest", Repositories: []string{repository}, Workloads: workloads,
	}, evidence.WithSource("/clusters/cluster-a/collectors/workloads"))
	require.NoError(t, err)
	return e
}

// entryOf returns the entry of the cluster in the ImageInventory of digest, or nil when there is none, also when the
// object doesn't exist.
func entryOf(t *testing.T, c cluster, digest string) *inventoryv1alpha1.ClusterPresence {
	t.Helper()
	_, direct := startAPI(t)
	var obj inventoryv1alpha1.ImageInventory
	err := direct.Get(context.Background(), client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)
	if apierrors.IsNotFound(err) {
		return nil
	}
	require.NoError(t, err)
	for i := range obj.Status.Clusters {
		if obj.Status.Clusters[i].Cluster == c.name {
			return &obj.Status.Clusters[i]
		}
	}
	return nil
}

// present waits until the cluster has an entry for digest, and returns it.
func present(t *testing.T, c cluster, digest string) *inventoryv1alpha1.ClusterPresence {
	t.Helper()
	var entry *inventoryv1alpha1.ClusterPresence
	require.Eventually(t, func() bool {
		entry = entryOf(t, c, digest)
		return entry != nil
	}, wait, tick, "the cluster %s has an entry for %s", c.name, digest)
	return entry
}

// absent waits until the cluster has no entry for digest.
func absent(t *testing.T, c cluster, digest string) {
	t.Helper()
	require.Eventually(t, func() bool { return entryOf(t, c, digest) == nil }, wait, tick,
		"the cluster %s has no entry for %s", c.name, digest)
}

// stays checks that the cluster keeps an entry for digest, or keeps none, for a while.
func stays(t *testing.T, c cluster, digest string, entry bool) {
	t.Helper()
	require.Never(t, func() bool { return (entryOf(t, c, digest) != nil) != entry }, quiet, tick,
		"the entry of the cluster %s for %s stays as it is", c.name, digest)
}

// observe writes an entry of the cluster for digest, as a spoke did before, with one workload.
func observe(t *testing.T, c cluster, digest string) {
	t.Helper()
	_, direct := startAPI(t)
	store := inventory.NewCRDStore(direct, nil, func() string { return c.name })
	require.NoError(t, store.Observe(context.Background(), digest, inventory.Observation{
		Cluster: c.name, ClusterID: c.id, DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		Repositories: []string{repository}, NamespaceCount: 1,
	}))
}

// newCollector creates a Collector with the status that the deployer records for a collector that watches in the
// spoke role and produces the types, and deletes it when the test ends. It returns its name.
func newCollector(t *testing.T, produces ...string) string {
	t.Helper()
	_, direct := startAPI(t)
	c := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: "collector-" + rand.String(6)},
		Spec:       configv1alpha1.CollectorSpec{Package: "artifacts.example/collectors/workloads:0.1.0"},
	}
	require.NoError(t, direct.Create(t.Context(), c))
	t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), c))) })
	c.Status.Capabilities = &configv1alpha1.CollectorCapabilities{
		Roles: []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke},
		Watch: configv1alpha1.CollectorWatchSupported,
	}
	for _, produced := range produces {
		c.Status.Capabilities.Produces = append(c.Status.Capabilities.Produces,
			configv1alpha1.ProducedType{Type: produced, Scope: configv1alpha1.EvidenceScopeSpoke})
	}
	c.Status.Version = ptr.To("0.1.0")
	c.Status.PackageDigest = ptr.To(fmt.Sprintf("sha256:%064x", 0xc0ffee))
	meta.SetStatusCondition(&c.Status.Conditions, metav1.Condition{
		Type: configv1alpha1.ConditionReady, Status: metav1.ConditionUnknown, Reason: configv1alpha1.ReasonNoData,
		Message: notCheckedYet, ObservedGeneration: c.Generation,
	})
	require.NoError(t, direct.Status().Update(t.Context(), c))
	return c.Name
}

// sees waits until the spoke's cache holds the Collector with the capabilities that newCollector recorded. The
// manager watches the Collectors from its start, so a test that makes one afterwards must wait for the cache before it
// relies on what the Collector declares.
func (s *spokeOf) sees(t *testing.T, name string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		var seen configv1alpha1.Collector
		if assert.NoError(c, s.manager.GetClient().Get(t.Context(), client.ObjectKey{Name: name}, &seen)) {
			assert.NotNil(c, seen.Status.Capabilities)
		}
	}, wait, tick, "the cache holds the Collector %s", name)
}

// presenceCollector makes sure a Collector of the name exists that streams presence to the spoke, which presence needs
// before it takes any snapshot to say what runs, and deletes it when the test ends.
func presenceCollector(t *testing.T, name string) {
	t.Helper()
	_, direct := startAPI(t)
	c := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       configv1alpha1.CollectorSpec{Package: "artifacts.example/collectors/workloads:0.1.0"},
	}
	if err := direct.Create(t.Context(), c); err != nil {
		require.True(t, apierrors.IsAlreadyExists(err), "create the Collector %s: %v", name, err)
		return
	}
	t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), c))) })
	c.Status.Capabilities = &configv1alpha1.CollectorCapabilities{
		Roles:    []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke},
		Watch:    configv1alpha1.CollectorWatchSupported,
		Produces: []configv1alpha1.ProducedType{{Type: evidence.TypePresence, Scope: configv1alpha1.EvidenceScopeSpoke}},
	}
	c.Status.Version = ptr.To("0.1.0")
	c.Status.PackageDigest = ptr.To(fmt.Sprintf("sha256:%064x", 0xc0ffee))
	meta.SetStatusCondition(&c.Status.Conditions, metav1.Condition{
		Type: configv1alpha1.ConditionReady, Status: metav1.ConditionUnknown, Reason: configv1alpha1.ReasonNoData,
		Message: notCheckedYet, ObservedGeneration: c.Generation,
	})
	require.NoError(t, direct.Status().Update(t.Context(), c))
}
