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

package exposure_test

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	// clusterA and clusterB are two clusters whose spokes stream presence and exposure to the hub.
	clusterA = "cluster-a"
	clusterB = "cluster-b"
	// hub labels the metrics of the stores of the tests, and names the hub's cluster in the calls to the sources.
	hub = "hub"
	// workloadsCollector streams presence, and networkReach exposure, both at version.
	workloadsCollector = "workloads"
	networkReach       = "network-reach"
	version            = "1.0.0"

	// dmzType is the type of the answers of a DMZ's sources, whose data says where an entry point is published.
	dmzType = "ch.example.dmz.publication.v1alpha1"
	// none is the answer of a source that doesn't publish an entry point, and internet of one that publishes it there.
	none     = "None"
	internet = "Internet"
	// The workloads of the tests are Deployments of the group apps, in the namespace team-a.
	deployment = "Deployment"
	appsGroup  = "apps"
	teamA      = "team-a"

	// shopHost is a host of an entry point, and shopIP an address of one, as a source's parameters carry them.
	shopHost = "shop.app.example"
	shopIP   = "192.0.2.10:443"
	// shop and api are the subjects of hosts of entry points, and shopAddress and nodePort of addresses.
	shop        = "host/" + shopHost
	api         = "host/api.app.example"
	shopAddress = "address/" + shopIP
	nodePort    = "address/198.51.100.11:30443"

	// wait bounds a wait for the view or the asker, and poll is how often it looks.
	wait = 30 * time.Second
	poll = 20 * time.Millisecond
)

// scheme holds the kinds of the tests: the built-in ones and the operator's.
var scheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme, configv1alpha1.AddToScheme, inventoryv1alpha1.AddToScheme,
	} {
		if err := add(s); err != nil {
			panic(err)
		}
	}
	return s
}()

// apiServer is the API server of the view's tests. It starts when the first test needs it, and TestMain stops it.
var apiServer struct {
	once   sync.Once
	env    *envtest.Environment
	cfg    *rest.Config
	client client.Client
	err    error
}

func TestMain(m *testing.M) {
	// The view and the asker log through controller-runtime's logger. Their lines would only crowd the output of a test
	// that fails.
	logf.SetLogger(logr.Discard())
	code := m.Run()
	if apiServer.env != nil {
		if err := apiServer.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping the API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// startAPI returns the configuration and a direct client of the API server, which it starts once, with the operator's
// CRDs.
func startAPI(t *testing.T) (*rest.Config, client.Client) {
	t.Helper()
	apiServer.once.Do(func() {
		apiServer.env = &envtest.Environment{
			CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
			ErrorIfCRDPathMissing: true,
			BinaryAssetsDirectory: assetsDirectory(),
		}
		if apiServer.cfg, apiServer.err = apiServer.env.Start(); apiServer.err != nil {
			return
		}
		apiServer.client, apiServer.err = client.New(apiServer.cfg, client.Options{Scheme: scheme})
	})
	require.NoError(t, apiServer.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	return apiServer.cfg, apiServer.client
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

// digestOf returns the n-th digest of the tests.
func digestOf(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}

// workload returns the subject of the Deployment of the name in team-a of the cluster.
func workload(cluster, name string) string {
	return subject.ForWorkload(subject.Workload{Cluster: cluster, Namespace: teamA, Group: appsGroup, Kind: deployment,
		Name: name})
}

// presenceEvent returns the presence of the image of the digest, which the workloads of the subjects run.
func presenceEvent(t *testing.T, digest string, workloads ...string) cloudevents.Event {
	t.Helper()
	data := sdkevidence.Presence{DigestKind: sdkevidence.DigestKindRepoDigest}
	for _, w := range workloads {
		data.Workloads = append(data.Workloads, sdkevidence.PresenceWorkload{Subject: w, APIGroup: appsGroup,
			Kind: deployment, Namespace: teamA, Name: path.Base(w), UID: "uid-" + path.Base(w)})
	}
	return newEvent(t, sdkevidence.TypePresence, subject.Image(digest), data, workloadsCollector)
}

// exposureEvent returns the exposure of a workload, exposed through one entry point whose subjects are points, and
// through the ways in that the unchecked reasons stand for. A workload without either isn't exposed.
func exposureEvent(t *testing.T, workload string, points []string, unchecked ...string) cloudevents.Event {
	t.Helper()
	external := sdkevidence.ExternalExposure{Exposed: len(points)+len(unchecked) > 0, Unchecked: unchecked}
	if len(points) > 0 {
		addresses := make([]string, len(points))
		for i, p := range points {
			_, addresses[i], _ = strings.Cut(p, "/")
		}
		external.EntryPoints = []sdkevidence.EntryPoint{{Addresses: addresses, Port: ptr.To[int32](443), Protocol: "TCP",
			ObjectRef: sdkevidence.ObjectRef{APIGroup: "networking.k8s.io", Kind: "Ingress", Namespace: teamA,
				Name: path.Base(workload)},
			Subjects: points}}
	}
	return newEvent(t, sdkevidence.TypeExposure, workload,
		sdkevidence.Exposure{External: external, InternalReach: "Cluster"}, networkReach)
}

// answerEvent returns the answer of the source of the name about an entry point, of the type, given at a time.
func answerEvent(t *testing.T, eventType, point, publishedTo, collector string, at time.Time) cloudevents.Event {
	t.Helper()
	return newEvent(t, eventType, point, publication{PublishedTo: publishedTo}, collector, sdkevidence.WithTime(at))
}

// publication is the data of an answer of a DMZ's source: where the DMZ publishes the entry point.
type publication struct {
	PublishedTo string `json:"publishedTo"`
}

// newEvent returns evidence of the type about the subject, which the collector of the name delivered.
func newEvent(t *testing.T, eventType, about string, data any, collector string, opts ...sdkevidence.Option) cloudevents.Event {
	t.Helper()
	e, err := sdkevidence.New(eventType, about, data,
		append([]sdkevidence.Option{sdkevidence.WithSource("/hub/collectors/" + collector)}, opts...)...)
	require.NoError(t, err)
	return e
}

// putIn stores an event that the stream of the collector in the cluster delivered.
func putIn(t *testing.T, store evidence.Store, collector, cluster string, e cloudevents.Event) {
	t.Helper()
	require.NoError(t, store.Put(t.Context(), collector, version, e, evidence.InCluster(cluster)))
}
