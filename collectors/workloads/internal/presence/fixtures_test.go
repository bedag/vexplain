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

package presence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// The tests run the collector against an API server of envtest, through a cache of informers of its own, as the
// collector's main runs it against its cluster. No kubelet runs: the tests write the status of each pod as a kubelet
// would. Each test makes namespaces of its own, whose pods run digests of their own, and reads only what the
// collector says about those.

const (
	// wait bounds how long a test waits for what must happen, and tick is how often it looks. quiet is how long a
	// test watches for what must not happen.
	wait  = 20 * time.Second
	tick  = 20 * time.Millisecond
	quiet = time.Second

	// settle is how long the watchers of the tests wait for more changes after one, which is short, so that a test
	// sees a change within a moment.
	settle = 10 * time.Millisecond

	// cluster is the cluster that the context of the tests names.
	cluster = "cluster-a"
	// taskLabel is the label of vexplain's own pods, as vexplain's context names it.
	taskLabel = "vexplain.bedag.ch/task"
	// repository is where the images of the tests come from.
	repository = "artifacts.example/team-a/app"
	// appContainer is the container of the pods of the tests.
	appContainer = "app"
	// byTag is an image ID that names a tag, which is no digest.
	byTag = repository + ":1.0"
	// The names of the pods of the tests.
	appPod, otherAppPod, taggedPod, toolPod = "app-0", "app-1", "tag-0", "tool-0"
	// The allowlisted keys of the tests, a namespace label and a namespace annotation, with their values.
	teamLabel, contactAnnotation = "team", "contact"
	team, contact                = "team-a", "owner@artifacts.example"
	// partOf and costCenter are the allowlisted keys of the workloads' labels in the tests, with values of theirs.
	partOf, costCenter = "app.kubernetes.io/part-of", "example.com/cost-center"
	shop, costCenterA  = "shop", "cc-1"
	// web is the Deployment of the tests, and webPod a pod of its first ReplicaSet. appLabel is the label that selects
	// its pods.
	web, webPod, appLabel = "web", "web-5d8f9-x2k4p", "app"

	// The nodes that the pods of the tests run on, with the platform that their labels say.
	nodeAMD64, platformAMD64 = "node-amd64", "linux/amd64"
	nodeARM64, platformARM64 = "node-arm64", "linux/arm64"
	// nodeBare runs pods too, and its labels say no platform.
	nodeBare = "node-bare"
)

// The containers that the tests name besides appContainer, and the kind of the regular ones.
const (
	setupContainer, proxyContainer, oddContainer, workerContainer = "setup", "proxy", "odd", "worker"
	regularContainer                                              = "Container"
)

// appContainers is what presence names of a pod that runs its image in appContainer alone.
var appContainers = []evidence.PresenceContainer{{Name: appContainer, Kind: regularContainer}}

// api is the API server of the tests, with a direct client and the cache that the watchers read through. It starts
// when the first test needs it, and TestMain stops it.
var api struct {
	once      sync.Once
	env       *envtest.Environment
	client    client.Client
	informers cache.Cache
	stop      context.CancelFunc
	err       error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if api.stop != nil {
		api.stop()
	}
	if api.env != nil {
		if err := api.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping the API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// startAPI returns a client of the API server, and the cache of informers that reads it, which it starts once, with
// the nodes of the tests.
func startAPI(t *testing.T) (client.Client, cache.Cache) {
	t.Helper()
	api.once.Do(func() {
		api.env = &envtest.Environment{BinaryAssetsDirectory: assetsDirectory()}
		cfg, err := api.env.Start()
		if err != nil {
			api.err = err
			return
		}
		if api.client, err = client.New(cfg, client.Options{Scheme: clientgoscheme.Scheme}); err != nil {
			api.err = err
			return
		}
		if api.informers, err = cache.New(cfg, CacheOptions()); err != nil {
			api.err = err
			return
		}
		ctx, stop := context.WithCancel(context.Background())
		api.stop = stop
		go func() { _ = api.informers.Start(ctx) }()
		api.err = createNodes(ctx, api.client)
	})
	require.NoError(t, api.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	return api.client, api.informers
}

// createNodes creates the nodes of the tests.
func createNodes(ctx context.Context, c client.Client) error {
	for name, labels := range map[string]map[string]string{
		nodeAMD64: {corev1.LabelOSStable: "linux", corev1.LabelArchStable: "amd64"},
		nodeARM64: {corev1.LabelOSStable: "linux", corev1.LabelArchStable: "arm64"},
		nodeBare:  nil,
	} {
		if err := c.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}); err != nil {
			return fmt.Errorf("create node %s: %w", name, err)
		}
	}
	return nil
}

// assetsDirectory is where the binaries of the API server are when KUBEBUILDER_ASSETS, which `make test` sets, is
// not: the repository's bin/k8s, which `make setup-envtest` fills. The tests then also run from an editor.
func assetsDirectory() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	root := filepath.Join("..", "..", "..", "..", "bin", "k8s")
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

// digestCount counts the digests of the tests, so that each is new.
var digestCount atomic.Int64

// newDigest returns a digest that no other test runs.
func newDigest() string {
	return fmt.Sprintf("sha256:%064x", 0xd16e57000+digestCount.Add(1))
}

// newNamespace creates a namespace with a name of its own, the labels and the annotations, and deletes it when the
// test ends. It returns the namespace once the cache holds it.
func newNamespace(t *testing.T, labels, annotations map[string]string) *corev1.Namespace {
	t.Helper()
	c, _ := startAPI(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "team-" + rand.String(6), Labels: labels, Annotations: annotations,
	}}
	require.NoError(t, c.Create(t.Context(), ns))
	t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(c.Delete(context.Background(), ns))) })
	cached(t, ns)
	return ns
}

// pod is a pod of the tests: where it runs, and what it is.
type pod struct {
	namespace, name, node string
	labels, annotations   map[string]string
	owner                 *metav1.OwnerReference
	// image is the image of the pod's container, which is repository:1.0 when it is empty.
	image string
}

// imageOrDefault returns the image of the pod's container.
func (p pod) imageOrDefault() string {
	if p.image == "" {
		return repository + ":1.0"
	}
	return p.image
}

// run creates the pod, whose container runs digest, pulled from repository, and writes its status as a kubelet
// would. It returns the pod once the cache holds its status. The deletion of its namespace deletes it.
func (p pod) run(t *testing.T, digest string) *corev1.Pod {
	t.Helper()
	return p.runReporting(t, repository+"@"+digest)
}

// runReporting is run for a container that reports imageID, whatever it is.
func (p pod) runReporting(t *testing.T, imageID string) *corev1.Pod {
	t.Helper()
	created := p.create(t)
	created.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: appContainer, Image: p.imageOrDefault(), ImageID: imageID,
	}}}
	c, _ := startAPI(t)
	require.NoError(t, c.Status().Update(t.Context(), created))
	cached(t, created)
	return created
}

// create creates the pod without a status, as before a kubelet starts it, and returns it once the cache holds it.
func (p pod) create(t *testing.T) *corev1.Pod {
	t.Helper()
	c, _ := startAPI(t)
	created := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: p.namespace, Name: p.name, Labels: p.labels, Annotations: p.annotations,
		},
		Spec: corev1.PodSpec{
			NodeName:   p.node,
			Containers: []corev1.Container{{Name: appContainer, Image: p.imageOrDefault()}},
		},
	}
	if p.owner != nil {
		created.OwnerReferences = []metav1.OwnerReference{*p.owner}
	}
	require.NoError(t, c.Create(t.Context(), created))
	cached(t, created)
	return created
}

// controlledBy is the owner reference of an object that obj controls.
func controlledBy(obj client.Object, apiVersion, kind string) *metav1.OwnerReference {
	return &metav1.OwnerReference{
		APIVersion: apiVersion, Kind: kind, Name: obj.GetName(), UID: obj.GetUID(), Controller: ptr.To(true),
	}
}

// deployment creates the Deployment web in namespace, and the ReplicaSet of it that runs its pods, webPod among them,
// and returns both. The ReplicaSet is in the cache when it returns.
func deployment(t *testing.T, namespace string) (*appsv1.Deployment, *appsv1.ReplicaSet) {
	t.Helper()
	c, _ := startAPI(t)
	const name = web
	labels := map[string]string{appLabel: name}
	template := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: appContainer, Image: repository + ":1.0"}}},
	}
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: template},
	}
	require.NoError(t, c.Create(t.Context(), d))
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: name + "-5d8f9",
			OwnerReferences: []metav1.OwnerReference{*controlledBy(d, "apps/v1", "Deployment")},
		},
		Spec: appsv1.ReplicaSetSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: template},
	}
	require.NoError(t, c.Create(t.Context(), rs))
	cached(t, rs)
	return d, rs
}

// replicaSetOf creates another ReplicaSet of the Deployment d, as a rollout does, and returns it once the cache holds
// it.
func replicaSetOf(t *testing.T, d *appsv1.Deployment, hash string) *appsv1.ReplicaSet {
	t.Helper()
	c, _ := startAPI(t)
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: d.Namespace, Name: d.Name + "-" + hash,
			OwnerReferences: []metav1.OwnerReference{*controlledBy(d, "apps/v1", "Deployment")},
		},
		Spec: appsv1.ReplicaSetSpec{Selector: d.Spec.Selector, Template: d.Spec.Template},
	}
	require.NoError(t, c.Create(t.Context(), rs))
	cached(t, rs)
	return rs
}

// labelled sets the labels of obj's own metadata, and returns once the cache holds them.
func labelled(t *testing.T, obj client.Object, labels map[string]string) {
	t.Helper()
	c, _ := startAPI(t)
	obj.SetLabels(labels)
	require.NoError(t, c.Update(t.Context(), obj))
	cached(t, obj)
}

// cached waits until the cache holds obj as the API server last returned it: as metadata, for every kind but pods,
// which the collector reads whole.
func cached(t *testing.T, obj client.Object) {
	t.Helper()
	_, informers := startAPI(t)
	var into client.Object
	if _, isPod := obj.(*corev1.Pod); isPod {
		into = &corev1.Pod{}
	} else {
		gvk, err := api.client.GroupVersionKindFor(obj)
		require.NoError(t, err)
		metadata := &metav1.PartialObjectMetadata{}
		metadata.SetGroupVersionKind(gvk)
		into = metadata
	}
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		if assert.NoError(c, informers.Get(t.Context(), client.ObjectKeyFromObject(obj), into)) {
			assert.Equal(c, obj.GetResourceVersion(), into.GetResourceVersion())
		}
	}, wait, tick, "the cache holds %s", client.ObjectKeyFromObject(obj))
}

// deletePod deletes the pod at once, as a kubelet confirms it, and waits until the cache no longer holds it.
func deletePod(t *testing.T, p *corev1.Pod) {
	t.Helper()
	c, informers := startAPI(t)
	require.NoError(t, c.Delete(t.Context(), p, client.GracePeriodSeconds(0)))
	require.Eventually(t, func() bool {
		return apierrors.IsNotFound(informers.Get(t.Context(), client.ObjectKeyFromObject(p), &corev1.Pod{}))
	}, wait, tick, "the cache lets go of pod %s", client.ObjectKeyFromObject(p))
}

// everything is the scope that selects every pod, as the context carries it.
var everything = json.RawMessage(`{}`)

// contextFor is the context of a Watch with the scope, and the allowlists of owner attribution when they are set, for
// an operator that runs in operatorNamespace.
func contextFor(operatorNamespace string, scope json.RawMessage, attribution string) collector.Context {
	c := collector.Context{
		Cluster: cluster, OperatorNamespace: operatorNamespace, OwnPodLabel: taskLabel, Scope: scope,
	}
	if attribution != "" {
		c.OwnerAttribution = json.RawMessage(attribution)
	}
	return c
}

// recordingSink is the sink of a Watch of the tests. It records what the Watch sends, checks each event as the SDK's
// sink does, and closes ended at SnapshotEnd.
type recordingSink struct {
	mu        sync.Mutex
	snapshot  []cloudevents.Event
	changes   []change
	ended     chan struct{}
	endedOnce sync.Once
	problems  []string
}

// change is an event or a tombstone after the snapshot.
type change struct {
	event     *cloudevents.Event
	tombstone string // the subject of a tombstone
}

func newRecordingSink() *recordingSink { return &recordingSink{ended: make(chan struct{})} }

func (s *recordingSink) SnapshotStart() error { return nil }

func (s *recordingSink) Event(e cloudevents.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := evidence.Validate(e); err != nil {
		s.problems = append(s.problems, fmt.Sprintf("event %s is not valid evidence: %v", e.Subject(), err))
	}
	if e.Type() != evidence.TypePresence {
		s.problems = append(s.problems, fmt.Sprintf("event %s is of type %s", e.Subject(), e.Type()))
	}
	select {
	case <-s.ended:
		s.changes = append(s.changes, change{event: &e})
	default:
		s.snapshot = append(s.snapshot, e)
	}
	return nil
}

func (s *recordingSink) Tombstone(eventType, about string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if eventType != evidence.TypePresence {
		s.problems = append(s.problems, fmt.Sprintf("a tombstone about %s is of type %s", about, eventType))
	}
	s.changes = append(s.changes, change{tombstone: about})
	return nil
}

func (s *recordingSink) SnapshotEnd() error {
	s.endedOnce.Do(func() { close(s.ended) })
	return nil
}

func (s *recordingSink) SourceChanged(...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.problems = append(s.problems, "the collector sent SourceChanged, and it has no source of its own")
	return nil
}

// watch runs a Watch of w with the context until the test ends, and returns its sink once the snapshot has ended. The
// test fails when the Watch returns before, or with anything but the end of its context, or when the sink recorded a
// problem.
func watch(t *testing.T, w *Watcher, c collector.Context) *recordingSink {
	t.Helper()
	sink, _ := startWatch(t, w, c)
	return sink
}

// startWatch is watch, and also returns the function that ends the Watch and waits until it has returned, which
// runs when the test ends unless the test runs it before.
func startWatch(t *testing.T, w *Watcher, c collector.Context) (*recordingSink, func()) {
	t.Helper()
	sink := newRecordingSink()
	ctx, cancel := context.WithCancel(context.Background())
	// done closes when the Watch has returned, with what it returned in err.
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		err = w.Watch(ctx, collector.WatchRequest{Role: collector.RoleSpoke, Context: c}, sink)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
				assert.ErrorIs(t, err, context.Canceled, "the Watch ends with its context")
			case <-time.After(wait):
				assert.Fail(t, "the Watch didn't end with its context")
			}
			sink.mu.Lock()
			defer sink.mu.Unlock()
			assert.Empty(t, sink.problems)
		})
	}
	select {
	case <-sink.ended:
	case <-done:
		cancel()
		require.FailNow(t, "the Watch ended before its snapshot", "%v", err)
	case <-time.After(wait):
		cancel()
		require.FailNow(t, "the Watch sent no SnapshotEnd")
	}
	t.Cleanup(stop)
	return sink, stop
}

// presenceIn returns what the events say about the image of digest: the data of the last event about it, and false
// when there is none.
func presenceIn(t *testing.T, events []cloudevents.Event, digest string) (evidence.Presence, bool) {
	t.Helper()
	var found *evidence.Presence
	for _, e := range events {
		if e.Subject() != subject.Image(digest) {
			continue
		}
		var data evidence.Presence
		require.NoError(t, json.Unmarshal(e.Data(), &data))
		found = &data
	}
	if found == nil {
		return evidence.Presence{}, false
	}
	return *found, true
}

// inSnapshot returns what the snapshot says about the image of digest, and false when it says nothing.
func (s *recordingSink) inSnapshot(t *testing.T, digest string) (evidence.Presence, bool) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return presenceIn(t, s.snapshot, digest)
}

// changesAbout returns the changes about the image of digest, in order.
func (s *recordingSink) changesAbout(digest string) []change {
	s.mu.Lock()
	defer s.mu.Unlock()
	var about []change
	for _, ch := range s.changes {
		if ch.tombstone == subject.Image(digest) || (ch.event != nil && ch.event.Subject() == subject.Image(digest)) {
			about = append(about, ch)
		}
	}
	return about
}

// nextChange waits for the change about the image of digest that follows the n changes about it so far, and returns
// it.
func (s *recordingSink) nextChange(t *testing.T, digest string, n int) change {
	t.Helper()
	require.Eventually(t, func() bool { return len(s.changesAbout(digest)) > n }, wait, tick,
		"a change about the image %s", digest)
	return s.changesAbout(digest)[n]
}

// dataOf returns the presence that the event of a change says.
func dataOf(t *testing.T, ch change) evidence.Presence {
	t.Helper()
	require.NotNil(t, ch.event, "the change is an event, not a tombstone")
	var data evidence.Presence
	require.NoError(t, json.Unmarshal(ch.event.Data(), &data))
	return data
}

// newWatcher returns a watcher of the tests, which reads the cache of the API server and counts the containers without a digest in
// withoutDigest, which may be nil.
func newWatcher(t *testing.T, withoutDigest *WithoutDigest) *Watcher {
	t.Helper()
	_, informers := startAPI(t)
	return NewWatcher(informers, Options{Name: "workloads", Version: "0.1.0", Settle: settle, WithoutDigest: withoutDigest})
}
