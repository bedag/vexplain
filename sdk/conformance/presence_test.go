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

package conformance_test

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	checkPrepared = "Presence/prepares the cluster and takes a snapshot"
	checkSelected = "Presence/lists the pods that the scope selects"
	checkExcluded = "Presence/leaves out the pods that the scope excludes"
	checkOwn      = "Presence/leaves out vexplain's own pods"
	checkLabelled = "Presence/counts the own-pod label only in the operator's namespace"
	checkNode     = "Presence/gives the node and the platform of each pod that it lists"
	checkContains = "Presence/names the containers that the pods run, when it names any"
	checkSchema   = "Presence/every event's data validates against its type's schema"

	// managedBy is the label that the suite puts on the namespaces and the node it creates, so that anyone can tell
	// them, as a selector.
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "vexplain-conformance"
	managedBy      = managedByLabel + "=" + managedByValue

	// The labels of a node that say its platform.
	osLabel, archLabel = "kubernetes.io/os", "kubernetes.io/arch"
)

// presenceChecks are the checks that a presence collector adds, in the order that they run.
var presenceChecks = []string{
	"Presence", checkPrepared, checkSelected, checkExcluded, checkOwn, checkLabelled, checkNode, checkContains,
	"Presence/every event is valid evidence",
	"Presence/every event is of a declared type",
	checkSchema,
}

// cluster is the API server of the presence tests. It starts when the first test needs it, and TestMain stops it.
var cluster struct {
	once   sync.Once
	env    *envtest.Environment
	client client.Client
	err    error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if cluster.env != nil {
		if err := cluster.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping the API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// tail returns the last n of the names, or all of them when there are fewer.
func tail(names []string, n int) iter.Seq[string] {
	return slices.Values(names[max(0, len(names)-n):])
}

// startCluster returns a client of the API server, which it starts once.
func startCluster(t *testing.T) client.Client {
	t.Helper()
	cluster.once.Do(func() {
		cluster.env = &envtest.Environment{BinaryAssetsDirectory: assetsDirectory()}
		cfg, err := cluster.env.Start()
		if err == nil {
			cluster.client, err = client.New(cfg, client.Options{})
		}
		cluster.err = err
	})
	require.NoError(t, cluster.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	return cluster.client
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

// flaws are the ways in which a presence collector can break what its context asks of it, and ways in which it can
// fail to be one.
type flaws struct {
	ignoreScope     bool // lists the pods of any namespace, whatever the scope says
	ignoreOwnPods   bool // lists vexplain's own pods
	labelEverywhere bool // counts the own-pod label in every namespace, so that anyone can hide a workload with it
	leakWorkloads   bool // applies the scope to the images, and then lists every pod that runs one of them
	listNothing     bool
	doesNotWatch    bool
	hubOnly         bool

	// The presence of a pod names its node and the node's platform, from the labels kubernetes.io/os and
	// kubernetes.io/arch. These flaws leave them out, or get them wrong.
	omitNode      bool // names neither the node nor the platform
	omitPlatform  bool // names the node, and not the platform
	wrongNode     bool // names a node that the pod doesn't run on
	wrongPlatform bool // names a platform that the node's labels don't say
	workloadsOnly bool // lists a pod as a workload, and the pods of a workload not at all

	// The presence of a pod may name its containers: a kind that the schema doesn't know breaks the event.
	unknownContainerKind bool // names a container of a kind that presence doesn't have
	wrongContainerName   bool // names a container that the pod doesn't have

	// Two ways to pass the checks above without doing what they ask for.
	hardCodePlatform      bool // names linux/amd64 for every pod, and never reads its node's labels
	skipOperatorNamespace bool // takes every pod of the operator's namespace for vexplain's own, label or not

	// A collector that reads through a cache doesn't see what was created just now. For the first snapshots of the
	// presence check, these collectors list no pod at all, or know no node.
	latePods  int
	lateNodes int
}

// presenceCollector is a collector of the presence type that reads the pods of a cluster, as a collector of
// vexplain's own does. It applies the scope and the own-pod label from its context, except for its flaws.
type presenceCollector struct {
	reader client.Reader
	flaws  flaws

	mu sync.Mutex
	// managed are the nodes that the suite made, which the collector read in its last snapshot.
	managed []string
	// checks counts the snapshots that the presence check took: those with a scope that includes namespaces.
	checks int
}

// presenceSnapshots returns how many snapshots the presence check has taken of the collector.
func (p *presenceCollector) presenceSnapshots() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checks
}

// managedNodes returns the nodes that the suite made, which the collector read in its last snapshot.
func (p *presenceCollector) managedNodes() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.managed)
}

func (p *presenceCollector) Info() collector.Info {
	return collector.Info{Name: "pods", Version: collectorVersion}
}

func (p *presenceCollector) Capabilities() collector.Capabilities {
	schema, _ := evidence.Schema(evidence.TypePresence)
	roles := []collector.Role{collector.RoleSpoke}
	if p.flaws.hubOnly {
		roles = []collector.Role{collector.RoleHub}
	}
	return collector.Capabilities{
		Roles:    roles,
		Produces: []collector.EvidenceType{{Type: evidence.TypePresence, Scope: collector.ScopeSpoke, Schema: schema}},
		Watches:  !p.flaws.doesNotWatch,
		Permissions: []collector.Permission{{
			APIGroups: []string{""}, Resources: []string{"pods", "namespaces"}, Verbs: []string{"list", "watch"},
		}},
	}
}

func (p *presenceCollector) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	events, err := p.snapshot(ctx, req.Context)
	if err != nil {
		return err
	}
	if err := sink.SnapshotStart(); err != nil {
		return err
	}
	for _, e := range events {
		if err := sink.Event(e); err != nil {
			return err
		}
	}
	if err := sink.SnapshotEnd(); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

// selectors is OperatorConfig.spec.scope.
type selectors struct {
	IncludeNamespaces *metav1.LabelSelector `json:"includeNamespaces"`
	ExcludeNamespaces *metav1.LabelSelector `json:"excludeNamespaces"`
	IncludePods       *metav1.LabelSelector `json:"includePods"`
	ExcludePods       *metav1.LabelSelector `json:"excludePods"`
}

// allows says whether the labels pass an include and an exclude selector. A selector that is not there includes
// everything, or excludes nothing. The exclude selector wins.
func allows(include, exclude *metav1.LabelSelector, set map[string]string) bool {
	if exclude != nil {
		selector, err := metav1.LabelSelectorAsSelector(exclude)
		if err != nil || selector.Matches(labels.Set(set)) {
			return false
		}
	}
	if include == nil {
		return true
	}
	selector, err := metav1.LabelSelectorAsSelector(include)
	return err == nil && selector.Matches(labels.Set(set))
}

func (s selectors) matches(namespace, pod map[string]string) bool {
	return allows(s.IncludeNamespaces, s.ExcludeNamespaces, namespace) && allows(s.IncludePods, s.ExcludePods, pod)
}

// digestOf returns the digest and the repository that a container runtime reports as an image ID.
func digestOf(imageID string) (digest, repository string, ok bool) {
	repository, digest, ok = strings.Cut(imageID, "@")
	return digest, repository, ok && strings.HasPrefix(digest, "sha256:")
}

func (p *presenceCollector) snapshot(ctx context.Context, c collector.Context) ([]cloudevents.Event, error) {
	if p.flaws.listNothing {
		return nil, nil
	}
	var scope selectors
	if len(c.Scope) > 0 {
		if err := json.Unmarshal(c.Scope, &scope); err != nil {
			return nil, err
		}
	}
	// The presence check is the only caller whose scope includes namespaces. It can't see what is new to a cache.
	flaws, late := p.flaws, 0
	if scope.IncludeNamespaces != nil {
		p.mu.Lock()
		p.checks++
		late = p.checks
		p.mu.Unlock()
	}
	if late > 0 && late <= flaws.latePods {
		return nil, nil
	}
	flaws.omitNode = flaws.omitNode || (late > 0 && late <= flaws.lateNodes)
	var namespaces corev1.NamespaceList
	if err := p.reader.List(ctx, &namespaces); err != nil {
		return nil, err
	}
	namespaceLabels := make(map[string]map[string]string, len(namespaces.Items))
	for _, namespace := range namespaces.Items {
		namespaceLabels[namespace.Name] = namespace.Labels
	}
	platforms, err := p.platforms(ctx)
	if err != nil {
		return nil, err
	}
	var pods corev1.PodList
	if err := p.reader.List(ctx, &pods); err != nil {
		return nil, err
	}
	// listed holds, for each digest, the pods that the collector lists as running it, and every pod that runs it.
	listed, every := make(map[string][]corev1.Pod), make(map[string][]corev1.Pod)
	repositories := make(map[string]string)
	for _, pod := range pods.Items {
		skip := p.skips(c, scope, namespaceLabels[pod.Namespace], pod)
		for _, status := range pod.Status.ContainerStatuses {
			digest, repository, ok := digestOf(status.ImageID)
			if !ok {
				continue
			}
			repositories[digest] = repository
			every[digest] = append(every[digest], pod)
			if !skip {
				listed[digest] = append(listed[digest], pod)
			}
		}
	}
	var events []cloudevents.Event
	for digest, running := range listed {
		if p.flaws.leakWorkloads {
			running = every[digest]
		}
		e, err := presenceOf(digest, repositories[digest], running, platforms, flaws)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

// skips says whether the collector leaves a pod out: it is one of vexplain's own, or the scope excludes it.
func (p *presenceCollector) skips(c collector.Context, scope selectors, namespaceLabels map[string]string,
	pod corev1.Pod) bool {
	_, labelled := pod.Labels[c.OwnPodLabel]
	own := labelled && c.OwnPodLabel != "" && (p.flaws.labelEverywhere ||
		(c.OperatorNamespace != "" && pod.Namespace == c.OperatorNamespace))
	if own && !p.flaws.ignoreOwnPods {
		return true
	}
	if p.flaws.skipOperatorNamespace && c.OperatorNamespace != "" && pod.Namespace == c.OperatorNamespace {
		return true
	}
	return !p.flaws.ignoreScope && !scope.matches(namespaceLabels, pod.Labels)
}

// platforms returns the platform of each node, as os/arch from the labels kubernetes.io/os and kubernetes.io/arch,
// and remembers the nodes that the suite made.
func (p *presenceCollector) platforms(ctx context.Context) (map[string]string, error) {
	var nodes corev1.NodeList
	if err := p.reader.List(ctx, &nodes); err != nil {
		return nil, err
	}
	platforms := make(map[string]string, len(nodes.Items))
	var managed []string
	for _, node := range nodes.Items {
		if node.Labels[osLabel] != "" && node.Labels[archLabel] != "" {
			platforms[node.Name] = node.Labels[osLabel] + "/" + node.Labels[archLabel]
		}
		if node.Labels[managedByLabel] == managedByValue {
			managed = append(managed, node.Name)
		}
	}
	p.mu.Lock()
	p.managed = managed
	p.mu.Unlock()
	return platforms, nil
}

// presenceOf returns the event about an image that the pods run. Each pod is its own workload, and its pods list
// it, with its node and the node's platform, except for the flaws.
func presenceOf(digest, repository string, pods []corev1.Pod, platforms map[string]string,
	flaws flaws) (cloudevents.Event, error) {
	slices.SortFunc(pods, func(a, b corev1.Pod) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	data := evidence.Presence{DigestKind: "RepoDigest", Repositories: []string{repository}}
	for _, pod := range pods {
		running := evidence.PresencePod{Name: pod.Name, Node: pod.Spec.NodeName, Platform: platforms[pod.Spec.NodeName]}
		switch {
		case flaws.omitNode:
			running.Node, running.Platform = "", ""
		case flaws.omitPlatform:
			running.Platform = ""
		case flaws.wrongNode:
			running.Node = "node-b"
		case flaws.wrongPlatform:
			running.Platform = "linux/arm64"
		case flaws.hardCodePlatform:
			running.Platform = "linux/amd64"
		}
		for _, container := range pod.Spec.Containers {
			kind := "Container"
			if flaws.unknownContainerKind {
				kind = "Ephemeral"
			}
			name := container.Name
			if flaws.wrongContainerName {
				name = "other"
			}
			running.Containers = append(running.Containers, evidence.PresenceContainer{Name: name, Kind: kind})
		}
		workload := evidence.PresenceWorkload{
			Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID),
			Pods: []evidence.PresencePod{running},
		}
		if flaws.workloadsOnly {
			workload.Pods = nil
		}
		data.Workloads = append(data.Workloads, workload)
	}
	return evidence.New(evidence.TypePresence, subject.Image(digest), data, evidence.WithSource(eventSource))
}

// presenceTarget serves a presence collector with the flaws, and returns a target for it with a client of the
// cluster that the collector reads.
func presenceTarget(t *testing.T, f flaws) conformance.Target {
	t.Helper()
	target, _ := presenceTargetOf(t, f)
	return target
}

// presenceTargetOf is presenceTarget, and returns the collector too.
func presenceTargetOf(t *testing.T, f flaws) (conformance.Target, *presenceCollector) {
	t.Helper()
	api := startCluster(t)
	c := &presenceCollector{reader: api, flaws: f}
	return conformance.Target{
		Dial:     serve(t, c),
		Settings: json.RawMessage(`{}`),
		Context:  testContext(),
		Client:   api,
	}, c
}

func TestAPresenceCollectorThatConformsPasses(t *testing.T) {
	rec := run(t, presenceTarget(t, flaws{}))

	requirePassed(t, rec, presenceChecks...)
	require.Equal(t, presenceChecks, slices.Collect(tail(rec.ran(), len(presenceChecks))), "the presence checks come last")
}

func TestEachBreakOfThePresenceContractFailsItsCheck(t *testing.T) {
	tests := []struct {
		name   string
		flaws  flaws
		failed []string
		// why is what the first failed check says, when the row says it.
		why string
	}{
		{"it lists the pods that the scope excludes", flaws{ignoreScope: true}, []string{checkExcluded}, ""},
		{"it lists vexplain's own pods", flaws{ignoreOwnPods: true}, []string{checkOwn}, ""},
		{"it counts the own-pod label in every namespace, and so lets anyone hide a pod", flaws{labelEverywhere: true},
			[]string{checkLabelled}, ""},
		{"it lists the pods of an image that a pod in scope runs, whatever the scope says about them",
			flaws{leakWorkloads: true}, []string{checkExcluded}, ""},
		{"it lists nothing", flaws{listNothing: true}, []string{checkSelected, checkLabelled}, ""},
		{"it names neither the node nor the platform of the pods that it lists", flaws{omitNode: true},
			[]string{checkNode}, "without its node"},
		{"it names the node of a pod and not its platform", flaws{omitPlatform: true},
			[]string{checkNode}, "without its platform"},
		{"it names a node that the pod doesn't run on", flaws{wrongNode: true},
			[]string{checkNode}, `"node-b"`},
		{"it names a platform that the labels of the node don't say", flaws{wrongPlatform: true},
			[]string{checkNode}, `"linux/arm64"`},
		{"it lists a pod as a workload and not among the pods of a workload", flaws{workloadsOnly: true},
			[]string{checkNode}, "among the pods"},
		{"it names linux/amd64 as the platform of every pod, and never reads the labels of the node",
			flaws{hardCodePlatform: true}, []string{checkNode}, "linux/arm64"},
		{"it names a container of a kind that presence doesn't have", flaws{unknownContainerKind: true},
			[]string{"Watch/spoke/every event's data validates against its type's schema", checkContains, checkSchema}, ""},
		{"it names a container that the pod doesn't have", flaws{wrongContainerName: true},
			[]string{checkContains}, "{other Container}"},
		{"it takes every pod of the operator's namespace for vexplain's own, and not only those with the label",
			flaws{skipOperatorNamespace: true}, []string{checkSelected}, "operator's namespace"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := run(t, presenceTarget(t, test.flaws))

			require.Equal(t, test.failed, rec.failedChecks(), "the checks that failed")
			require.Contains(t, rec.ran(), checkPrepared)
			if test.why != "" {
				require.Contains(t, rec.messages(test.failed[0]), test.why)
			}
		})
	}
}

func TestThePresenceCheckWaitsForWhatACacheHasntSeen(t *testing.T) {
	tests := []struct {
		name  string
		flaws flaws
	}{
		{"a pod that the cache hasn't seen", flaws{latePods: 2}},
		{"a node that the cache hasn't seen", flaws{lateNodes: 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, c := presenceTargetOf(t, test.flaws)

			rec := newRecorder()
			conformance.RunWithin(rec, target, slowWait, slowWait)

			requirePassed(t, rec, presenceChecks...)
			require.Equal(t, 3, c.presenceSnapshots(), "the first two snapshots lacked what the cache hadn't seen")
		})
	}
}

func TestThePresenceCheckSaysWhatItNeeds(t *testing.T) {
	tests := []struct {
		name   string
		change func(target *conformance.Target)
		flaws  flaws
		why    string
	}{
		{"a Kubernetes client", func(target *conformance.Target) { target.Client = nil }, flaws{}, "Kubernetes client"},
		{"a collector that watches", func(*conformance.Target) {}, flaws{doesNotWatch: true}, "watch"},
		{"the spoke role", func(*conformance.Target) {}, flaws{hubOnly: true}, "spoke"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := presenceTarget(t, test.flaws)
			test.change(&target)

			rec := run(t, target)

			require.Equal(t, []string{checkPrepared}, rec.failedChecks())
			require.Contains(t, rec.messages(checkPrepared), test.why)
			require.NotContains(t, rec.ran(), checkSelected, "the checks on the snapshot don't run without one")
		})
	}
}

func TestThePresenceCheckLeavesNothingBehind(t *testing.T) {
	api := startCluster(t)
	target, pods := presenceTargetOf(t, flaws{})
	requirePassed(t, run(t, target), checkPrepared)

	var namespaces corev1.NamespaceList
	selector, err := labels.Parse(managedBy)
	require.NoError(t, err)
	require.NoError(t, api.List(context.Background(), &namespaces, client.MatchingLabelsSelector{Selector: selector}))
	require.NotEmpty(t, namespaces.Items, "the suite labels the namespaces it creates")
	for _, namespace := range namespaces.Items {
		// The API server of the tests runs no namespace controller, so a deleted namespace stays, terminating.
		require.NotNil(t, namespace.DeletionTimestamp, "namespace %s is deleted", namespace.Name)
	}

	nodes := pods.managedNodes()
	require.Len(t, nodes, 2, "the pods of the check run on two nodes that the suite made, and the collector read them")
	for _, name := range nodes {
		err := api.Get(context.Background(), client.ObjectKey{Name: name}, &corev1.Node{})
		require.True(t, apierrors.IsNotFound(err), "node %s is deleted: %v", name, err)
	}
}
