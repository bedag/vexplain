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

	// managedBy is the label that the suite puts on the namespaces it creates, so that anyone can tell them.
	managedBy = "app.kubernetes.io/managed-by=vexplain-conformance"
)

// presenceChecks are the checks that a presence collector adds, in the order that they run.
var presenceChecks = []string{
	"Presence", checkPrepared, checkSelected, checkExcluded, checkOwn, checkLabelled,
	"Presence/every event is valid evidence",
	"Presence/every event is of a declared type",
	"Presence/every event's data validates against its type's schema",
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
}

// presenceCollector is a collector of the presence type that reads the pods of a cluster, as a collector of
// vexplain's own does. It applies the scope and the own-pod label from its context, except for its flaws.
type presenceCollector struct {
	reader client.Reader
	flaws  flaws
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
	var namespaces corev1.NamespaceList
	if err := p.reader.List(ctx, &namespaces); err != nil {
		return nil, err
	}
	namespaceLabels := make(map[string]map[string]string, len(namespaces.Items))
	for _, namespace := range namespaces.Items {
		namespaceLabels[namespace.Name] = namespace.Labels
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
		e, err := presenceOf(digest, repositories[digest], running)
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
	return !p.flaws.ignoreScope && !scope.matches(namespaceLabels, pod.Labels)
}

// presenceOf returns the event about an image that the pods run. Each pod is its own workload.
func presenceOf(digest, repository string, pods []corev1.Pod) (cloudevents.Event, error) {
	slices.SortFunc(pods, func(a, b corev1.Pod) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	data := evidence.Presence{DigestKind: "RepoDigest", Repositories: []string{repository}}
	for _, pod := range pods {
		data.Workloads = append(data.Workloads, evidence.PresenceWorkload{
			Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID),
			Pods: []evidence.PresencePod{{Name: pod.Name}},
		})
	}
	return evidence.New(evidence.TypePresence, subject.Image(digest), data, evidence.WithSource(eventSource))
}

// presenceTarget serves a presence collector with the flaws, and returns a target for it with a client of the
// cluster that the collector reads.
func presenceTarget(t *testing.T, f flaws) conformance.Target {
	t.Helper()
	api := startCluster(t)
	return conformance.Target{
		Dial:     serve(t, &presenceCollector{reader: api, flaws: f}),
		Settings: json.RawMessage(`{}`),
		Context:  testContext(),
		Client:   api,
	}
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
	}{
		{"it lists the pods that the scope excludes", flaws{ignoreScope: true}, []string{checkExcluded}},
		{"it lists vexplain's own pods", flaws{ignoreOwnPods: true}, []string{checkOwn}},
		{"it counts the own-pod label in every namespace, and so lets anyone hide a pod", flaws{labelEverywhere: true},
			[]string{checkLabelled}},
		{"it lists the pods of an image that a pod in scope runs, whatever the scope says about them",
			flaws{leakWorkloads: true}, []string{checkExcluded}},
		{"it lists nothing", flaws{listNothing: true}, []string{checkSelected, checkLabelled}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := run(t, presenceTarget(t, test.flaws))

			require.Equal(t, test.failed, rec.failedChecks(), "the checks that failed")
			require.Contains(t, rec.ran(), checkPrepared)
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
	requirePassed(t, run(t, presenceTarget(t, flaws{})), checkPrepared)

	var namespaces corev1.NamespaceList
	selector, err := labels.Parse(managedBy)
	require.NoError(t, err)
	require.NoError(t, api.List(context.Background(), &namespaces, client.MatchingLabelsSelector{Selector: selector}))
	require.NotEmpty(t, namespaces.Items, "the suite labels the namespaces it creates")
	for _, namespace := range namespaces.Items {
		// The API server of the tests runs no namespace controller, so a deleted namespace stays, terminating.
		require.NotNil(t, namespace.DeletionTimestamp, "namespace %s is deleted", namespace.Name)
	}
}
