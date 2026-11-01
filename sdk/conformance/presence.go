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

package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// The presence check puts nodes and pods in a cluster, which the collector reads, and checks what the collector
// lists. The names that it uses are its own, and not vexplain's. vexplain tells a collector in its context which
// label marks its own pods, and a collector that has the label in its code, and doesn't read it from the context,
// must fail.
const (
	// ownPodLabel marks the pods that stand in for vexplain's own, such as its scan pods.
	ownPodLabel = "conformance.example/own-pod"
	// runLabel marks the namespaces of one run, which the scope includes. excludedLabel marks one of them that the
	// scope excludes. analyseLabel marks the pods that the scope includes, and skipLabel one of them that it
	// excludes.
	runLabel      = "conformance.example/run"
	excludedLabel = "conformance.example/excluded"
	analyseLabel  = "conformance.example/analyse"
	skipLabel     = "conformance.example/skip"
	// The suite marks the namespaces and the nodes that it creates, so that anyone can tell what a failed run left
	// behind.
	managedByLabel = "app.kubernetes.io/managed-by"
	managedBy      = "vexplain-conformance"
	// The nodes that the pods of the check run on, one for each architecture, with the labels from which a
	// collector reads the platform of a node. No kubelet backs them: they are objects, as the status that the suite
	// sets on each pod is made up. A pod that names its node, as every pod with an image ID does, is for the
	// kubelet of that node alone, so no scheduler places it, and no other node runs it. Two nodes make a collector
	// read the platform of each pod's own node: with one, it could write that platform for every pod.
	osLabel   = "kubernetes.io/os"
	archLabel = "kubernetes.io/arch"
	nodeOS    = "linux"
	archAMD64 = "amd64"
	archARM64 = "arm64"
	// The pods of the check run images of this repository, which doesn't exist.
	repository = "artifacts.example/conformance/"
	// marked is the value of the labels that mark a namespace or a pod.
	marked = "true"
	// imageSelected is the image that two pods of the check run: one in scope, and one that is not.
	imageSelected = "selected"
	// retryInterval is how long the presence check waits between two snapshots, when the collector doesn't list
	// a pod, or know its node, yet.
	retryInterval = 250 * time.Millisecond
)

// The namespaces of the check, by what each is for.
const (
	// nsOperator is vexplain's own namespace: in scope, and the only one where the own-pod label counts.
	nsOperator = "operator"
	// nsIn is in scope.
	nsIn = "in"
	// nsExcluded is selected by includeNamespaces, and then excluded by excludeNamespaces.
	nsExcluded = "excluded"
	// nsOutside is not selected by includeNamespaces.
	nsOutside = "outside"
)

var namespaceRoles = []string{nsOperator, nsIn, nsExcluded, nsOutside}

// nodeArchs are the architectures of the nodes of the check.
var nodeArchs = []string{archAMD64, archARM64}

// rule is what a pod of the check tests.
type rule int

const (
	// ruleSelected pods are in scope, and the collector lists them.
	ruleSelected rule = iota
	// ruleLabelled pods carry the own-pod label outside the operator's namespace, where it counts for nothing, and
	// the collector lists them. Otherwise anyone who can create pods could hide a workload from triage by
	// adding the label.
	ruleLabelled
	// ruleScope pods are out of scope, and the collector leaves them out.
	ruleScope
	// ruleOwn pods are vexplain's own, and the collector leaves them out.
	ruleOwn
)

// standIn is a pod that the check creates.
type standIn struct {
	name, namespace string
	labels          map[string]string
	// arch is the architecture of the node that the pod runs on.
	arch string
	// image names the image that the pod runs. Pods of one image run one digest.
	image string
	rule  rule
	// why says what decides whether the collector lists the pod, for the message of a failure.
	why string
}

// standIns are the pods of the check. Each runs an image of its own, so that a snapshot says which pods the
// collector lists, except for shared, which runs the image of selected: the collector must leave it out of the
// workloads of that image, too. The pods that must be listed run on both nodes: selected and operator-workload on
// the amd64 node, labelled on the arm64 node.
var standIns = []standIn{
	{
		name: "selected", namespace: nsIn, image: imageSelected, rule: ruleSelected, arch: archAMD64,
		labels: map[string]string{analyseLabel: marked},
		why:    "its namespace and its labels pass the scope",
	},
	{
		name: "operator-workload", namespace: nsOperator, image: "operator-workload", rule: ruleSelected, arch: archAMD64,
		labels: map[string]string{analyseLabel: marked},
		why:    "it is in the operator's namespace, where a pod is one of vexplain's own only if it has the own-pod label",
	},
	{
		name: "shared", namespace: nsOutside, image: imageSelected, rule: ruleScope, arch: archARM64,
		labels: map[string]string{analyseLabel: marked},
		why:    "its namespace isn't selected by includeNamespaces, though a pod in scope runs its image",
	},
	{
		name: "labelled", namespace: nsIn, image: "labelled", rule: ruleLabelled, arch: archARM64,
		labels: map[string]string{analyseLabel: marked, ownPodLabel: "conformance"},
		why:    "the own-pod label counts only in the operator's namespace, and this pod is in another",
	},
	{
		name: "own", namespace: nsOperator, image: "own", rule: ruleOwn, arch: archAMD64,
		labels: map[string]string{analyseLabel: marked, ownPodLabel: "conformance"},
		why:    "it carries the own-pod label in the operator's namespace",
	},
	{
		name: "other-namespace", namespace: nsOutside, image: "other-namespace", rule: ruleScope, arch: archAMD64,
		labels: map[string]string{analyseLabel: marked},
		why:    "its namespace isn't selected by includeNamespaces",
	},
	{
		name: "excluded-namespace", namespace: nsExcluded, image: "excluded-namespace", rule: ruleScope, arch: archAMD64,
		labels: map[string]string{analyseLabel: marked},
		why:    "its namespace is excluded by excludeNamespaces, which wins over includeNamespaces",
	},
	{
		name: "not-included", namespace: nsIn, image: "not-included", rule: ruleScope, arch: archAMD64,
		why: "includePods doesn't select it",
	},
	{
		name: "excluded-pod", namespace: nsIn, image: "excluded-pod", rule: ruleScope, arch: archAMD64,
		labels: map[string]string{analyseLabel: marked, skipLabel: marked},
		why:    "excludePods excludes it, which wins over includePods",
	},
}

// scene is what the presence check puts in the cluster, under a token that is unique to one run.
type scene struct {
	api   client.Client
	token string
}

func newScene(api client.Client) *scene { return &scene{api: api, token: rand.String(6)} }

// namespace returns the name of the namespace for a role.
func (sc *scene) namespace(role string) string {
	return "vexplain-conformance-" + sc.token + "-" + role
}

// node returns the name of the node of an architecture.
func (sc *scene) node(arch string) string {
	return "vexplain-conformance-" + sc.token + "-" + arch
}

// digest returns the digest that the pods of an image run.
func (sc *scene) digest(image string) string {
	sum := sha256.Sum256([]byte(sc.token + "/" + image))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// context returns the context for the presence check: the Target's, with the operator namespace, the own-pod label
// and the scope that the check makes its own.
func (sc *scene) context(base collector.Context) collector.Context {
	base.OperatorNamespace = sc.namespace(nsOperator)
	base.OwnPodLabel = ownPodLabel
	base.Scope = sc.scope()
	return base
}

// scope is OperatorConfig.spec.scope for the check, as JSON: it includes the namespaces of this run and the pods
// that are marked, and excludes a namespace and a pod by label. It is written by hand, because the SDK can't
// import the operator's API.
func (sc *scene) scope() json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{
  "includeNamespaces": {"matchLabels": {%q: %q}},
  "excludeNamespaces": {"matchExpressions": [{"key": %q, "operator": "In", "values": [%q]}]},
  "includePods": {"matchLabels": {%q: %q}},
  "excludePods": {"matchExpressions": [{"key": %q, "operator": "Exists"}]}
}`, runLabel, sc.token, excludedLabel, marked, analyseLabel, marked, skipLabel))
}

// create makes the nodes, the namespaces and the pods, which run on the nodes, and sets what a kubelet would
// report: the image of each pod's container, through the status subresource.
func (sc *scene) create(ctx context.Context) error {
	for _, arch := range nodeArchs {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: sc.node(arch), Labels: map[string]string{
			managedByLabel: managedBy, osLabel: nodeOS, archLabel: arch,
		}}}
		if err := sc.api.Create(ctx, node); err != nil {
			return fmt.Errorf("creating node %s: %w", node.Name, err)
		}
	}
	for _, role := range namespaceRoles {
		labels := map[string]string{managedByLabel: managedBy}
		if role != nsOutside {
			labels[runLabel] = sc.token
		}
		if role == nsExcluded {
			labels[excludedLabel] = marked
		}
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: sc.namespace(role), Labels: labels}}
		if err := sc.api.Create(ctx, namespace); err != nil {
			return fmt.Errorf("creating namespace %s: %w", namespace.Name, err)
		}
	}
	for _, in := range standIns {
		pod := &corev1.Pod{
			// The labels are a copy: the client decodes the answer of the API server into the pod.
			ObjectMeta: metav1.ObjectMeta{Name: in.name, Namespace: sc.namespace(in.namespace), Labels: maps.Clone(in.labels)},
			Spec: corev1.PodSpec{
				NodeName:   sc.node(in.arch),
				Containers: []corev1.Container{{Name: "app", Image: repository + in.image + ":latest"}},
			},
		}
		if err := sc.api.Create(ctx, pod); err != nil {
			return fmt.Errorf("creating pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:    "app",
			Image:   repository + in.image + ":latest",
			ImageID: repository + in.image + "@" + sc.digest(in.image),
		}}
		if err := sc.api.Status().Update(ctx, pod); err != nil {
			return fmt.Errorf("setting the image ID of pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

// cleanup deletes the namespaces, and with them everything in them, and the nodes.
func (sc *scene) cleanup(ctx context.Context) error {
	var failed []error
	objects := make([]client.Object, 0, len(nodeArchs)+len(namespaceRoles))
	for _, arch := range nodeArchs {
		objects = append(objects, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: sc.node(arch)}})
	}
	for _, role := range namespaceRoles {
		objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: sc.namespace(role)}})
	}
	for _, object := range objects {
		if err := sc.api.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) {
			failed = append(failed, err)
		}
	}
	return errors.Join(failed...)
}

// listing is what the events of a snapshot say about pods.
type listing struct {
	// images are the digests that an event is about.
	images map[string]bool
	// pods are the pods that an event lists, as workloads or as the pods of a workload.
	pods map[podRef]bool
	// details are what an event says about the pods of a workload: the node and the platform of each.
	details map[podRef]evidence.PresencePod
}

type podRef struct{ namespace, name string }

// listingOf reads the presence events of a snapshot.
func listingOf(events []received) listing {
	found := listing{
		images:  make(map[string]bool),
		pods:    make(map[podRef]bool),
		details: make(map[podRef]evidence.PresencePod),
	}
	for _, e := range events {
		if e.err != nil || e.event.Type() != evidence.TypePresence {
			continue
		}
		about, err := subjects.Parse(e.event.Subject())
		if err != nil || about.Kind != subjects.KindImage {
			continue
		}
		found.images[about.Digest] = true
		var data evidence.Presence
		if json.Unmarshal(e.event.Data(), &data) != nil {
			continue
		}
		for _, workload := range data.Workloads {
			found.pods[podRef{workload.Namespace, workload.Name}] = true
			for _, pod := range workload.Pods {
				ref := podRef{workload.Namespace, pod.Name}
				found.pods[ref] = true
				found.details[ref] = pod
			}
		}
	}
	return found
}

// of returns the pods of the check that test one of the rules.
func (sc *scene) of(rules ...rule) []standIn {
	var pods []standIn
	for _, in := range standIns {
		if slices.Contains(rules, in.rule) {
			pods = append(pods, in)
		}
	}
	return pods
}

// missing lists the pods that must be listed, according to the rules, and whose image no event is about.
func (sc *scene) missing(found listing, rules ...rule) []string {
	var problems []string
	for _, in := range sc.of(rules...) {
		if !found.images[sc.digest(in.image)] {
			problems = append(problems, fmt.Sprintf("no event is about the image of pod %s/%s, which the collector must "+
				"list: %s", sc.namespace(in.namespace), in.name, in.why))
		}
	}
	return problems
}

// leaks lists the pods that must be left out, according to the rules, and that an event lists, or whose image an
// event is about, when no pod that must be listed runs it.
func (sc *scene) leaks(found listing, rules ...rule) []string {
	var problems []string
	for _, in := range sc.of(rules...) {
		ref := podRef{sc.namespace(in.namespace), in.name}
		if found.pods[ref] {
			problems = append(problems, fmt.Sprintf("an event lists pod %s/%s, which the collector must leave out: %s",
				ref.namespace, ref.name, in.why))
		}
		if found.images[sc.digest(in.image)] && len(sc.runningImage(in.image, ruleSelected, ruleLabelled)) == 0 {
			problems = append(problems, fmt.Sprintf("an event is about the image of pod %s/%s, which only pods that the "+
				"collector must leave out run: %s", ref.namespace, ref.name, in.why))
		}
	}
	return problems
}

// placement lists the pods that must be listed, according to the rules, and whose image an event is about, when no
// event gives the node that the pod itself runs on and the platform of that node, from the labels
// kubernetes.io/os and kubernetes.io/arch. The hub uses the platforms of presence to notice an image that runs on
// a platform that it has not seen. A pod whose image no event is about is for missing to list.
func (sc *scene) placement(found listing, rules ...rule) []string {
	var problems []string
	for _, in := range sc.of(rules...) {
		if !found.images[sc.digest(in.image)] {
			continue
		}
		name := sc.namespace(in.namespace) + "/" + in.name
		node, platform := sc.node(in.arch), nodeOS+"/"+in.arch
		pod, listed := found.details[podRef{sc.namespace(in.namespace), in.name}]
		switch {
		case !listed:
			problems = append(problems, fmt.Sprintf("an event is about the image of pod %s, and doesn't list the pod among "+
				"the pods of a workload, with its node and platform", name))
		case pod.Node == "":
			problems = append(problems, fmt.Sprintf("an event lists pod %s without its node, which is %s", name, node))
		case pod.Node != node:
			problems = append(problems, fmt.Sprintf("an event lists pod %s on the node %q, and it runs on %s", name, pod.Node,
				node))
		case pod.Platform == "":
			problems = append(problems, fmt.Sprintf("an event lists pod %s without its platform, which its node's labels %s "+
				"and %s say is %s", name, osLabel, archLabel, platform))
		case pod.Platform != platform:
			problems = append(problems, fmt.Sprintf("an event lists pod %s with the platform %q, and its node's labels %s "+
				"and %s say %s", name, pod.Platform, osLabel, archLabel, platform))
		}
	}
	return problems
}

// runningImage returns the pods of the check that run an image, and test one of the rules.
func (sc *scene) runningImage(image string, rules ...rule) []standIn {
	return slices.DeleteFunc(sc.of(rules...), func(in standIn) bool { return in.image != image })
}

// presenceChecks checks a collector of the presence type: it applies the scope, counts the label of vexplain's own
// pods only in vexplain's namespace, as its context says, and gives the node and the platform of each pod that it
// lists. It creates two nodes and pods that the collector reads, and checks the snapshot that the collector then
// delivers.
func (s *session) presenceChecks(r Reporter) {
	r.Helper()
	var (
		sc     *scene
		events []received
		found  listing
	)
	defer func() {
		if sc == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.lim.call)
		defer cancel()
		if err := sc.cleanup(ctx); err != nil {
			r.Errorf("deleting the namespaces that the check created: %v", err)
		}
	}()
	prepared := r.Run("prepares the cluster and takes a snapshot", func(r Reporter) {
		s.presencePrerequisites(r)
		sc = newScene(s.target.Client)
		ctx, cancel := context.WithTimeout(context.Background(), s.lim.call)
		defer cancel()
		if err := sc.create(ctx); err != nil {
			r.Fatalf("%v", err)
		}
		events, found = s.presenceSnapshot(r, sc)
	})
	if !prepared {
		return
	}
	r.Run("lists the pods that the scope selects", func(r Reporter) { report(r, sc.missing(found, ruleSelected)) })
	r.Run("leaves out the pods that the scope excludes", func(r Reporter) { report(r, sc.leaks(found, ruleScope)) })
	r.Run("leaves out vexplain's own pods", func(r Reporter) { report(r, sc.leaks(found, ruleOwn)) })
	r.Run("counts the own-pod label only in the operator's namespace", func(r Reporter) {
		report(r, sc.missing(found, ruleLabelled))
	})
	r.Run("gives the node and the platform of each pod that it lists", func(r Reporter) {
		report(r, sc.placement(found, ruleSelected, ruleLabelled))
	})
	s.eventChecks(r, events)
}

// presencePrerequisites ends the check when it can't run: it needs a client of the cluster that the collector
// reads, and a collector that delivers presence from a Watch of the spoke role, where the pods are.
func (s *session) presencePrerequisites(r Reporter) {
	r.Helper()
	switch {
	case s.target.Client == nil:
		r.Fatalf("a collector that produces %s is checked against a cluster, and its conformance needs a Kubernetes "+
			"client: set Target.Client to a client of the cluster that the collector reads", evidence.TypePresence)
	case !s.caps.GetWatches():
		r.Fatalf("a collector that produces %s delivers it from Watch, and this one says that it doesn't watch",
			evidence.TypePresence)
	case !slices.Contains(s.caps.GetRoles(), collectorv1alpha1.Role_ROLE_SPOKE):
		r.Fatalf("a collector that produces %s takes the spoke role, where the pods are, and this one doesn't",
			evidence.TypePresence)
	}
}

// presenceSnapshot takes a snapshot of the spoke's Watch, with the context of the check. A collector that reads
// through a cache may not list a pod, or know its node, that was created just now, so it takes another snapshot
// until the pods that must be listed are, with their nodes and platforms, or the time is up. A pod that must be
// left out and is listed is never waited for.
func (s *session) presenceSnapshot(r Reporter, sc *scene) ([]received, listing) {
	r.Helper()
	deadline := time.Now().Add(s.lim.presence)
	c := sc.context(s.target.Context)
	for {
		snap := s.snapshot(collectorv1alpha1.Role_ROLE_SPOKE, c, s.target.Settings)
		if snap.start != "" {
			r.Fatalf("%s", snap.start)
		}
		if snap.end != "" {
			r.Fatalf("%s", snap.end)
		}
		found := listingOf(snap.events)
		incomplete := len(sc.missing(found, ruleSelected, ruleLabelled)) > 0 ||
			len(sc.placement(found, ruleSelected, ruleLabelled)) > 0
		waiting := incomplete && len(sc.leaks(found, ruleScope, ruleOwn)) == 0 && time.Now().Before(deadline)
		if !waiting {
			return snap.events, found
		}
		time.Sleep(retryInterval)
	}
}
