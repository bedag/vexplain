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
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/scope"
	"github.com/bedag/vexplain/sdk/workloads"
)

// Why a container in scope is skipped: the collector can't report the image that it runs.
const (
	// reasonUnparsable is a container whose image ID is set and is no digest.
	reasonUnparsable = "Unparsable"
	// reasonPending is a container that has no image ID yet, as while its image is pulled.
	reasonPending = "Pending"
)

// reasons are the reasons for which a container is skipped, sorted.
var reasons = []string{reasonPending, reasonUnparsable}

// The kinds of digest that presence tells apart.
const (
	// digestKindRepo is a digest that a registry can serve: the container runtime names its repository.
	digestKindRepo = "RepoDigest"
	// digestKindImageID is the digest of an image's configuration, which no registry serves.
	digestKindImageID = "ImageID"
)

// The kinds that the collector reads as metadata only: it needs their labels, annotations and owner references, and
// a cache of the whole objects would hold what it never reads, such as the pod templates of every ReplicaSet and Job
// of the cluster. ResolveOwner reads ReplicaSets and Jobs as metadata too.
var (
	namespaceKind  = corev1.SchemeGroupVersion.WithKind("Namespace")
	nodeKind       = corev1.SchemeGroupVersion.WithKind("Node")
	replicaSetKind = appsv1.SchemeGroupVersion.WithKind("ReplicaSet")
	jobKind        = batchv1.SchemeGroupVersion.WithKind("Job")
)

// rules are what the context of a Watch says about the pods: which count, which are vexplain's own, and what an event
// copies of them.
type rules struct {
	scope *scope.Matcher
	// ownPodLabel marks vexplain's own pods, and counts only in operatorNamespace.
	ownPodLabel, operatorNamespace string
	allow                          allowlists
}

// allowlists are the allowlists of owner attribution, OperatorConfig's spec.ownerAttribution: the keys of the labels
// and annotations that an event copies. Owner data is copied, and never interpreted.
type allowlists struct {
	NamespaceLabels      []string `json:"namespaceLabels,omitempty"`
	NamespaceAnnotations []string `json:"namespaceAnnotations,omitempty"`
	WorkloadLabels       []string `json:"workloadLabels,omitempty"`
}

// rulesOf reads the rules from the context of a Watch. It refuses a scope or allowlists that it can't read fully: a
// field that it doesn't know could leave pods out, or keep owner data in.
func rulesOf(c collector.Context) (rules, error) {
	matcher, err := scope.Parse(c.Scope)
	if err != nil {
		return rules{}, err
	}
	var allow allowlists
	if raw := bytes.TrimSpace(c.OwnerAttribution); len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&allow); err != nil {
			return rules{}, fmt.Errorf("read the allowlists of owner attribution: %w", err)
		}
		if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
			return rules{}, errors.New("read the allowlists of owner attribution: more JSON follows them")
		}
	}
	return rules{scope: matcher, ownPodLabel: c.OwnPodLabel, operatorNamespace: c.OperatorNamespace, allow: allow}, nil
}

// state is what a build finds: the presence of each digest that a pod in scope runs, by digest, and how many
// containers in scope it skipped, by why.
type state struct {
	images  map[string]evidence.Presence
	skipped map[string]int
}

// build reads the pods, the namespaces and the nodes of the cluster through r, and returns the presence of each
// digest that a pod in scope runs, as the rules say, with every workload that runs it.
//
//   - A pod is in scope when the scope selects it and its namespace, and it isn't one of vexplain's own. A pod whose
//     namespace r doesn't hold yet waits for it.
//   - A workload is the pod's top-level workload, with its UID, as workloads.ResolveOwner reads it: a mirror pod is a
//     workload of its own. It lists its pods that run the digest, each with its node and the platform that the
//     node's labels kubernetes.io/os and kubernetes.io/arch say.
//   - An event copies the labels and the annotations that the allowlists name, and no others. A workload's labels are
//     those of its pods, which carry the labels of its pod template: the collector reads no workload but pods,
//     ReplicaSets and Jobs. When its pods differ in an allowlisted label, the first pod by name decides.
//
// Every pod counts, whatever its phase, so that the image of a finished Job doesn't come and go. The order of what
// build returns depends on the cluster alone, so that the same cluster gives the same events.
func build(ctx context.Context, r client.Reader, rl rules) (state, error) {
	namespaces, err := listMetadata(ctx, r, namespaceKind)
	if err != nil {
		return state{}, err
	}
	nodes, err := listMetadata(ctx, r, nodeKind)
	if err != nil {
		return state{}, err
	}
	var pods corev1.PodList
	// The pods are only read, so the cache needn't copy them.
	if err := r.List(ctx, &pods, client.UnsafeDisableDeepCopy); err != nil {
		return state{}, fmt.Errorf("list the pods: %w", err)
	}
	b := &builder{
		rules:      rl,
		namespaces: make(map[string]*metav1.PartialObjectMetadata, len(namespaces)),
		platforms:  make(map[string]string, len(nodes)),
		images:     map[string]*image{},
		skipped:    map[string]int{},
	}
	for i := range namespaces {
		b.namespaces[namespaces[i].Name] = &namespaces[i]
	}
	for i := range nodes {
		if platform, ok := platformOf(&nodes[i]); ok {
			b.platforms[nodes[i].Name] = platform
		}
	}
	ordered := make([]*corev1.Pod, 0, len(pods.Items))
	for i := range pods.Items {
		ordered = append(ordered, &pods.Items[i])
	}
	slices.SortFunc(ordered, func(a, b *corev1.Pod) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	for _, pod := range ordered {
		if err := b.add(ctx, r, pod); err != nil {
			return state{}, err
		}
	}
	return b.state(), nil
}

// listMetadata lists the objects of a kind through r, as metadata only.
func listMetadata(ctx context.Context, r client.Reader, kind schema.GroupVersionKind) (
	[]metav1.PartialObjectMetadata, error) {
	list := &metav1.PartialObjectMetadataList{}
	list.SetGroupVersionKind(kind.GroupVersion().WithKind(kind.Kind + "List"))
	if err := r.List(ctx, list, client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the %s objects: %w", kind.Kind, err)
	}
	return list.Items, nil
}

// platformOf returns the platform that a node's labels say, as os/arch. A node names no variant of its
// architecture.
func platformOf(node *metav1.PartialObjectMetadata) (string, bool) {
	osName, arch := node.Labels[corev1.LabelOSStable], node.Labels[corev1.LabelArchStable]
	if osName == "" || arch == "" {
		return "", false
	}
	return osName + "/" + arch, true
}

// builder collects the presence of the digests, one pod at a time.
type builder struct {
	rules      rules
	namespaces map[string]*metav1.PartialObjectMetadata
	// platforms are the platforms of the nodes, by name, of those whose labels say one.
	platforms map[string]string
	images    map[string]*image
	skipped   map[string]int
}

// image is the presence of one digest while the build collects it.
type image struct {
	repositories map[string]bool
	workloads    map[workloads.WorkloadRef]*evidence.PresenceWorkload
}

// add adds what a pod runs, when it is in scope, and counts the containers of it that it skips.
func (b *builder) add(ctx context.Context, r client.Reader, pod *corev1.Pod) error {
	namespace, known := b.namespaces[pod.Namespace]
	if !known || !b.rules.scope.Matches(namespace.Labels, pod.Labels) ||
		workloads.IsOwnPod(pod, b.rules.ownPodLabel, b.rules.operatorNamespace) {
		return nil
	}
	images, unparsable := workloads.PodImages(pod)
	b.skipped[reasonUnparsable] += len(unparsable)
	b.skipped[reasonPending] += pending(pod)
	if len(images) == 0 {
		return nil
	}
	owner, err := workloads.ResolveOwner(ctx, r, pod)
	if err != nil {
		return err
	}
	running := evidence.PresencePod{Name: pod.Name, Node: pod.Spec.NodeName, Platform: b.platforms[pod.Spec.NodeName]}
	for _, ref := range images {
		img := b.images[ref.Digest]
		if img == nil {
			img = &image{repositories: map[string]bool{}, workloads: map[workloads.WorkloadRef]*evidence.PresenceWorkload{}}
			b.images[ref.Digest] = img
		}
		if !ref.IsImageID() {
			img.repositories[ref.Repository] = true
		}
		workload := img.workloads[owner]
		if workload == nil {
			workload = &evidence.PresenceWorkload{
				APIGroup: owner.APIGroup, Kind: owner.Kind, Namespace: owner.Namespace, Name: owner.Name,
				UID:                  string(owner.UID),
				NamespaceLabels:      allowed(b.rules.allow.NamespaceLabels, namespace.Labels, nil),
				NamespaceAnnotations: allowed(b.rules.allow.NamespaceAnnotations, namespace.Annotations, nil),
			}
			img.workloads[owner] = workload
		}
		workload.Pods = append(workload.Pods, running)
		workload.Labels = allowed(b.rules.allow.WorkloadLabels, pod.Labels, workload.Labels)
	}
	return nil
}

// pending counts the containers of a pod that have no image ID yet, as while their images are pulled. A pod that has
// ended never gets one, so none of its containers counts.
func pending(pod *corev1.Pod) int {
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return 0
	}
	reported := map[string]bool{}
	for _, status := range slices.Concat(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses) {
		if status.ImageID != "" {
			reported[status.Name] = true
		}
	}
	n := 0
	for _, container := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if !reported[container.Name] {
			n++
		}
	}
	return n
}

// allowed adds to kept the labels or annotations of from whose keys are in allowlist and not in kept yet, and returns
// them sorted by key.
func allowed(allowlist []string, from map[string]string, kept []evidence.KeyValue) []evidence.KeyValue {
	for _, key := range allowlist {
		value, ok := from[key]
		if ok && !slices.ContainsFunc(kept, func(kv evidence.KeyValue) bool { return kv.Key == key }) {
			kept = append(kept, evidence.KeyValue{Key: key, Value: value})
		}
	}
	slices.SortFunc(kept, func(a, b evidence.KeyValue) int { return cmp.Compare(a.Key, b.Key) })
	return kept
}

// state returns what the builder collected, in an order that depends on the cluster alone: the repositories sorted,
// and the workloads by namespace, kind, name, API group and UID, each with its pods by name.
func (b *builder) state() state {
	images := make(map[string]evidence.Presence, len(b.images))
	for digest, img := range b.images {
		presence := evidence.Presence{
			DigestKind:   digestKindImageID,
			Repositories: slices.Sorted(maps.Keys(img.repositories)),
		}
		if len(presence.Repositories) > 0 {
			presence.DigestKind = digestKindRepo
		}
		for _, workload := range img.workloads {
			slices.SortFunc(workload.Pods, func(a, b evidence.PresencePod) int { return cmp.Compare(a.Name, b.Name) })
			presence.Workloads = append(presence.Workloads, *workload)
		}
		slices.SortFunc(presence.Workloads, func(a, b evidence.PresenceWorkload) int {
			return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name),
				cmp.Compare(a.APIGroup, b.APIGroup), cmp.Compare(a.UID, b.UID))
		})
		images[digest] = presence
	}
	return state{images: images, skipped: maps.Clone(b.skipped)}
}
