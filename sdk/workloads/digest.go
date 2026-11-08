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

// Package workloads reads what a pod runs and who owns it, for vexplain's operator and for the
// collectors that report what runs where.
//
// PodImages turns a pod into the images its containers run, as the container runtime reports their digests.
// ResolveOwner turns a pod into its top-level workload, such as a Deployment or a CronJob. IsOwnPod tells vexplain's
// own pods, such as its scan pods, which are no workloads of the cluster. All of them only read: vexplain never writes
// to the workloads it analyses.
package workloads

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// TaskLabel marks a task pod: a pod that the operator runs for itself, such as a scan pod, and not
// a workload of the cluster. The value names the task, such as "scan", but only the presence of the
// label counts, and only in the operator's namespace: see IsTaskPod.
//
// Anyone who can create pods can set a label. If the label counted in every namespace, setting it
// would hide a workload from the inventory, and so from triage. The operator's namespace is the
// administrators' to control, and it is where the operator runs its task pods.
const TaskLabel = "vexplain.bedag.ch/task"

// digestPattern matches a sha256 digest: the algorithm, a colon and 64 lowercase hex digits.
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// The kinds of container that an image runs in.
const (
	// ContainerKindContainer is a regular container.
	ContainerKindContainer = "Container"
	// ContainerKindInitContainer is an init container.
	ContainerKindInitContainer = "InitContainer"
	// ContainerKindSidecar is an init container with restartPolicy Always: it starts before the containers and
	// runs along with them.
	ContainerKindSidecar = "Sidecar"
)

// ContainerRef names a container of a pod, and says what kind it is.
type ContainerRef struct {
	Name string
	// Kind is ContainerKindContainer, ContainerKindInitContainer or ContainerKindSidecar.
	Kind string
}

// ImageRef is an image that the containers of a pod run: a digest that a container runtime reports, with the
// repository the image was pulled from when the runtime says so, or the reference of an image that no digest names.
type ImageRef struct {
	// Digest is "sha256:" followed by 64 lowercase hex digits. For a Reference image it is ReferenceDigest of the
	// reference.
	Digest string
	// Repository is where the image was pulled from, such as "artifacts.example/lib/nginx". It is empty when Digest is
	// an image ID, and it is the image reference when Reference is set.
	Repository string
	// Reference is set for an image that has no digest: its container reports no image ID, or one that is no digest.
	// No registry can be asked for it by digest, so its content can't be fetched.
	Reference bool
	// Containers are the containers of the pod that run the image, sorted by name.
	Containers []ContainerRef
}

// IsImageID reports whether Digest is an image ID and not a repository digest. An image ID is the
// digest of the image's configuration. No registry can serve it, so the content of such an image
// can't be fetched.
func (r ImageRef) IsImageID() bool {
	return r.Repository == "" && !r.Reference
}

// ReferenceDigest returns the digest that stands for an image that has none: the SHA-256 of its reference, as the
// container's image field says it. It names the image in presence, and no registry knows it.
func ReferenceDigest(reference string) string {
	sum := sha256.Sum256([]byte(reference))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DigestFromImageID reads the digest from the imageID of a container status. It accepts what
// container runtimes report, with or without a prefix such as docker-pullable:// or docker://:
//
//   - repository@sha256:<64 hex digits>, a repository digest
//   - sha256:<64 hex digits>, an image ID
//
// It reports false for anything else: an empty value (the container hasn't started), a tag, a
// digest of another algorithm and a digest that isn't 64 lowercase hex digits.
func DigestFromImageID(imageID string) (ImageRef, bool) {
	value := imageID
	if _, rest, found := strings.Cut(value, "://"); found {
		value = rest
	}

	repository, digest := "", value
	if at := strings.LastIndexByte(value, '@'); at >= 0 {
		repository, digest = value[:at], value[at+1:]
		// A repository digest names its repository. Without one, the value would read as an
		// image ID, which is a different kind of digest.
		if repository == "" {
			return ImageRef{}, false
		}
	}
	if !digestPattern.MatchString(digest) {
		return ImageRef{}, false
	}
	return ImageRef{Digest: digest, Repository: repository}, true
}

// PodImages returns the images a pod runs, as its container runtime reports them in the status of
// the init containers and of the containers, and the containers that run each. Ephemeral containers are skipped:
// they are debug sessions, not part of the workload.
//
// A container is a Container, an InitContainer, or a Sidecar: an init container with restartPolicy Always.
//
// A container whose status gives no digest, because it has no image ID yet or its image ID is no digest, runs a
// Reference image, keyed by ReferenceDigest of the image field of its spec. A container without an image in its spec
// has none to name, and is left out.
//
// The images come sorted by digest, one per digest. When several containers report the same digest,
// the image keeps the repository of the first one read, and the init containers are read first.
//
// unparsable holds the names of the containers whose imageID is set but isn't a digest, in the
// order they were read, so that the caller can make them visible. A container that hasn't started
// has an empty imageID. That isn't a failure, so it isn't listed.
func PodImages(pod *corev1.Pod) (images []ImageRef, unparsable []string) {
	byDigest := make(map[string]*ImageRef)
	add := func(ref ImageRef, container ContainerRef) {
		image, ok := byDigest[ref.Digest]
		if !ok {
			image = &ref
			byDigest[ref.Digest] = image
		}
		image.Containers = append(image.Containers, container)
	}
	for _, c := range containersOf(pod) {
		ref, ok := DigestFromImageID(c.imageID)
		if c.imageID != "" && !ok {
			unparsable = append(unparsable, c.name)
		}
		if !ok {
			if c.image == "" {
				continue
			}
			ref = ImageRef{Digest: ReferenceDigest(c.image), Repository: c.image, Reference: true}
		}
		add(ref, ContainerRef{Name: c.name, Kind: c.kind})
	}
	for _, image := range byDigest {
		slices.SortFunc(image.Containers, func(a, b ContainerRef) int { return cmp.Compare(a.Name, b.Name) })
		images = append(images, *image)
	}
	slices.SortFunc(images, func(a, b ImageRef) int { return cmp.Compare(a.Digest, b.Digest) })
	return images, unparsable
}

// podContainer is a container of a pod as PodImages reads it: its place in the spec, and what its status reports.
type podContainer struct {
	name, kind, image, imageID string
}

// containersOf returns the init containers and then the containers of a pod, each with what its spec and its
// status say. A status without a container in the spec, which a pod read in part may have, is a container too, of
// the kind of the list that reports it, and with no image of its spec.
func containersOf(pod *corev1.Pod) []podContainer {
	var found []podContainer
	read := func(specs []corev1.Container, statuses []corev1.ContainerStatus, kind func(corev1.Container) string,
		orphan string) {
		reported := make(map[string]string, len(statuses))
		for _, status := range statuses {
			reported[status.Name] = status.ImageID
		}
		named := make(map[string]bool, len(specs))
		for _, spec := range specs {
			named[spec.Name] = true
			found = append(found, podContainer{name: spec.Name, kind: kind(spec), image: spec.Image,
				imageID: reported[spec.Name]})
		}
		for _, status := range statuses {
			if !named[status.Name] {
				found = append(found, podContainer{name: status.Name, kind: orphan, imageID: status.ImageID})
			}
		}
	}
	read(pod.Spec.InitContainers, pod.Status.InitContainerStatuses, func(c corev1.Container) string {
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			return ContainerKindSidecar
		}
		return ContainerKindInitContainer
	}, ContainerKindInitContainer)
	read(pod.Spec.Containers, pod.Status.ContainerStatuses, func(corev1.Container) string {
		return ContainerKindContainer
	}, ContainerKindContainer)
	return found
}

// IsTaskPod reports whether pod is a task pod of the operator that runs in operatorNamespace: a pod
// that carries TaskLabel and runs in that namespace. The inventory never counts a task pod. A pod
// that carries the label in any other namespace is a workload like any other.
//
// With no operator namespace there are no task pods, so that the label never hides a pod on a
// guess.
func IsTaskPod(pod *corev1.Pod, operatorNamespace string) bool {
	return IsOwnPod(pod, TaskLabel, operatorNamespace)
}

// IsOwnPod reports whether pod is one of vexplain's own pods: it carries label, the label that marks
// them, and runs in operatorNamespace, the namespace of vexplain's operator. vexplain tells its
// collectors both in the context of every Watch and Invoke, and a pod that carries the label in any
// other namespace is a workload like any other, as IsTaskPod says for TaskLabel.
//
// With no label or no operator namespace there are no own pods, so that the label never hides a pod
// on a guess.
func IsOwnPod(pod *corev1.Pod, label, operatorNamespace string) bool {
	if label == "" || operatorNamespace == "" {
		return false
	}
	_, labelled := pod.Labels[label]
	return labelled && pod.Namespace == operatorNamespace
}
