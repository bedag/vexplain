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

// Package workloads reads what a pod runs and who owns it.
//
// PodImages turns the status of a pod into the digests of the images its containers run, as the
// container runtime reports them. ResolveOwner turns a pod into its top-level workload, such as a
// Deployment or a CronJob. Both only read: the operator never writes to the workloads it analyses.
package workloads

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PodDigestIndex names the field index on pods whose keys are the digests the pods report. Register
// IndexPodDigests under this name, then list the pods that run a digest with client.MatchingFields.
const PodDigestIndex = "inventory.vexplain.bedag.ch/image-digests"

// TaskLabel marks a task pod: a pod that the operator runs for itself, such as a scan pod, and not
// a workload of the cluster. The value names the task, such as "scan", but only the presence of the
// label counts. IndexPodDigests gives a task pod no digests, so the inventory never counts it.
const TaskLabel = "vexplain.bedag.ch/task"

// digestPattern matches a sha256 digest: the algorithm, a colon and 64 lowercase hex digits.
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ImageRef is a digest that a container runtime reports for a running container, with the
// repository the image was pulled from when the runtime says so.
type ImageRef struct {
	// Digest is "sha256:" followed by 64 lowercase hex digits.
	Digest string
	// Repository is where the image was pulled from, such as "artifacts.example/lib/nginx". It is
	// empty when Digest is an image ID.
	Repository string
}

// IsImageID reports whether Digest is an image ID and not a repository digest. An image ID is the
// digest of the image's configuration. No registry can serve it, so the content of such an image
// can't be fetched.
func (r ImageRef) IsImageID() bool {
	return r.Repository == ""
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
// the init containers and of the containers. Ephemeral containers are skipped: they are debug
// sessions, not part of the workload.
//
// The images come sorted by digest, one per digest. When several containers report the same digest,
// the image keeps the repository of the first one read, and the init containers are read first.
//
// unparsable holds the names of the containers whose imageID is set but isn't a digest, in the
// order they were read, so that the caller can make them visible. A container that hasn't started
// has an empty imageID. That isn't a failure, so it isn't listed.
func PodImages(pod *corev1.Pod) (images []ImageRef, unparsable []string) {
	seen := make(map[string]bool)
	for _, status := range slices.Concat(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses) {
		if status.ImageID == "" {
			continue
		}
		ref, ok := DigestFromImageID(status.ImageID)
		if !ok {
			unparsable = append(unparsable, status.Name)
			continue
		}
		if !seen[ref.Digest] {
			seen[ref.Digest] = true
			images = append(images, ref)
		}
	}
	slices.SortFunc(images, func(a, b ImageRef) int { return cmp.Compare(a.Digest, b.Digest) })
	return images, unparsable
}

// IndexPodDigests is the index function for PodDigestIndex. It returns the digests of the images
// of a pod, as PodImages reports them. It returns nil for a task pod, which carries TaskLabel, and
// for any other object.
func IndexPodDigests(obj client.Object) []string {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	if _, isTask := pod.Labels[TaskLabel]; isTask {
		return nil
	}
	images, _ := PodImages(pod)
	digests := make([]string, 0, len(images))
	for _, image := range images {
		digests = append(digests, image.Digest)
	}
	return digests
}
