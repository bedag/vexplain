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

package scan

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// errNoPlatform is the failure of a scan whose pods' nodes say no platform.
var errNoPlatform = errors.New("no node that runs the image says its platform with the labels kubernetes.io/os and " +
	"kubernetes.io/arch")

// scanPlatforms returns the platforms to scan an image for, sorted: those of the nodes that the scheduler put the
// image's pods on, read through nodes one at a time. The collector may get nodes, and never lists them. A pod that
// isn't scheduled yet runs nowhere, and says nothing; a pod that runs the image is scheduled.
//
// A node says its platform with the labels kubernetes.io/os and kubernetes.io/arch, which name no variant. A node
// without both, or whose labels make no platform that the API holds, is skipped, and so is a node that is gone. With
// no platform at all, it returns errNoPlatform.
func scanPlatforms(ctx context.Context, nodes client.Reader, pods []corev1.Pod) ([]string, error) {
	found := map[string]bool{}
	read := map[string]bool{}
	for i := range pods {
		nodeName := pods[i].Spec.NodeName
		if nodeName == "" || read[nodeName] {
			continue
		}
		read[nodeName] = true
		var node corev1.Node
		if err := nodes.Get(ctx, client.ObjectKey{Name: nodeName}, &node); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("read node %q: %w", nodeName, err)
		}
		if platform, ok := platformOf(&node); ok {
			found[platform] = true
		}
	}
	if len(found) == 0 {
		return nil, errNoPlatform
	}
	return slices.Sorted(maps.Keys(found)), nil
}

// platformOf returns the platform that node's labels say, as os/architecture.
func platformOf(node *corev1.Node) (string, bool) {
	osName, arch := node.Labels[corev1.LabelOSStable], node.Labels[corev1.LabelArchStable]
	if osName == "" || arch == "" {
		return "", false
	}
	platform := osName + "/" + arch
	if len(platform) > maxPlatformLength || !platformPattern.MatchString(platform) {
		return "", false
	}
	return platform, true
}
