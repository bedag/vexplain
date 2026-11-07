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
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// These tests cover which platforms a scan asks for: those of the nodes that run the digest's pods,
// read from the nodes' labels. The collector reads each node with get, and never lists them.

// labelledNode returns a node whose labels say its platform. An empty os or arch leaves that label out.
func labelledNode(name, os, arch string) *corev1.Node {
	labels := map[string]string{}
	if os != "" {
		labels[corev1.LabelOSStable] = os
	}
	if arch != "" {
		labels[corev1.LabelArchStable] = arch
	}
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// clusterNodes are the nodes of the tests: one of each architecture, and one that doesn't say its
// architecture.
func clusterNodes() []client.Object {
	return []client.Object{
		labelledNode("node-amd64", "linux", "amd64"),
		labelledNode("node-arm64", "linux", "arm64"),
		labelledNode("node-arm64-b", "linux", "arm64"),
		labelledNode("node-unlabelled", "linux", ""),
	}
}

// podOn returns a pod in phase that the scheduler put on the node named node. An empty node is a
// pod that isn't scheduled yet.
func podOn(name, node string, phase corev1.PodPhase) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: name},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: phase},
	}
}

// nodeReads counts the reads of nodes, by kind of read.
type nodeReads struct{ gets, lists int }

// nodeReader returns a reader that holds objs and counts its reads.
func nodeReader(objs ...client.Object) (client.Reader, *nodeReads) {
	reads := &nodeReads{}
	c := fake.NewClientBuilder().WithObjects(objs...).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			reads.gets++
			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			reads.lists++
			return c.List(ctx, list, opts...)
		},
	}).Build()
	return c, reads
}

func TestPlatformsOfTheNodesThatRunTheDigest(t *testing.T) {
	reader, reads := nodeReader(clusterNodes()...)

	platforms, err := scanPlatforms(t.Context(), reader, []corev1.Pod{
		podOn("app-0", "node-arm64", corev1.PodRunning), podOn("app-1", "node-arm64-b", corev1.PodRunning),
	})

	require.NoError(t, err)
	require.Equal(t, []string{linuxARM64}, platforms)
	require.Equal(t, nodeReads{gets: 2}, *reads, "the nodes of the pods are read one by one, never listed")
}

// A pod that the scheduler hasn't put on a node yet runs nowhere, so it says nothing about the
// platforms.
func TestPlatformsIgnoreAPodThatIsNotScheduled(t *testing.T) {
	reader, _ := nodeReader(clusterNodes()...)

	platforms, err := scanPlatforms(t.Context(), reader, []corev1.Pod{
		podOn("app-0", "node-arm64", corev1.PodRunning), podOn("app-1", "", corev1.PodPending),
	})

	require.NoError(t, err)
	require.Equal(t, []string{linuxARM64}, platforms)
}

// Every pod that the scheduler put on a node counts, whatever its phase: a pod that still pulls an
// image of another container, and the finished pod of a Job, run or ran the digest there.
func TestPlatformsCountEveryScheduledPod(t *testing.T) {
	reader, _ := nodeReader(clusterNodes()...)

	platforms, err := scanPlatforms(t.Context(), reader, []corev1.Pod{
		podOn("app-0", "node-arm64", corev1.PodPending), podOn("job-0", "node-amd64", corev1.PodSucceeded),
	})

	require.NoError(t, err)
	require.Equal(t, []string{linuxAMD64, linuxARM64}, platforms)
}

// A pod that the scheduler hasn't put anywhere yet says no platform, and neither does the cluster: the collector
// reads nodes one at a time, and doesn't list them. A pod that runs the digest has been scheduled, so this is a
// request whose pods aren't running yet, which fails, and is asked for again later.
func TestPlatformsFailWhenNoPodIsScheduled(t *testing.T) {
	reader, reads := nodeReader(clusterNodes()...)

	_, err := scanPlatforms(t.Context(), reader, []corev1.Pod{podOn("app-0", "", corev1.PodPending)})

	require.ErrorIs(t, err, errNoPlatform)
	require.Equal(t, nodeReads{}, *reads)
}

// A node says its platform only with both labels; without them, it is skipped, and so is a node that
// is gone.
func TestPlatformsSkipANodeThatDoesNotSayItsPlatform(t *testing.T) {
	reader, _ := nodeReader(clusterNodes()...)

	platforms, err := scanPlatforms(t.Context(), reader, []corev1.Pod{
		podOn("app-0", "node-unlabelled", corev1.PodRunning), podOn("app-1", "node-gone", corev1.PodRunning),
		podOn("app-2", "node-amd64", corev1.PodRunning),
	})
	require.NoError(t, err)
	require.Equal(t, []string{linuxAMD64}, platforms)

	_, err = scanPlatforms(t.Context(), reader, []corev1.Pod{
		podOn("app-0", "node-unlabelled", corev1.PodRunning), podOn("app-1", "node-gone", corev1.PodRunning),
	})
	require.ErrorIs(t, err, errNoPlatform)
}

// A label value that isn't a platform as the API writes one is no platform either.
func TestPlatformsSkipALabelThatIsNoPlatform(t *testing.T) {
	reader, _ := nodeReader(labelledNode("node-odd", "Linux", "amd64"), labelledNode("node-amd64", "linux", "amd64"))

	platforms, err := scanPlatforms(t.Context(), reader, []corev1.Pod{
		podOn("app-0", "node-odd", corev1.PodRunning), podOn("app-1", "node-amd64", corev1.PodRunning),
	})

	require.NoError(t, err)
	require.Equal(t, []string{linuxAMD64}, platforms)
}

// Without a node that says its platform, there is nothing to ask the scanner for.
func TestPlatformsFailWhenNoNodeSaysItsPlatform(t *testing.T) {
	reader, _ := nodeReader(labelledNode("node-unlabelled", "linux", ""))

	_, err := scanPlatforms(t.Context(), reader, []corev1.Pod{podOn("app-0", "node-unlabelled", corev1.PodRunning)})

	require.ErrorIs(t, err, errNoPlatform)
}

// A node that can't be read is an error, and never a node without a platform.
func TestPlatformsReturnAFailedRead(t *testing.T) {
	failing := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("the API server is away")
		},
	}).Build()

	_, err := scanPlatforms(t.Context(), failing, []corev1.Pod{podOn("app-0", "node-amd64", corev1.PodRunning)})

	require.Error(t, err)
	require.NotErrorIs(t, err, errNoPlatform)
}
