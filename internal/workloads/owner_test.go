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

package workloads_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/bedag/vexplain/internal/workloads"
)

// Every fixture lives in the namespace ns. The pod, the ReplicaSet and the Job of a row have these
// names, so that the pod's owner reference finds the ReplicaSet or the Job. The rest are the API
// groups, the API versions and the kinds that the rows of the tables repeat.
const (
	ns      = "ns"
	web     = "web"
	podName = "p"
	rsName  = "rs"
	jobName = "j"

	appsGroup  = "apps"
	batchGroup = "batch"
	appsV1     = "apps/v1"
	batchV1    = "batch/v1"

	deploymentKind  = "Deployment"
	replicaSetKind  = "ReplicaSet"
	statefulSetKind = "StatefulSet"
	jobKind         = "Job"
	cronJobKind     = "CronJob"
	podKind         = "Pod"
)

// controller is an owner reference that makes the owner the controller of the object.
func controller(apiVersion, kind, name string) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		UID:        types.UID("uid-" + name),
		Controller: ptr.To(true),
	}
}

// owner is an owner reference that doesn't make the owner the controller of the object.
func owner(apiVersion, kind, name string) metav1.OwnerReference {
	ref := controller(apiVersion, kind, name)
	ref.Controller = nil
	return ref
}

func pod(owners ...metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: podName, OwnerReferences: owners}}
}

func replicaSet(owners ...metav1.OwnerReference) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: rsName, OwnerReferences: owners}}
}

func job(owners ...metav1.OwnerReference) *batchv1.Job {
	return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: jobName, OwnerReferences: owners}}
}

// workload is a workload in the namespace ns.
func workload(group, kind, name string) workloads.WorkloadRef {
	return workloads.WorkloadRef{APIGroup: group, Kind: kind, Namespace: ns, Name: name}
}

// fetch is how spy writes down a read of the object called name in the namespace ns.
func fetch(kind, name string) string {
	return kind + " " + ns + "/" + name
}

// spy is a fake client that writes down every object it is asked to read. A fake client answers
// "not found" for an object it doesn't hold, which ResolveOwner treats as a valid answer, so
// without the record a read that shouldn't happen would go unnoticed. When err is set, every read
// fails with it.
type spy struct {
	client.Client
	err error
	// fetched has the kind and the key of each read, spelled like fetch spells them.
	fetched []string
	// asked has a copy of each object that was passed to Get, as it was before the read filled it
	// in. The fake client serves a typed object as well as a metadata-only one, so the copy is what
	// shows which of the two ResolveOwner asked for.
	asked []runtime.Object
}

func newSpy(t *testing.T, objs ...client.Object) *spy {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	return &spy{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()}
}

func (s *spy) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	s.fetched = append(s.fetched, kindOf(obj)+" "+key.String())
	s.asked = append(s.asked, obj.DeepCopyObject())
	if s.err != nil {
		return s.err
	}
	return s.Client.Get(ctx, key, obj, opts...)
}

// kindOf is the kind of an object that is about to be read. A metadata-only object says in its
// type meta which kind it stands for. A typed object is its Go type, so that a typed read still
// shows up as the kind it reads, and TestResolveOwnerReadsMetadataOnly is what fails.
func kindOf(obj client.Object) string {
	if kind := obj.GetObjectKind().GroupVersionKind().Kind; kind != "" {
		return kind
	}
	return reflect.TypeOf(obj).Elem().Name()
}

func TestResolveOwner(t *testing.T) {
	tests := []struct {
		name    string
		cluster []client.Object // the objects in the cluster, besides the pod
		pod     *corev1.Pod
		want    workloads.WorkloadRef
		fetched []string // the objects ResolveOwner reads, in order
	}{
		// The pod's controller is the workload, except for a ReplicaSet or a Job, whose
		// controller is the workload.
		{
			name:    "a ReplicaSet of a Deployment resolves to the Deployment",
			cluster: []client.Object{replicaSet(controller(appsV1, deploymentKind, web))},
			pod:     pod(controller(appsV1, replicaSetKind, rsName)),
			want:    workload(appsGroup, deploymentKind, web),
			fetched: []string{fetch(replicaSetKind, rsName)},
		},
		{
			name:    "a ReplicaSet of a Rollout resolves to the Rollout, which is not read",
			cluster: []client.Object{replicaSet(controller("argoproj.io/v1alpha1", "Rollout", "r"))},
			pod:     pod(controller(appsV1, replicaSetKind, rsName)),
			want:    workload("argoproj.io", "Rollout", "r"),
			fetched: []string{fetch(replicaSetKind, rsName)},
		},
		{
			name:    "a ReplicaSet without an owner is the workload",
			cluster: []client.Object{replicaSet()},
			pod:     pod(controller(appsV1, replicaSetKind, rsName)),
			want:    workload(appsGroup, replicaSetKind, rsName),
			fetched: []string{fetch(replicaSetKind, rsName)},
		},
		{
			name:    "a Job of a CronJob resolves to the CronJob",
			cluster: []client.Object{job(controller(batchV1, cronJobKind, "c"))},
			pod:     pod(controller(batchV1, jobKind, jobName)),
			want:    workload(batchGroup, cronJobKind, "c"),
			fetched: []string{fetch(jobKind, jobName)},
		},
		{
			name:    "a Job without an owner is the workload",
			cluster: []client.Object{job()},
			pod:     pod(controller(batchV1, jobKind, jobName)),
			want:    workload(batchGroup, jobKind, jobName),
			fetched: []string{fetch(jobKind, jobName)},
		},

		// Any other controller is the workload, and nothing is read for it.
		{
			name: "a StatefulSet is the workload, and is not read",
			pod:  pod(controller(appsV1, statefulSetKind, "s")),
			want: workload(appsGroup, statefulSetKind, "s"),
		},
		{
			name: "an owner of the core group has an empty API group",
			pod:  pod(controller("v1", "ReplicationController", "rc")),
			want: workload("", "ReplicationController", "rc"),
		},
		{
			name: "a pod without an owner is the workload",
			pod:  pod(),
			want: workloads.WorkloadRef{Kind: podKind, Namespace: ns, Name: podName},
		},

		// An owner that is gone, or that has no controller, ends the chain at that owner.
		{
			name:    "a ReplicaSet that no longer exists is the workload",
			pod:     pod(controller(appsV1, replicaSetKind, rsName)),
			want:    workload(appsGroup, replicaSetKind, rsName),
			fetched: []string{fetch(replicaSetKind, rsName)},
		},
		{
			name:    "a Job that no longer exists is the workload",
			pod:     pod(controller(batchV1, jobKind, jobName)),
			want:    workload(batchGroup, jobKind, jobName),
			fetched: []string{fetch(jobKind, jobName)},
		},
		{
			name:    "a ReplicaSet without a controller reference is the workload",
			cluster: []client.Object{replicaSet(owner(appsV1, deploymentKind, web))},
			pod:     pod(controller(appsV1, replicaSetKind, rsName)),
			want:    workload(appsGroup, replicaSetKind, rsName),
			fetched: []string{fetch(replicaSetKind, rsName)},
		},
		{
			name:    "a Job without a controller reference is the workload",
			cluster: []client.Object{job(owner(batchV1, cronJobKind, "c"))},
			pod:     pod(controller(batchV1, jobKind, jobName)),
			want:    workload(batchGroup, jobKind, jobName),
			fetched: []string{fetch(jobKind, jobName)},
		},

		// Only a controller reference counts.
		{
			name: "a pod whose owner references include no controller is a bare pod",
			pod:  pod(owner(appsV1, replicaSetKind, rsName)),
			want: workloads.WorkloadRef{Kind: podKind, Namespace: ns, Name: podName},
		},
		{
			name: "the controller wins among several owner references",
			pod: pod(
				owner(appsV1, deploymentKind, web),
				controller(appsV1, statefulSetKind, "s")),
			want: workload(appsGroup, statefulSetKind, "s"),
		},

		// A ReplicaSet or a Job is only read when it belongs to apps or to batch. The cluster holds
		// an object with the same name, so a read would give a different answer.
		{
			name:    "a ReplicaSet of another API group is the workload, and is not read",
			cluster: []client.Object{replicaSet(controller(appsV1, deploymentKind, web))},
			pod:     pod(controller("example.com/v1", replicaSetKind, rsName)),
			want:    workload("example.com", replicaSetKind, rsName),
		},
		{
			name:    "a Job of another API group is the workload, and is not read",
			cluster: []client.Object{job(controller(batchV1, cronJobKind, "c"))},
			pod:     pod(controller("example.com/v1", jobKind, jobName)),
			want:    workload("example.com", jobKind, jobName),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newSpy(t, tc.cluster...)

			got, err := workloads.ResolveOwner(t.Context(), r, tc.pod)

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.fetched, r.fetched)
		})
	}
}

// ResolveOwner reads the ReplicaSet and the Job as metadata only, because their owner references
// are all it needs. A typed read would make the manager's cache hold every ReplicaSet and every
// Job of the cluster, pod templates included. The fake client serves a typed read as well as a
// metadata-only one, so the rows of TestResolveOwner can't tell them apart. This test can, and it
// also pins the API version, which a metadata-only read has to name.
func TestResolveOwnerReadsMetadataOnly(t *testing.T) {
	tests := []struct {
		name    string
		cluster client.Object
		pod     *corev1.Pod
		want    schema.GroupVersionKind // the kind that the object passed to Get stands for
	}{
		{
			name:    "a ReplicaSet",
			cluster: replicaSet(controller(appsV1, deploymentKind, web)),
			pod:     pod(controller(appsV1, replicaSetKind, rsName)),
			want:    schema.GroupVersionKind{Group: appsGroup, Version: "v1", Kind: replicaSetKind},
		},
		{
			name:    "a Job",
			cluster: job(controller(batchV1, cronJobKind, "c")),
			pod:     pod(controller(batchV1, jobKind, jobName)),
			want:    schema.GroupVersionKind{Group: batchGroup, Version: "v1", Kind: jobKind},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newSpy(t, tc.cluster)

			_, err := workloads.ResolveOwner(t.Context(), r, tc.pod)

			require.NoError(t, err)
			require.Len(t, r.asked, 1)
			require.IsType(t, &metav1.PartialObjectMetadata{}, r.asked[0])
			require.Equal(t, tc.want, r.asked[0].GetObjectKind().GroupVersionKind())
		})
	}
}

// A failed read of the ReplicaSet or the Job, other than "not found", is an error. A guess would
// make the ReplicaSet or the Job the workload of the pod, hide the real one, and nobody would
// learn that it was a guess. With the error, the caller tries again.
func TestResolveOwnerReturnsReadErrors(t *testing.T) {
	boom := errors.New("boom")
	denied := errors.New("denied")

	tests := []struct {
		name string
		pod  *corev1.Pod
		err  error
	}{
		{
			name: "a ReplicaSet that can't be read",
			pod:  pod(controller(appsV1, replicaSetKind, rsName)),
			err:  boom,
		},
		{
			name: "a ReplicaSet that the operator may not read",
			pod:  pod(controller(appsV1, replicaSetKind, rsName)),
			err: apierrors.NewForbidden(
				schema.GroupResource{Group: appsGroup, Resource: "replicasets"}, rsName, denied),
		},
		{
			name: "a Job that can't be read",
			pod:  pod(controller(batchV1, jobKind, jobName)),
			err:  boom,
		},
		{
			name: "a Job that the operator may not read",
			pod:  pod(controller(batchV1, jobKind, jobName)),
			err: apierrors.NewForbidden(
				schema.GroupResource{Group: batchGroup, Resource: "jobs"}, jobName, denied),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newSpy(t)
			r.err = tc.err

			got, err := workloads.ResolveOwner(t.Context(), r, tc.pod)

			require.ErrorIs(t, err, tc.err)
			require.Zero(t, got)
		})
	}
}
