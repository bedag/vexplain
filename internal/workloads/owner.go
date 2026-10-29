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

package workloads

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// podKind is the kind of a bare pod, a pod that no controller owns. It lives in the core group.
const podKind = "Pod"

// The two kinds that ResolveOwner looks through, because a Deployment or a CronJob usually owns
// them, in the version it reads them in.
var (
	replicaSetGVK = appsv1.SchemeGroupVersion.WithKind("ReplicaSet")
	jobGVK        = batchv1.SchemeGroupVersion.WithKind("Job")
)

// WorkloadRef names a workload: the top-level object that runs pods, such as a Deployment, a
// StatefulSet or a CronJob, or else a bare pod.
type WorkloadRef struct {
	// APIGroup is the API group of Kind. It is empty for the core group, which holds bare pods.
	APIGroup string
	// Kind is the kind of the workload, such as "Deployment".
	Kind string
	// Namespace is the namespace of the pods that the workload runs.
	Namespace string
	// Name is the name of the workload.
	Name string
}

// groupKind is the kind of the workload with its API group.
func (w WorkloadRef) groupKind() schema.GroupKind {
	return schema.GroupKind{Group: w.APIGroup, Kind: w.Kind}
}

// ResolveOwner returns the top-level workload of a pod: the object that people deploy and name,
// such as a Deployment, a StatefulSet or a CronJob. A pod that no controller owns is a workload
// itself.
//
// The controller reference of the pod gives the workload, with one step more for the two kinds that
// a workload usually owns. When the controller is a ReplicaSet (apps) or a Job (batch),
// ResolveOwner reads it and returns its controller instead. The read is for the metadata only,
// because the owner references are all it needs. ResolveOwner never reads that controller. So every
// kind works as a top-level owner, Argo Rollouts and other custom controllers included, and
// ResolveOwner reads nothing but ReplicaSets and Jobs, so it needs no access to any other kind of
// workload.
//
// A ReplicaSet or Job that has no controller reference, or that no longer exists, is the workload
// itself. Any other failure to read it is returned with an empty WorkloadRef, so that the caller
// can try again. ResolveOwner doesn't guess a workload.
func ResolveOwner(ctx context.Context, r client.Reader, pod *corev1.Pod) (WorkloadRef, error) {
	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return WorkloadRef{Kind: podKind, Namespace: pod.Namespace, Name: pod.Name}, nil
	}
	workload := workloadOf(controller, pod.Namespace)

	var gvk schema.GroupVersionKind
	switch workload.groupKind() {
	case replicaSetGVK.GroupKind():
		gvk = replicaSetGVK
	case jobGVK.GroupKind():
		gvk = jobGVK
	default:
		return workload, nil
	}

	// The owner references are all that is needed, so the object is read as metadata only. A typed
	// read would make a cached reader hold every ReplicaSet and Job of the cluster, pod templates
	// included.
	replicaSetOrJob := &metav1.PartialObjectMetadata{}
	replicaSetOrJob.SetGroupVersionKind(gvk)
	key := client.ObjectKey{Namespace: workload.Namespace, Name: workload.Name}
	if err := r.Get(ctx, key, replicaSetOrJob); err != nil {
		if apierrors.IsNotFound(err) {
			return workload, nil
		}
		return WorkloadRef{}, fmt.Errorf("read %s %s: %w", workload.Kind, key, err)
	}
	if parent := metav1.GetControllerOf(replicaSetOrJob); parent != nil {
		return workloadOf(parent, pod.Namespace), nil
	}
	return workload, nil
}

// workloadOf names the object that an owner reference points to. An owner reference carries no
// namespace, so the caller passes the one of the pod.
//
// The API server rejects an owner reference whose apiVersion doesn't parse, so there is no error
// to handle here.
func workloadOf(owner *metav1.OwnerReference, namespace string) WorkloadRef {
	gvk := schema.FromAPIVersionAndKind(owner.APIVersion, owner.Kind)
	return WorkloadRef{APIGroup: gvk.Group, Kind: gvk.Kind, Namespace: namespace, Name: owner.Name}
}
