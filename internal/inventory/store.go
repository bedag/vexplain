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

// Package inventory is the one door to the ImageInventory objects: only a Store reads, writes or
// watches them. Controllers never touch the inventory API directly.
//
// An ImageInventory is bulky, derived data. Keeping it behind an interface lets the storage change
// without a change to the code that uses it, and keeps hub and spoke apart. The spoke side
// reports through Observe and Forget, follows the objects through Source and Digests, and counts
// its own presence through CountForCluster. The hub side reads through Get. Nothing but this
// interface stands between them.
package inventory

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/source"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/workloads"
)

// Observation is what one cluster reports about one digest: where the digest runs there.
type Observation struct {
	// Cluster is the name of the reporting cluster, and ClusterID its identity. The name labels the
	// cluster's entry. The ID, which never changes, lets a rename be recognised.
	Cluster, ClusterID string
	// DigestKind says what the digest is, a repository digest or an image ID.
	DigestKind inventoryv1alpha1.DigestKind
	// Repositories are the repositories the digest was pulled from. An image ID has none.
	Repositories []string
	// NamespaceCount is the number of namespaces in which the digest runs in this cluster.
	NamespaceCount int32
	// Workloads are the workloads that run the digest in this cluster. The store counts them.
	Workloads []workloads.WorkloadRef // all of them; the store sorts and keeps the first 100
}

// Store keeps the ImageInventory objects, one per reported digest. It is the only way to read,
// write or watch them.
//
// Each cluster writes only its own entry in the object of a digest, and several clusters can write
// at the same time. A write that finds the object changed reads it again and retries, so no
// writer's entry is lost to another's. If a writer keeps losing, the method returns the conflict,
// and the caller tries again later.
type Store interface {
	// Get returns the object of a digest, or nil, nil when there is none.
	Get(ctx context.Context, digest string) (*inventoryv1alpha1.ImageInventory, error) // nil, nil if absent
	// Observe creates the object if needed and sets this cluster's entry. It removes any
	// other entry with the same ClusterID (a renamed cluster) and writes nothing if the
	// result is unchanged.
	Observe(ctx context.Context, digest string, obs Observation) error
	// Forget removes every entry whose cluster name is `cluster` or whose ClusterID is
	// `clusterID`. That also covers a rename that happened while the digest disappeared.
	// It deletes the object when no entries remain. No error if absent.
	Forget(ctx context.Context, digest, cluster, clusterID string) error
	// Digests returns the digest of every object, in no particular order.
	Digests(ctx context.Context) ([]string, error)
	// CountForCluster returns the number of objects with an entry whose ClusterID is clusterID,
	// whatever cluster name the entry carries.
	CountForCluster(ctx context.Context, clusterID string) (int, error)
	// Source delivers one request per created, changed or deleted object, named after the object:
	// NameForDigest of its digest. A controller watches the objects through it.
	Source() source.Source
}
