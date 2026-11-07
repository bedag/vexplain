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

// Package inventory is the door to the ImageInventory and ImageVerdicts objects of the inventory
// group: only its stores read, write or watch them. Controllers never touch the inventory API
// directly. The Evidence objects have a door of their own, the evidence store.
//
// The objects are bulky, derived data. Keeping them behind interfaces lets the storage change
// without a change to the code that uses it, and keeps hub and spoke apart. Through a Store, the
// spoke side reports presence with Observe and Forget, follows the objects through Source and
// Digests, and counts its own presence through CountForCluster. The facts of the evidence are
// written with SetFacts and UpdateFacts. The hub side reads through Get, finds the digests of a
// platform manifest through ManifestReferences, and writes the summary of each image with SetSummary.
// The hub's result sheets go through a VerdictsStore. Nothing but these interfaces and the evidence
// store stands between hub and spoke.
package inventory

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/source"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/sdk/workloads"
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
	// Platforms are the platforms that the pods which run the digest run on, from their nodes, as
	// os/architecture[/variant]. The store keeps those that are platforms, sorted, each once, and the
	// first 8. Empty means the cluster doesn't say.
	Platforms []string
	// NamespaceCount is the number of namespaces in which the digest runs in this cluster.
	NamespaceCount int32
	// Exposure is the highest exposure of the workloads that run the digest. Empty means that the
	// cluster doesn't say yet: the store then keeps the exposure that the entry has, and a new entry
	// has none.
	Exposure inventoryv1alpha1.SSVCExposure
	// Workloads are the workloads that run the digest in this cluster. The store counts them.
	Workloads []workloads.WorkloadRef // all of them; the store sorts and keeps the first 100
}

// Store keeps the ImageInventory objects, one per reported digest. It is the only way to read,
// write or watch them.
//
// Each cluster writes only its own entry in the object of a digest, and several clusters can write
// at the same time. A write that finds the object changed reads it again and retries, so no
// writer's entry is lost to another's. If a writer keeps losing, the method returns the conflict,
// and the caller tries again later. The hub's summary is written alone, so that neither undoes the
// other: SetSummary.
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
	// NameForDigest of its digest. A controller watches the objects through it. A change of the
	// summary alone delivers none: nothing that watches reads it, and the hub writes it whenever what
	// it reads changes.
	Source() source.Source
	// SetFacts replaces the facts of an existing object; nil clears them. It never creates one: when
	// the digest has no object it returns false and writes nothing. It writes nothing when nothing
	// changes. It returns true when the object exists, whether it wrote or not.
	SetFacts(ctx context.Context, digest string, facts *inventoryv1alpha1.ImageFacts) (bool, error)
	// UpdateFacts replaces the facts of an existing object with what update makes of them, as
	// SetFacts does. update gets a copy of the facts as they are, nil when there are none, and may
	// change it. When another writer changes the object before the write, UpdateFacts reads it
	// again and calls update again, so that what update makes always starts from the facts that it
	// replaces. An error of update ends UpdateFacts, which writes nothing and returns the error.
	UpdateFacts(ctx context.Context, digest string,
		update func(*inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error)) (bool, error)
	// ManifestReferences returns the reported digests whose facts name the platform manifest, in no
	// particular order.
	ManifestReferences(ctx context.Context, manifestDigest string) ([]string, error)
	// SetSummary replaces the summary of an existing object as a whole, and writes nothing else of it
	// (decision 0039): neither an entry nor the facts, which a write of the summary therefore never
	// undoes, and which a write of the summary never makes fail. A write of an entry or of the facts
	// that meets it reads the object again, and keeps the summary. SetSummary never creates an object:
	// when the digest has none it returns false and writes nothing. It doesn't compare the summary
	// with the stored one, and writes it all the same.
	SetSummary(ctx context.Context, digest string, summary inventoryv1alpha1.ImageSummary) (bool, error)
}
