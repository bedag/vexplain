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

package remote

import (
	"context"
	"fmt"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/internal/evidence"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// namespacesVersion is the version under which the hub stores its records of the namespaces, where a collector's would
// be: the version of their type, which changes only with their form, so that a new build of the hub rewrites none.
const namespacesVersion = "v1alpha1"

var (
	// namespaceKind is the kind of a namespace, of which the copier reads the metadata only.
	namespaceKind = corev1.SchemeGroupVersion.WithKind("Namespace")
	// namespacePair is the source and the type of the hub's records of the spoke's namespaces.
	namespacePair = pair{source: evidence.HubSource, eventType: sdkevidence.TypeNamespace}
)

// namespaceMetadata returns an empty object of a namespace's metadata, as the copier's cache watches it.
func namespaceMetadata() *metav1.PartialObjectMetadata {
	obj := &metav1.PartialObjectMetadata{}
	obj.SetGroupVersionKind(namespaceKind)
	return obj
}

// copyNamespaces copies the labels of each of the spoke's namespaces whose object changed since the last round, or of
// each when full says so, and deletes the copy of each namespace that the spoke no longer holds: of each that the last
// round left, or every copy of the spoke's that no namespace of the round stands for when full says so. It returns what
// the round leaves of the spoke's namespaces.
func (c *Copier) copyNamespaces(ctx context.Context, full bool, copied *tally) (map[string]seenRecord, error) {
	list := &metav1.PartialObjectMetadataList{}
	list.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("NamespaceList"))
	// The objects are only read, and none leaves the copier, so the cache needn't copy them.
	if err := c.spokeCache.List(ctx, list, client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the spoke's namespaces: %w", err)
	}
	namespaces := make(map[string]seenRecord, len(list.Items))
	for i := range list.Items {
		obj := &list.Items[i]
		if before, ok := c.namespaces[obj.Name]; ok && !full && before.version == obj.ResourceVersion {
			namespaces[obj.Name] = before
			continue
		}
		key, err := c.copyNamespace(ctx, obj, copied)
		if err != nil {
			return nil, err
		}
		namespaces[obj.Name] = seenRecord{version: obj.ResourceVersion, key: key}
	}
	if full {
		return namespaces, c.prune(ctx, namespaces, map[pair]bool{namespacePair: true})
	}
	return namespaces, c.deleteGone(ctx, c.namespaces, namespaces)
}

// copyNamespace copies the labels of the spoke's namespace that obj holds into a record of the hub's own, and returns
// its key, or the zero key when the hub refuses them. Labels that the type's schema doesn't hold, such as more than
// 1000, are refused whole, counted as invalid, and have the hub's copy deleted, so that they read as missing: cut, they
// could have a playbook match the namespace by what it isn't.
func (c *Copier) copyNamespace(ctx context.Context, obj *metav1.PartialObjectMetadata, copied *tally) (evidence.Key,
	error) {
	about, err := subject.Namespace(c.spoke, obj.Name)
	if err != nil {
		// No API server that checks its names gives such a name, which then isn't logged: it could hold the token that
		// the hub sent.
		c.refuseRecord(refusedInvalid, evidence.Key{Type: namespacePair.eventType, Source: namespacePair.source,
			Cluster: c.spoke})
		return evidence.Key{}, nil
	}
	key := evidence.Key{Subject: about, Type: namespacePair.eventType, Source: namespacePair.source, Cluster: c.spoke}
	// Sorted, the same labels make the same record, which the store doesn't write again.
	var labels sdkevidence.NamespaceLabels
	for _, k := range slices.Sorted(maps.Keys(obj.Labels)) {
		labels.Labels = append(labels.Labels, sdkevidence.KeyValue{Key: k, Value: obj.Labels[k]})
	}
	e, err := sdkevidence.New(key.Type, about, labels, sdkevidence.WithSource("/clusters/"+c.spoke+"/namespaces"))
	if err == nil {
		err = checkCore(e)
	}
	if err != nil {
		return c.refuseUnread(ctx, key)
	}
	return c.put(ctx, key, namespacesVersion, e, copied)
}
