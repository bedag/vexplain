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

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// deployment is the kind of the load's workloads.
const deployment = "Deployment"

// digestOf returns a digest made up of the number n.
func digestOf(n int) string { return fmt.Sprintf("sha256:%064x", n) }

// presenceRecord returns the hub's copy of the presence of an image in a cluster, with a Deployment of each name.
func presenceRecord(t *testing.T, digest, cluster string, workloads ...string) inventoryv1alpha1.Evidence {
	t.Helper()
	presence := sdkevidence.Presence{DigestKind: sdkevidence.DigestKindRepoDigest}
	for _, workload := range workloads {
		presence.Workloads = append(presence.Workloads, sdkevidence.PresenceWorkload{APIGroup: "apps",
			Kind: deployment, Namespace: namespaceOf(0), Name: workload,
			Pods: []sdkevidence.PresencePod{{Name: workload + "-1", Node: "node", Platform: "linux/arm64"}}})
	}
	decoded, err := json.Marshal(presence)
	require.NoError(t, err)
	var data bytes.Buffer
	writer := gzip.NewWriter(&data)
	_, err = writer.Write(decoded)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return inventoryv1alpha1.Evidence{Spec: inventoryv1alpha1.EvidenceSpec{Subject: subject.Image(digest),
		Type: sdkevidence.TypePresence, Source: "workloads", Cluster: ptr.To(cluster), Data: data.Bytes(),
		Encoding: inventoryv1alpha1.EvidenceEncodingGzipJSON, UncompressedBytes: ptr.To(int64(len(decoded)))}}
}

// measurementOfTheLoad returns a measurement of two spokes whose load's images have made-up digests.
func measurementOfTheLoad() *measurement {
	m := &measurement{names: []string{"cluster-a", "cluster-b"}, digests: map[int]string{}}
	for g := range loadImages {
		m.digests[g] = digestOf(g)
	}
	return m
}

// theLoadOnTheHub returns what the hub holds once the load has arrived: each image's entries with the workloads of the
// layout, its copies of presence, its facts of one manifest, and the manifest's sheet. The objects of an image are at
// its number, in the inventories and the sheets.
func theLoadOnTheHub(t *testing.T, m *measurement) *holdings {
	t.Helper()
	held := &holdings{}
	entries := map[int][]inventoryv1alpha1.ClusterPresence{}
	for s, cluster := range m.names {
		for k, g := range imagesOf(s) {
			workloads, _ := layout(k)
			entries[g] = append(entries[g], inventoryv1alpha1.ClusterPresence{Cluster: cluster,
				WorkloadCount: ptr.To(int32(workloads))})
			names := make([]string, workloads)
			for i := range names {
				names[i] = fmt.Sprintf("%s-%02d", imageName(g), i)
			}
			held.evidence = append(held.evidence, presenceRecord(t, m.digests[g], cluster, names...))
		}
	}
	for g := range loadImages {
		manifest := digestOf(1000 + g)
		held.inventories = append(held.inventories, inventoryv1alpha1.ImageInventory{
			Spec: inventoryv1alpha1.ImageInventorySpec{Digest: m.digests[g]},
			Status: inventoryv1alpha1.ImageInventoryStatus{Clusters: entries[g], Facts: &inventoryv1alpha1.ImageFacts{
				Manifests: []inventoryv1alpha1.ManifestFact{{Platform: "linux/arm64", Digest: manifest}}}},
		})
		held.sheets = append(held.sheets, inventoryv1alpha1.ImageVerdicts{
			Spec:   inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifest, Playbook: sheetPlaybook},
			Status: inventoryv1alpha1.ImageVerdictsStatus{Counts: &inventoryv1alpha1.FindingCounts{}},
		})
	}
	return held
}

// The load has arrived when the hub holds every part of it, and each takes the tool's wait away one by one.
func TestTheLoadArrivesWithItsEntriesCopiesScansAndSheets(t *testing.T) {
	m := measurementOfTheLoad()
	missing, err := m.missing(theLoadOnTheHub(t, m))
	require.NoError(t, err)
	require.Empty(t, missing, "the hub holds the whole load")

	for want, change := range map[string]func(*holdings){
		"the inventory of img-49": func(h *holdings) { h.inventories = h.inventories[:loadImages-1] },
		"the entry of cluster-a in img-20": func(h *holdings) {
			h.inventories[20].Status.Clusters[0].WorkloadCount = ptr.To(int32(27))
		},
		"the presence of img-20 in cluster-b": func(h *holdings) {
			// A later record of the same key takes the place of the earlier, as a newer copy does.
			h.evidence = append(h.evidence, presenceRecord(t, m.digests[20], "cluster-b", "only-one"))
		},
		"the scan of img-03":  func(h *holdings) { h.inventories[3].Status.Facts = nil },
		"the sheet of img-07": func(h *holdings) { h.sheets[7].Status.Counts = nil },
	} {
		held := theLoadOnTheHub(t, m)
		change(held)
		missing, err := m.missing(held)
		require.NoError(t, err, want)
		require.Equal(t, want, missing)
	}

	held := theLoadOnTheHub(t, m)
	held.inventories[5].Status.Facts = &inventoryv1alpha1.ImageFacts{Failures: []inventoryv1alpha1.ScanFailure{
		{Source: "scanner", Reason: inventoryv1alpha1.ScanFailureReasonNotFound}}}
	_, err = m.missing(held)
	require.ErrorContains(t, err, "the scan of img-05 failed: NotFound", "a failed scan isn't waited for")
}

// The storage tallies every record once, by kind, and the Evidence also by collector and type, with presence apart;
// it fits only the load's records; and it gives the managed fields and the listed items of the largest ImageInventory,
// and the sheets' findings with their database.
func TestStorageTalliesEveryRecordOnceAndFitsTheLoadAlone(t *testing.T) {
	load, other := digestOf(1), digestOf(2)
	exposure := inventoryv1alpha1.Evidence{Spec: inventoryv1alpha1.EvidenceSpec{Subject: "workload/cluster-a/x",
		Type: sdkevidence.TypeExposure, Source: "network-reach", Cluster: ptr.To("cluster-a"), Data: []byte("x")}}
	listed := inventoryv1alpha1.ClusterPresence{Cluster: "cluster-a",
		Workloads: []inventoryv1alpha1.WorkloadReference{
			{APIGroup: ptr.To("apps"), Kind: deployment, Namespace: namespaceOf(0), Name: "img-01-00"},
			{APIGroup: ptr.To("apps"), Kind: deployment, Namespace: namespaceOf(1), Name: "img-01-01"}},
		Namespaces: []inventoryv1alpha1.NamespacePresence{{Name: namespaceOf(0)}, {Name: namespaceOf(1)}}}
	managed := []metav1.ManagedFieldsEntry{{Manager: "manager", Operation: metav1.ManagedFieldsOperationUpdate,
		FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:status":{"f:clusters":{}}}`)}}}
	held := &holdings{
		evidence: []inventoryv1alpha1.Evidence{presenceRecord(t, load, "cluster-a", "img-01-00", "img-01-01"),
			presenceRecord(t, other, "cluster-a", "kube-proxy"), exposure},
		inventories: []inventoryv1alpha1.ImageInventory{
			{ObjectMeta: metav1.ObjectMeta{ManagedFields: managed}, Spec: inventoryv1alpha1.ImageInventorySpec{Digest: load},
				Status: inventoryv1alpha1.ImageInventoryStatus{Clusters: []inventoryv1alpha1.ClusterPresence{listed,
					{Cluster: "cluster-b"}}}},
			{Spec: inventoryv1alpha1.ImageInventorySpec{Digest: other}},
		},
		sheets: []inventoryv1alpha1.ImageVerdicts{{Status: inventoryv1alpha1.ImageVerdictsStatus{
			FindingsVersion: ptr.To("v6.1.10"), Counts: &inventoryv1alpha1.FindingCounts{Affected: ptr.To(int32(1)),
				UnderInvestigation: ptr.To(int32(105)), NotAffected: ptr.To(int32(0)), Fixed: ptr.To(int32(0))}}}},
	}

	s, err := storageOf(held, map[string]bool{load: true})

	require.NoError(t, err)
	counts := map[string]int{}
	for group, tallied := range s.groups {
		counts[group] = tallied.count
	}
	require.Equal(t, map[string]int{"Evidence": 3, "Evidence presence": 2,
		"Evidence network-reach " + sdkevidence.TypeExposure: 1, "ImageInventory": 2, "ImageVerdicts": 1}, counts)
	total := sizeOf(&held.evidence[0]) + sizeOf(&held.evidence[1]) + sizeOf(&held.evidence[2]) +
		sizeOf(&held.inventories[0]) + sizeOf(&held.inventories[1]) + sizeOf(&held.sheets[0])
	require.Equal(t, total, s.total, "each record counts once, whatever groups it is in")

	require.Len(t, s.presence, 1, "the presence of the load's image alone")
	require.Equal(t, []float64{2}, s.presence[0].x)
	require.Len(t, s.inventories, 1, "the ImageInventory of the load's image alone")
	require.Equal(t, []float64{2, 2, 2}, s.inventories[0].x, "its entries, listed workloads and listed namespaces")
	require.Equal(t, 2, s.largestPresence.workloads)

	require.Equal(t, inventorySize{object: sizeOf(&held.inventories[0]), managed: sizeOf(managed),
		workload: sizeOf(listed.Workloads[0]), namespace: sizeOf(listed.Namespaces[0])}, s.largestInventory)
	require.Equal(t, map[string]int{"1 Affected, 105 UnderInvestigation, 0 NotAffected, 0 Fixed": 1}, s.findings)
	require.Equal(t, []string{"v6.1.10"}, s.versions)
}
