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
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"k8s.io/utils/ptr"

	"github.com/bedag/vexplain/hack/internal/docker"
	"github.com/bedag/vexplain/internal/settings"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// sizeOf is the size of an object as the operator's own metrics measure it, such as vexplain_evidence_object_bytes:
// the length of the whole object as json.Marshal encodes it, managed fields included, close to what etcd holds.
func sizeOf(obj any) int {
	raw, err := json.Marshal(obj)
	if err != nil {
		return 0
	}
	return len(raw)
}

// tally is the count, the total and the largest of a group of sizes.
type tally struct {
	count, total, largest int
}

func (t *tally) add(size int) {
	t.count++
	t.total += size
	t.largest = max(t.largest, size)
}

// reportHoldings prints the hub's records by kind, the Evidence by collector and type with presence apart, the fits of
// the presence records and of the ImageInventory objects with their projections, and the share of etcd that the
// inventory group takes. The fits take the records of the load's images alone: those of the images that the spokes
// run for themselves, such as kind's own, have workloads of other kinds and names, and facts of failed scans.
func (m *measurement) reportHoldings(ctx context.Context, held *holdings) error {
	load := map[string]bool{}
	for _, digest := range m.digests {
		load[digest] = true
	}
	groups := map[string]*tally{}
	count := func(group string, size int) {
		if groups[group] == nil {
			groups[group] = &tally{}
		}
		groups[group].add(size)
	}
	var presence []point
	var largestPresence struct{ compressed, decoded, object, workloads int }
	for i := range held.evidence {
		e := &held.evidence[i]
		size := sizeOf(e)
		count("Evidence", size)
		if e.Spec.Type != sdkevidence.TypePresence {
			count("Evidence "+e.Spec.Source+" "+e.Spec.Type, size)
			continue
		}
		count("Evidence presence", size)
		decoded, err := presenceOf(e)
		if err != nil {
			return err
		}
		workloads, compressed := len(decoded.Workloads), len(e.Spec.Data)
		if load[strings.TrimPrefix(e.Spec.Subject, subject.Image(""))] {
			presence = append(presence, point{x: []float64{float64(workloads)}, y: []float64{float64(compressed),
				float64(ptr.Deref(e.Spec.UncompressedBytes, 0)), float64(size)}})
		}
		m.say("raw presence %s %s workloads=%d compressed=%d decoded=%d object=%d\n", ptr.Deref(e.Spec.Cluster, ""),
			e.Spec.Subject, workloads, compressed, ptr.Deref(e.Spec.UncompressedBytes, 0), size)
		if compressed > largestPresence.compressed {
			largestPresence.compressed, largestPresence.decoded = compressed, int(ptr.Deref(e.Spec.UncompressedBytes, 0))
			largestPresence.object, largestPresence.workloads = size, workloads
		}
	}
	var inventories []point
	for i := range held.inventories {
		inv := &held.inventories[i]
		size := sizeOf(inv)
		count("ImageInventory", size)
		var workloads, namespaces int
		for _, entry := range inv.Status.Clusters {
			workloads += len(entry.Workloads)
			namespaces += len(entry.Namespaces)
		}
		if load[inv.Spec.Digest] {
			inventories = append(inventories, point{x: []float64{float64(len(inv.Status.Clusters)),
				float64(workloads), float64(namespaces)}, y: []float64{float64(size)}})
		}
		m.say("raw inventory %s entries=%d workloads=%d namespaces=%d object=%d\n", inv.Spec.Digest,
			len(inv.Status.Clusters), workloads, namespaces, size)
	}
	for i := range held.sheets {
		count("ImageVerdicts", sizeOf(&held.sheets[i]))
	}
	for i := range held.ledgers {
		count("Ledger", sizeOf(&held.ledgers[i]))
	}
	for i := range held.statuses {
		count("PlaybookClusterStatus", sizeOf(&held.statuses[i]))
	}

	m.say("\nthe hub's records of the inventory group (bytes as JSON, managed fields included; %% of 512 KiB):\n")
	inventoryBytes := 0
	for _, group := range slices.Sorted(maps.Keys(groups)) {
		t := groups[group]
		m.say("  %-90s %5d objects %11d B, largest %9d B (%s)\n", group, t.count, t.total, t.largest,
			percent(float64(t.largest), triggerBytes))
		if !strings.Contains(group, " ") {
			inventoryBytes += t.total
		}
	}
	m.say("  all kinds: %d B\n", inventoryBytes)

	m.say("\nthe largest presence record: %d workloads, %d B compressed (%s of the evidence store's cap of %d B), "+
		"%d B decoded, %d B as an object (%s of 512 KiB)\n", largestPresence.workloads, largestPresence.compressed,
		percent(float64(largestPresence.compressed), settings.DefaultEvidenceMaxCompressedBytes),
		settings.DefaultEvidenceMaxCompressedBytes, largestPresence.decoded, largestPresence.object,
		percent(float64(largestPresence.object), triggerBytes))
	if err := m.reportPresenceFit(presence); err != nil {
		return err
	}
	if err := m.reportInventoryFit(inventories); err != nil {
		return err
	}
	return m.reportEtcd(ctx, inventoryBytes)
}

// percent formats part of whole as a percentage.
func percent(part, whole float64) string {
	return strconv.FormatFloat(100*part/whole, 'f', 1, 64) + "%"
}

// reportPresenceFit fits the bytes of a presence record against its workloads, compressed, decoded and as an object,
// and projects the workloads of one image in one cluster at which the record reaches the evidence store's cap, and at
// which its object reaches 512 KiB.
func (m *measurement) reportPresenceFit(points []point) error {
	m.say("\nbytes of a presence record = a + b x workloads, over the %d records of the load's images (each workload "+
		"with one pod of one container):\n", len(points))
	limits := []struct {
		what  string
		limit float64
	}{
		{"compressed, against the evidence store's cap of 768 KiB", settings.DefaultEvidenceMaxCompressedBytes},
		{"decoded, against the store's 64 MiB before compression", 64 << 20},
		{"as an object, against 0004's 512 KiB", triggerBytes},
	}
	for i, limit := range limits {
		fit, err := leastSquares(column(points, i))
		if err != nil {
			return fmt.Errorf("fit the presence records: %w", err)
		}
		m.say("  %-60s a=%8.1f b=%7.2f, largest residual %6.1f B; projected: reached at %.0f workloads\n",
			limit.what, fit.coefficients[0], fit.coefficients[1], fit.largestResidual,
			reachedAt(fit.coefficients[0], fit.coefficients[1], limit.limit))
	}
	return nil
}

// reportInventoryFit fits the bytes of an ImageInventory against its entries, the workloads that they list and the
// namespaces that they list, and projects the entries, one per cluster, at which an image's object reaches 512 KiB, and
// etcd's default limit of a request, 1.5 MiB, above which the hub can't write it at all. It does so for entries of a
// few sizes: the load's smallest, entries as large as the load's largest, and entries at the store's bounds, 100
// workloads and 100 namespaces by default, and 1000 namespaces at most.
func (m *measurement) reportInventoryFit(points []point) error {
	fit, err := leastSquares(column(points, 0))
	if err != nil {
		return fmt.Errorf("fit the ImageInventory objects: %w", err)
	}
	c := fit.coefficients
	m.say("\nbytes of an ImageInventory = a + b x entries + c x workloads listed + d x namespaces listed, over the %d "+
		"objects of the load's images:\n", len(points))
	m.say("  a=%.1f b=%.1f c=%.2f d=%.2f, largest residual %.1f B\n", c[0], c[1], c[2], c[3], fit.largestResidual)
	for _, entry := range []struct{ workloads, namespaces float64 }{{1, 1}, {28, 10}, {100, 100}, {100, 1000}} {
		perEntry := c[1] + c[2]*entry.workloads + c[3]*entry.namespaces
		m.say("  projected: entries of %3.0f workloads in %4.0f namespaces take %8.0f B each, and reach 512 KiB at "+
			"%.1f clusters, 1.5 MiB at %.1f\n", entry.workloads, entry.namespaces, perEntry,
			reachedAt(c[0], perEntry, triggerBytes), reachedAt(c[0], perEntry, etcdRequestBytes))
	}
	return nil
}

// reportEtcd prints the size of the hub's etcd, as the API server reports the file and etcd its use, and the share of
// it that the inventory group's objects take.
func (m *measurement) reportEtcd(ctx context.Context, inventoryBytes int) error {
	families, err := apiServerMetrics(ctx, m.hub)
	if err != nil {
		return err
	}
	file := gaugeOf(families, "apiserver_storage_size_bytes")
	raw, err := docker.Run(ctx, "exec", m.hub.node(), "curl", "-s", "http://127.0.0.1:2381/metrics")
	if err != nil {
		return err
	}
	etcd, err := parseMetrics([]byte(raw))
	if err != nil {
		return err
	}
	inUse := gaugeOf(etcd, "etcd_mvcc_db_total_size_in_use_in_bytes")
	m.say("\netcd of the hub: the file %.0f B, in use %.0f B; the inventory group's objects %d B, %s of the file and "+
		"%s of the use (0004's trigger: %s)\n", file, inUse, inventoryBytes, percent(float64(inventoryBytes), file),
		percent(float64(inventoryBytes), inUse), percent(triggerEtcdShare, 1))
	for _, f := range families["apiserver_storage_objects"].GetMetric() {
		if resource := labelsOf(f)["resource"]; strings.HasSuffix(resource, "."+inventoryGroup) {
			m.say("raw objects %s %.0f\n", resource, f.GetGauge().GetValue())
		}
	}
	return nil
}
