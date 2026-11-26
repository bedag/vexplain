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

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
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

// storage is what the hub's records come to: their bytes by group, the points of the fits, the largest presence record
// and ImageInventory, and the sheets' findings.
type storage struct {
	// groups tallies the records by kind, and the Evidence also by its collector and type, with presence apart. total
	// is the bytes of every record, each counted once.
	groups map[string]*tally
	total  int
	// presence and inventories are the points of the fits: the presence records and ImageInventory objects of the
	// load's images.
	presence, inventories []point
	largestPresence       presenceSize
	largestInventory      inventorySize
	// findings counts the sheets by their counts of findings, and versions are the database versions of the findings.
	findings map[string]int
	versions []string
	// raw are the raw numbers of each presence record and ImageInventory, a line each.
	raw []string
}

// presenceSize is the size of a presence record: its workloads, its data compressed and decoded, and its object.
type presenceSize struct{ workloads, compressed, decoded, object int }

// inventorySize is the size of an ImageInventory: its object, its managed fields, and a workload and a namespace that
// an entry lists, as JSON without their managed fields.
type inventorySize struct{ object, managed, workload, namespace int }

// storageOf measures the hub's records. The fits take the records of the load's images alone, by digest: those of the
// images that the spokes run for themselves, such as kind's own, have workloads of other kinds and names, and facts of
// failed scans.
func storageOf(held *holdings, load map[string]bool) (*storage, error) {
	s := &storage{groups: map[string]*tally{}, findings: map[string]int{}}
	count := func(size int, groups ...string) {
		s.total += size
		for _, group := range groups {
			if s.groups[group] == nil {
				s.groups[group] = &tally{}
			}
			s.groups[group].add(size)
		}
	}
	for i := range held.evidence {
		e := &held.evidence[i]
		size := sizeOf(e)
		if e.Spec.Type != sdkevidence.TypePresence {
			count(size, "Evidence", "Evidence "+e.Spec.Source+" "+e.Spec.Type)
			continue
		}
		count(size, "Evidence", "Evidence presence")
		decoded, err := presenceOf(e)
		if err != nil {
			return nil, err
		}
		p := presenceSize{workloads: len(decoded.Workloads), compressed: len(e.Spec.Data),
			decoded: int(ptr.Deref(e.Spec.UncompressedBytes, 0)), object: size}
		if load[strings.TrimPrefix(e.Spec.Subject, subject.Image(""))] {
			s.presence = append(s.presence, point{x: []float64{float64(p.workloads)},
				y: []float64{float64(p.compressed), float64(p.decoded), float64(p.object)}})
		}
		if p.compressed > s.largestPresence.compressed {
			s.largestPresence = p
		}
		s.raw = append(s.raw, fmt.Sprintf("raw presence %s %s workloads=%d compressed=%d decoded=%d object=%d",
			ptr.Deref(e.Spec.Cluster, ""), e.Spec.Subject, p.workloads, p.compressed, p.decoded, p.object))
	}
	for i := range held.inventories {
		inv := &held.inventories[i]
		size := sizeOf(inv)
		count(size, "ImageInventory")
		var workloads, namespaces int
		for _, entry := range inv.Status.Clusters {
			workloads += len(entry.Workloads)
			namespaces += len(entry.Namespaces)
		}
		if load[inv.Spec.Digest] {
			s.inventories = append(s.inventories, point{x: []float64{float64(len(inv.Status.Clusters)),
				float64(workloads), float64(namespaces)}, y: []float64{float64(size)}})
		}
		if size > s.largestInventory.object {
			s.largestInventory = inventorySizeOf(inv, size)
		}
		s.raw = append(s.raw, fmt.Sprintf("raw inventory %s entries=%d workloads=%d namespaces=%d object=%d",
			inv.Spec.Digest, len(inv.Status.Clusters), workloads, namespaces, size))
	}
	for i := range held.sheets {
		sheet := &held.sheets[i]
		count(sizeOf(sheet), "ImageVerdicts")
		if c := sheet.Status.Counts; c != nil {
			s.findings[fmt.Sprintf("%d Affected, %d UnderInvestigation, %d NotAffected, %d Fixed",
				ptr.Deref(c.Affected, 0), ptr.Deref(c.UnderInvestigation, 0), ptr.Deref(c.NotAffected, 0),
				ptr.Deref(c.Fixed, 0))]++
		}
		if version := ptr.Deref(sheet.Status.FindingsVersion, ""); version != "" && !slices.Contains(s.versions, version) {
			s.versions = append(s.versions, version)
		}
	}
	for i := range held.ledgers {
		count(sizeOf(&held.ledgers[i]), "Ledger")
	}
	for i := range held.statuses {
		count(sizeOf(&held.statuses[i]), "PlaybookClusterStatus")
	}
	slices.Sort(s.versions)
	return s, nil
}

// inventorySizeOf returns the sizes of an ImageInventory whose object is size: its managed fields, and the first
// workload and namespace that one of its entries lists.
func inventorySizeOf(inv *inventoryv1alpha1.ImageInventory, size int) inventorySize {
	found := inventorySize{object: size, managed: sizeOf(inv.ManagedFields)}
	for _, entry := range inv.Status.Clusters {
		if len(entry.Workloads) > 0 && len(entry.Namespaces) > 0 {
			found.workload, found.namespace = sizeOf(entry.Workloads[0]), sizeOf(entry.Namespaces[0])
			break
		}
	}
	return found
}

// reportHoldings prints the hub's records by kind, the Evidence by collector and type with presence apart, the largest
// presence record and ImageInventory, the sheets' findings, the fits of the presence records and of the ImageInventory
// objects with their projections, and the share of etcd that the inventory group takes.
func (m *measurement) reportHoldings(ctx context.Context, held *holdings) error {
	load := map[string]bool{}
	for _, digest := range m.digests {
		load[digest] = true
	}
	s, err := storageOf(held, load)
	if err != nil {
		return err
	}
	for _, line := range s.raw {
		m.say("%s\n", line)
	}
	m.say("\nthe hub's records of the inventory group (bytes as JSON, managed fields included; %% of 512 KiB):\n")
	for _, group := range slices.Sorted(maps.Keys(s.groups)) {
		t := s.groups[group]
		m.say("  %-90s %5d objects %11d B, largest %9d B (%s)\n", group, t.count, t.total, t.largest,
			percent(float64(t.largest), triggerBytes))
	}
	m.say("  all kinds: %d B\n", s.total)

	p := s.largestPresence
	m.say("\nthe largest presence record: %d workloads, %d B compressed (%s of the evidence store's cap of %d B), "+
		"%d B decoded, %d B as an object (%s of 512 KiB)\n", p.workloads, p.compressed,
		percent(float64(p.compressed), settings.DefaultEvidenceMaxCompressedBytes),
		settings.DefaultEvidenceMaxCompressedBytes, p.decoded, p.object, percent(float64(p.object), triggerBytes))
	inv := s.largestInventory
	m.say("the largest ImageInventory: %d B, of which %d B are managed fields (%s); a workload that it lists takes %d B "+
		"of JSON, and a namespace %d B, without their managed fields\n", inv.object, inv.managed,
		percent(float64(inv.managed), float64(inv.object)), inv.workload, inv.namespace)
	for _, findings := range slices.Sorted(maps.Keys(s.findings)) {
		m.say("the sheets: %d with the findings %s\n", s.findings[findings], findings)
	}
	m.say("the database of their findings: %s\n", strings.Join(s.versions, ", "))
	if err := m.reportPresenceFit(s.presence); err != nil {
		return err
	}
	if err := m.reportInventoryFit(s.inventories); err != nil {
		return err
	}
	return m.reportEtcd(ctx, s.total)
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
			"%.0f clusters, 1.5 MiB at %.0f\n", entry.workloads, entry.namespaces, perEntry,
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
