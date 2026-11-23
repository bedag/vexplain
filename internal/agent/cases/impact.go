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

package cases

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"

	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/urgency"
)

// maxOwners is how many namespaces a case names with their owner values.
const maxOwners = 5

// maxSubject is the longest subject that the evidence store keeps, which an Assessment's queue holds too.
const maxSubject = 512

// presence is where a platform manifest runs, as the hub's inventory holds it for the digests whose facts name it.
type presence struct {
	repositories          []string
	platform              string
	clusters              []string
	namespaces, resources int32
	// byExposure counts the workloads by their exposure, and groups groups them by their exposure and the rules that
	// decided it, when the exposure rules decide it.
	byExposure map[configv1alpha1.SSVCExposure]int32
	groups     []ExposureGroup
	owners     []NamespaceOwners
}

// presenceOf reads where the manifest runs: the entries of the clusters of each digest whose facts name it, but those
// whose nodes run another platform. With exposures, the exposure rules of the playbook decide the exposure of the
// workloads, as byRules counts them. Without, they count as the inventory holds them.
func presenceOf(ctx context.Context, inv inventory.Store, manifest, playbook string, exposures Exposures) (presence, error) {
	digests, err := inv.ManifestReferences(ctx, manifest)
	if err != nil {
		return presence{}, err
	}
	p := presence{byExposure: map[configv1alpha1.SSVCExposure]int32{}}
	clusters := map[string]bool{}
	var places []Place
	counted := map[Place]int32{}
	for _, digest := range digests {
		obj, err := inv.Get(ctx, digest)
		if err != nil {
			return presence{}, err
		}
		if obj == nil {
			continue
		}
		platform := platformOf(obj.Status.Facts, manifest)
		p.platform = cmp.Or(p.platform, platform)
		for _, entry := range obj.Status.Clusters {
			if !runsOn(entry.Platforms, platform) {
				continue
			}
			clusters[entry.Cluster] = true
			p.repositories = append(p.repositories, entry.Repositories...)
			p.namespaces += ptr.Deref(entry.NamespaceCount, 0)
			p.resources += ptr.Deref(entry.WorkloadCount, 0)
			for _, ns := range entry.Namespaces {
				p.owners = append(p.owners, NamespaceOwners{Cluster: entry.Cluster, Namespace: ns.Name, Owner: ns.Owner})
			}
			if exposures == nil {
				countAsInventory(p.byExposure, entry)
				continue
			}
			place := Place{Digest: digest, Cluster: entry.Cluster}
			places = append(places, place)
			counted[place] += ptr.Deref(entry.WorkloadCount, 0)
		}
	}
	if exposures != nil {
		named, err := exposures.Of(ctx, playbook, manifest, places)
		if err != nil {
			return presence{}, err
		}
		p.byExposure, p.groups = byRules(places, counted, named)
	}
	slices.Sort(p.repositories)
	p.repositories = slices.Compact(p.repositories)
	p.clusters = slices.Sorted(maps.Keys(clusters))
	slices.SortFunc(p.owners, func(a, b NamespaceOwners) int {
		return cmp.Or(cmp.Compare(a.Cluster, b.Cluster), cmp.Compare(a.Namespace, b.Namespace))
	})
	p.owners = slices.CompactFunc(p.owners, func(a, b NamespaceOwners) bool {
		return a.Cluster == b.Cluster && a.Namespace == b.Namespace
	})
	p.owners = slices.Clip(p.owners[:min(len(p.owners), maxOwners)])
	return p, nil
}

// countAsInventory adds the workloads of a cluster's entry to the counts by exposure as the inventory holds them, as the
// spoke decides them: the counts of its namespaces, and the workloads of the namespaces that it leaves out, past its
// cap, at its highest exposure, which errs towards urgency.
func countAsInventory(byExposure map[configv1alpha1.SSVCExposure]int32, entry inventoryv1alpha1.ClusterPresence) {
	workloads := ptr.Deref(entry.WorkloadCount, 0)
	for _, ns := range entry.Namespaces {
		c := ns.WorkloadsByExposure
		for level, n := range map[configv1alpha1.SSVCExposure]*int32{configv1alpha1.SSVCExposureOpen: c.Open,
			configv1alpha1.SSVCExposureControlled: c.Controlled, configv1alpha1.SSVCExposureSmall: c.Small,
			configv1alpha1.SSVCExposureUnknown: c.Unknown} {
			byExposure[level] += ptr.Deref(n, 0)
			workloads -= ptr.Deref(n, 0)
		}
	}
	if workloads > 0 {
		level := configv1alpha1.SSVCExposure(ptr.Deref(entry.Exposure, inventoryv1alpha1.SSVCExposureUnknown))
		byExposure[level] += workloads
	}
}

// byRules counts the workloads that run a manifest by their exposure, and groups them, as the exposure rules decided it:
// each workload that presence names in a place counts once, with its exposure, also where two places name it, as the
// digests of an index and of its manifest do; each workload that the inventory counts in a place and presence doesn't
// name there counts as Unknown, as all of a place whose presence hasn't reached the hub do. The counts hold every
// workload, and the groups are the first MaxExposureGroups in their order.
func byRules(places []Place, counted map[Place]int32, named map[Place][]WorkloadExposure) (
	map[configv1alpha1.SSVCExposure]int32, []ExposureGroup) {
	decided := map[string]WorkloadExposure{}
	var unnamed int32
	for _, p := range places {
		unnamed += max(0, counted[p]-int32(len(named[p])))
		for _, w := range named[p] {
			if d, seen := decided[w.Subject]; !seen || exposureRank(w.Exposure) > exposureRank(d.Exposure) {
				decided[w.Subject] = w
			}
		}
	}
	byExposure := map[configv1alpha1.SSVCExposure]int32{}
	var groups []ExposureGroup
	type key struct {
		exposure       configv1alpha1.SSVCExposure
		rules, missing string
	}
	index := map[key]int{}
	add := func(exposure configv1alpha1.SSVCExposure, rules, missing []string, n int32, subject string) {
		rules, missing = rules[:min(len(rules), MaxGroupNames)], missing[:min(len(missing), MaxGroupNames)]
		k := key{exposure, strings.Join(rules, ","), strings.Join(missing, ",")}
		i, ok := index[k]
		if !ok {
			i, index[k] = len(groups), len(groups)
			groups = append(groups, ExposureGroup{Exposure: exposure, Rules: rules, Missing: missing})
		}
		groups[i].Workloads += n
		byExposure[exposure] += n
		// A longer subject is no workload's whose exposure the hub can hold, and no Assessment holds it: it counts unnamed.
		if subject != "" && len(subject) <= maxSubject {
			groups[i].First = append(groups[i].First, subject)
		}
	}
	for _, w := range decided {
		// No rule concludes Unknown: an Unknown workload's rules are those that couldn't be evaluated.
		add(w.Exposure, append(slices.Clone(w.Rules), w.Failed...), w.Missing, 1, w.Subject)
	}
	if unnamed > 0 {
		add(configv1alpha1.SSVCExposureUnknown, nil, nil, unnamed, "")
	}
	for i := range groups {
		slices.Sort(groups[i].First)
		groups[i].First = slices.Clip(groups[i].First[:min(len(groups[i].First), MaxGroupFirst)])
	}
	slices.SortFunc(groups, func(a, b ExposureGroup) int {
		return cmp.Or(cmp.Compare(exposureRank(b.Exposure), exposureRank(a.Exposure)), slices.Compare(a.Rules, b.Rules),
			slices.Compare(a.Missing, b.Missing))
	})
	return byExposure, groups[:min(len(groups), MaxExposureGroups)]
}

// platformOf returns the platform under which facts list the manifest, and "" when they don't.
func platformOf(facts *inventoryv1alpha1.ImageFacts, manifest string) string {
	if facts == nil {
		return ""
	}
	for _, m := range facts.Manifests {
		if m.Digest == manifest {
			return m.Platform
		}
	}
	return ""
}

// runsOn reports whether nodes of the running platforms run the manifest of the platform. An entry that names no
// platform, or a manifest of no known platform, may run it.
func runsOn(running []string, platform string) bool {
	return platform == "" || len(running) == 0 ||
		slices.ContainsFunc(running, func(r string) bool { return inventory.PlatformCovers(platform, r) })
}

// impact returns the impact of a case of the findings where the manifest runs: the urgency of the case at each
// exposure of its workloads, by the table that the overrides change.
func (p presence) impact(findings []inventoryv1alpha1.Finding, overrides []configv1alpha1.UrgencyOverride) Impact {
	im := Impact{
		Clusters: int32(len(p.clusters)), Namespaces: p.namespaces, Resources: p.resources,
		Owners: p.owners, ClusterNames: p.clusters, WorkloadsByExposure: maps.Clone(p.byExposure), Exposure: p.groups,
	}
	for level, n := range p.byExposure {
		if n <= 0 {
			continue
		}
		if exposureRank(level) > exposureRank(im.HighestExposure) {
			im.HighestExposure = level
		}
		outcome := decide(findings, level, overrides)
		if urgencyRank(outcome) < urgencyRank(im.HighestUrgency) {
			im.HighestUrgency = outcome
		}
		if outcome == configv1alpha1.SSVCOutcomeImmediate || outcome == configv1alpha1.SSVCOutcomeOutOfCycle {
			im.UrgentResources += n
		}
	}
	return im
}

// decide returns the most urgent outcome of the findings for a workload of the exposure.
func decide(findings []inventoryv1alpha1.Finding, exposure configv1alpha1.SSVCExposure,
	overrides []configv1alpha1.UrgencyOverride) configv1alpha1.SSVCOutcome {
	var most configv1alpha1.SSVCOutcome
	for _, f := range findings {
		if o := urgency.Decide(urgency.FromFinding(f, exposure), overrides); urgencyRank(o) < urgencyRank(most) {
			most = o
		}
	}
	return most
}

// exposureRank orders the exposures, the highest the largest: Open, then Unknown and any value that this version
// doesn't know, which urgency counts as Open, then Controlled, Small, and none.
func exposureRank(e configv1alpha1.SSVCExposure) int {
	switch e {
	case configv1alpha1.SSVCExposureOpen:
		return 4
	case configv1alpha1.SSVCExposureControlled:
		return 2
	case configv1alpha1.SSVCExposureSmall:
		return 1
	case "":
		return 0
	}
	return 3
}
