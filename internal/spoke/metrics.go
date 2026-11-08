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

package spoke

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/text"
)

// The series that the reports give, and the label values that they share.
const (
	clusterLabel   = "cluster"
	namespaceLabel = "namespace"
	workloadLabel  = "workload"
	digestSeries   = "digest"
	cveLabel       = "cve"
	verdictLabel   = "verdict"
	urgencyLabel   = "urgency"
	reviewLabel    = "review_state"
	stageLabel     = "stage"
	collectorLabel = "collector"
	sourceLabel    = "source"

	// settledUrgency is the urgency label of a settled finding: no action is due, and a report keeps no urgency for it.
	settledUrgency = "None"

	// The funnel's stages, spelt as the API spells a status.
	stageFlagged = "Flagged"
	stageSettled = "Settled"

	// scrapeTimeout bounds the reads that a scrape makes.
	scrapeTimeout = 5 * time.Second
)

var (
	findingsDesc = prometheus.NewDesc("vexplain_findings",
		"Findings of the workloads by verdict. An open finding (Affected or UnderInvestigation) counts once for each "+
			"vulnerability and package of a workload, whether or not an action of its report lists it. A settled finding "+
			"(NotAffected or Fixed) has the urgency None and counts once for each manifest, from the sheets' counts, so a "+
			"vulnerability that two platforms share counts twice. A report's summary counts the same.",
		[]string{clusterLabel, namespaceLabel, verdictLabel, urgencyLabel, reviewLabel}, nil)
	openCaseDesc = prometheus.NewDesc("vexplain_open_case",
		"A finding that needs action, for each workload, image digest and CVE, with the verdict and urgency that the "+
			"image's own results give it. Where those results disagree, as the sheets of an image's variants can, or as "+
			"two packages of the image can, the CVE has one series for each verdict and urgency that they give. It covers "+
			"every open finding of the workload, also those whose IDs or action its report leaves out.",
		[]string{clusterLabel, namespaceLabel, workloadLabel, digestSeries, cveLabel, verdictLabel, urgencyLabel}, nil)
	funnelDesc = prometheus.NewDesc("vexplain_funnel",
		"Findings of the workloads by stage, counted once for each manifest from the sheets' counts: Flagged for all of "+
			"them, Settled for those that a rule settled, then Affected and UnderInvestigation for those that need action.",
		[]string{clusterLabel, stageLabel}, nil)
	collectorReadyDesc = prometheus.NewDesc("vexplain_collector_ready",
		"1 when the Ready condition of the collector is True, 0 otherwise.",
		[]string{clusterLabel, collectorLabel}, nil)
	collectorSourceAgeDesc = prometheus.NewDesc("vexplain_collector_source_age_seconds",
		"Age in seconds of each source of a collector that says when its data was built, such as a vulnerability "+
			"database: the time since the build time that the Collector's status.sources record.",
		[]string{clusterLabel, collectorLabel, sourceLabel}, nil)
)

// openCase is one case of the worklist: a vulnerability that needs action in an image of a workload, with the verdict
// and urgency that the image's own sheet gives it.
type openCase struct{ cve, digest, verdict, urgency string }

// casesOf lists the cases of a workload: every finding that needs action in the sheets of its images, whether or not the
// report lists an action for it. A sheet may say Affected where another says UnderInvestigation, so each image gets
// what its own sheet says, and an image whose variants' sheets disagree gets a case for each verdict and urgency.
func casesOf(images []RunningImage, sheets map[string]*inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts, exposure configv1alpha1.SSVCExposure, cfg settings.Effective) []openCase {
	var out []openCase
	for _, s := range slots(images) {
		for _, manifest := range manifestsFor(facts[s.digest], s.platform) {
			sheet := sheets[manifest]
			if stateOf(sheet) == triagev1alpha1.ReportImageStatePending {
				continue
			}
			for _, f := range sheet.Status.Findings {
				if open, ok := candidateOf(f, exposure, cfg); ok {
					out = append(out, openCase{open.id, s.digest, string(open.status), string(open.urgency)})
				}
			}
		}
	}
	return out
}

// openCount is the number of open findings of a workload with one verdict, urgency and review state.
type openCount struct{ verdict, urgency, reviewState string }

// reportSeries is what one report gives the series: the little that they need of its rendering.
type reportSeries struct {
	cluster, workload             string
	affected, underInvestigation  int32
	notAffected, fixed            int32
	open                          map[openCount]int32
	cases                         []openCase
	ownerLabels, ownerAnnotations map[string]string
}

// seriesOf reduces the rendering of a workload's report to what the series need: its open findings, each once for a
// vulnerability and a package, whether or not an action of the report lists them; the counts of its sheets; and its
// owner values. cases are the cases of the worklist. Equal cases are kept once. None of it reads the report's actions.
func seriesOf(cluster, workload string, r rendering, cases []openCase) reportSeries {
	out := reportSeries{cluster: cluster, workload: workload, open: map[openCount]int32{}}
	out.affected, out.underInvestigation = r.counts.affected, r.counts.underInvestigation
	out.notAffected, out.fixed = r.counts.notAffected, r.counts.fixed
	for _, c := range r.open {
		out.open[openCount{string(c.status), string(c.urgency), c.reviewState}]++
	}
	seen := map[openCase]bool{}
	for _, c := range cases {
		if !seen[c] {
			seen[c] = true
			out.cases = append(out.cases, c)
		}
	}
	for _, o := range r.status.Owner {
		switch o.Source {
		case triagev1alpha1.OwnerSourceNamespaceLabel:
			out.ownerLabels = setOwner(out.ownerLabels, o)
		case triagev1alpha1.OwnerSourceNamespaceAnnotation:
			out.ownerAnnotations = setOwner(out.ownerAnnotations, o)
		}
	}
	return out
}

func setOwner(m map[string]string, o triagev1alpha1.OwnerValue) map[string]string {
	if m == nil {
		m = map[string]string{}
	}
	m[o.Key] = ptr.Deref(o.Value, "")
	return m
}

// ReportsCollector turns the reports that the renderer looks at into Prometheus series. It holds one entry for each
// report, which the renderer sets whenever it looks at the report and deletes with it, and builds the series from the
// entries when it is scraped. Owner info has label names that depend on the keys that the admin allowlisted, so it is
// built as const metrics, as kube-state-metrics builds its label metrics.
type ReportsCollector struct {
	mu      sync.Mutex
	entries map[types.NamespacedName]reportSeries
}

// NewReportsCollector returns a collector without entries.
func NewReportsCollector() *ReportsCollector {
	return &ReportsCollector{entries: map[types.NamespacedName]reportSeries{}}
}

func (c *ReportsCollector) set(key types.NamespacedName, s reportSeries) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = s
}

func (c *ReportsCollector) delete(key types.NamespacedName) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Describe sends nothing: the owner info's labels aren't known beforehand, so the collector is unchecked.
func (c *ReportsCollector) Describe(chan<- *prometheus.Desc) {}

// Collect sends the series of the entries, in a stable order.
func (c *ReportsCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	keys := make([]types.NamespacedName, 0, len(c.entries))
	entries := make(map[types.NamespacedName]reportSeries, len(c.entries))
	for k, v := range c.entries {
		keys = append(keys, k)
		entries[k] = v
	}
	c.mu.Unlock()
	slices.SortFunc(keys, func(a, b types.NamespacedName) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})

	type findingsKey struct{ cluster, namespace, verdict, urgency, reviewState string }
	findings := map[findingsKey]float64{}
	funnel := map[string]map[string]float64{}
	owners := map[[2]string]reportSeries{}
	cases := map[[7]string]bool{}
	for _, k := range keys {
		e := entries[k]
		ns := text.Printable(k.Namespace)
		cluster := text.Printable(e.cluster)
		settled := e.notAffected + e.fixed
		if funnel[cluster] == nil {
			funnel[cluster] = map[string]float64{}
		}
		funnel[cluster][stageFlagged] += float64(e.affected + e.underInvestigation + settled)
		funnel[cluster][stageSettled] += float64(settled)
		funnel[cluster][string(inventoryv1alpha1.VEXStatusAffected)] += float64(e.affected)
		funnel[cluster][string(inventoryv1alpha1.VEXStatusUnderInvestigation)] += float64(e.underInvestigation)
		for verdict, n := range map[string]int32{
			string(inventoryv1alpha1.VEXStatusNotAffected): e.notAffected, string(inventoryv1alpha1.VEXStatusFixed): e.fixed,
		} {
			if n > 0 {
				findings[findingsKey{cluster, ns, verdict, settledUrgency, reviewRuleSettled}] += float64(n)
			}
		}
		for f, n := range e.open {
			findings[findingsKey{cluster, ns, f.verdict, f.urgency, f.reviewState}] += float64(n)
		}
		for _, f := range e.cases {
			label := [7]string{cluster, ns, text.Printable(e.workload), text.Printable(f.digest), text.Printable(f.cve),
				f.verdict, f.urgency}
			if !cases[label] {
				cases[label] = true
				emit(ch, openCaseDesc, 1, label[:]...)
			}
		}
		if _, ok := owners[[2]string{cluster, ns}]; !ok {
			owners[[2]string{cluster, ns}] = e
		}
	}
	findingKeys := make([]findingsKey, 0, len(findings))
	for k := range findings {
		findingKeys = append(findingKeys, k)
	}
	slices.SortFunc(findingKeys, func(a, b findingsKey) int {
		return slices.Compare([]string{a.cluster, a.namespace, a.verdict, a.urgency, a.reviewState},
			[]string{b.cluster, b.namespace, b.verdict, b.urgency, b.reviewState})
	})
	for _, k := range findingKeys {
		emit(ch, findingsDesc, findings[k], k.cluster, k.namespace, k.verdict, k.urgency, k.reviewState)
	}
	for cluster, stages := range funnel {
		for stage, n := range stages {
			emit(ch, funnelDesc, n, cluster, stage)
		}
	}
	// One series per namespace, from the first report in order that has the namespace's owner values.
	for k, e := range owners {
		emitOwnerInfo(ch, k[0], k[1], e)
	}
}

func emit(ch chan<- prometheus.Metric, desc *prometheus.Desc, value float64, labels ...string) {
	ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labels...)
}

// emitOwnerInfo sends the info series of a namespace, with a label for each allowlisted key of its labels and
// annotations.
func emitOwnerInfo(ch chan<- prometheus.Metric, cluster, namespace string, e reportSeries) {
	names := []string{clusterLabel, namespaceLabel}
	values := []string{cluster, namespace}
	used := map[string]bool{clusterLabel: true, namespaceLabel: true}
	for _, from := range []struct {
		prefix string
		keys   map[string]string
	}{{"label_", e.ownerLabels}, {"annotation_", e.ownerAnnotations}} {
		keys := make([]string, 0, len(from.keys))
		for k := range from.keys {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			name := uniqueName(used, from.prefix+SanitizeLabelName(k))
			used[name] = true
			names = append(names, name)
			values = append(values, text.Printable(from.keys[k]))
		}
	}
	desc := prometheus.NewDesc("vexplain_namespace_owner_info",
		"The labels and annotations of a namespace that the admin allowlisted to say whom to inform, one series for "+
			"each namespace. Join it to the other series on cluster and namespace.", names, nil)
	ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1, values...)
}

// SanitizeLabelName makes a label or annotation key a Prometheus label name as kube-state-metrics does: every
// character outside [a-zA-Z0-9_] becomes an underscore.
func SanitizeLabelName(key string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		}
		return '_'
	}, key)
}

// uniqueName returns name, or name with the first suffix _2, _3 and so on that no other label has. Keys such as
// "a.b" and "a-b" sanitise to one name, and a series with a repeated label name is invalid.
func uniqueName(used map[string]bool, name string) string {
	if !used[name] {
		return name
	}
	for i := 2; ; i++ {
		if candidate := name + "_" + strconv.Itoa(i); !used[candidate] {
			return candidate
		}
	}
}

// CollectorsCollector reports, when it is scraped, whether each Collector is ready, from its Ready condition, and the
// age of each of its sources that has a build time, from its status.sources, so that the age grows between the checks
// of the deployer, which writes the sources only when they change.
type CollectorsCollector struct {
	reader client.Reader
	log    logr.Logger
	// now tells the time of a scrape.
	now func() time.Time
}

// NewCollectorsCollector returns a collector that reads the Collectors, and the cluster's name, through reader.
func NewCollectorsCollector(reader client.Reader, log logr.Logger) *CollectorsCollector {
	return &CollectorsCollector{reader: reader, log: log, now: time.Now}
}

// Describe sends the descriptions of its series.
func (c *CollectorsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collectorReadyDesc
	ch <- collectorSourceAgeDesc
}

// Collect sends 1 for each Collector whose Ready condition is True and 0 for each other, and the age of each source
// that has a build time. A failed read sends an invalid metric, which the scrape reports as an error, and no value that
// might be wrong.
func (c *CollectorsCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	cfg, err := settings.Load(ctx, c.reader)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(collectorReadyDesc, err)
		return
	}
	var list configv1alpha1.CollectorList
	if err := c.reader.List(ctx, &list); err != nil {
		c.log.Error(err, "Could not list the collectors for the metrics")
		ch <- prometheus.NewInvalidMetric(collectorReadyDesc, err)
		return
	}
	now := c.now()
	for _, obj := range list.Items {
		ready := 0.0
		if meta.IsStatusConditionTrue(obj.Status.Conditions, configv1alpha1.ConditionReady) {
			ready = 1
		}
		emit(ch, collectorReadyDesc, ready, text.Printable(cfg.ClusterName), text.Printable(obj.Name))
		for _, source := range obj.Status.Sources {
			if source.BuiltTime == nil {
				continue
			}
			emit(ch, collectorSourceAgeDesc, now.Sub(source.BuiltTime.Time).Seconds(), text.Printable(cfg.ClusterName),
				text.Printable(obj.Name), text.Printable(source.Name))
		}
	}
}
