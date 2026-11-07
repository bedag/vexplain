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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/santhosh-tekuri/jsonschema/v6"
	ctrl "sigs.k8s.io/controller-runtime"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// exposureSchema is the schema of the data of an exposure event, which an event must follow to be read.
var exposureSchema = compileSchema(evidence.TypeExposure)

// compileSchema compiles the SDK's schema of an event type, which the SDK's own tests compile too.
func compileSchema(eventType string) *jsonschema.Schema {
	raw, _ := evidence.Schema(eventType)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		panic(fmt.Sprintf("the SDK's schema of %s isn't JSON: %v", eventType, err))
	}
	compiler := jsonschema.NewCompiler()
	url := "urn:vexplain:schema:" + eventType
	if err := compiler.AddResource(url, doc); err != nil {
		panic(fmt.Sprintf("the SDK's schema of %s can't be added: %v", eventType, err))
	}
	return compiler.MustCompile(url)
}

// workloadKey names a workload of an exposure: its API group, kind, namespace and name. An exposure subject carries no
// UID, and a spoke's collectors report only its own cluster.
type workloadKey struct{ apiGroup, kind, namespace, name string }

func keyOf(w evidence.PresenceWorkload) workloadKey {
	return workloadKey{apiGroup: w.APIGroup, kind: w.Kind, namespace: w.Namespace, name: w.Name}
}

// said is what one collector, or all of them together, say of a workload's exposure: SSVC's value, the internal reach,
// and whether an exposed workload reaches it. An empty reach says nothing.
type said struct {
	ssvc     configv1alpha1.SSVCExposure
	reach    string
	indirect bool
}

// Exposure implements collectorclient.Sink for the exposure type, and keeps each workload's exposure in memory, as
// SSVC's system exposure (Small, Controlled, Open or Unknown), with the internal reach and the indirect exposure that a
// report shows beside it (decision 0038).
//
// It keeps what each collector delivered, by workload. With several collectors, a workload's exposure is the highest
// that any of them says, and Unknown only when none says anything of it; its reach is the widest that any of them says,
// and it is indirect when any of them says so. Forget drops what one collector delivered, and nothing else. The
// snapshot of a collector replaces what it delivered, and each change and tombstone after it changes one workload.
// Whenever what is known of a workload changes, the function that watch gave is told, outside the lock.
type Exposure struct {
	log logr.Logger

	mu sync.Mutex
	// delivered is what each collector says of each workload, by collector. A collector that says nothing of a
	// workload has no entry for it.
	delivered map[string]map[workloadKey]said
	// snapshotted holds the collectors whose snapshot arrived since the start, or since they were forgotten.
	snapshotted map[string]bool
	// changed is told which workloads' exposure changed, or that any may have.
	changed func(workloads map[workloadKey]bool, all bool)
}

// NewExposure returns an Exposure that knows nothing yet.
func NewExposure() *Exposure {
	return &Exposure{
		log:         ctrl.Log.WithName("spoke-exposure"),
		delivered:   map[string]map[workloadKey]said{},
		snapshotted: map[string]bool{},
	}
}

// watch sets the function that is told of changes. The caller sets it once, before the first event.
func (e *Exposure) watch(changed func(workloads map[workloadKey]bool, all bool)) { e.changed = changed }

// Of returns a workload's exposure: the highest that any collector says, and Unknown when none says anything.
func (e *Exposure) Of(w evidence.PresenceWorkload) configv1alpha1.SSVCExposure {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.effective(keyOf(w)).ssvc
}

// ForReport returns what a report shows of a workload's exposure: its SSVC exposure, as Of gives it, and its reach,
// which is nil when no collector says anything of the workload.
func (e *Exposure) ForReport(w evidence.PresenceWorkload) WorkloadExposure {
	e.mu.Lock()
	defer e.mu.Unlock()
	known := e.effective(keyOf(w))
	out := WorkloadExposure{SSVC: known.ssvc}
	if known.reach != "" {
		out.Reach = &triagev1alpha1.ReportReach{InternalReach: triagev1alpha1.InternalReach(known.reach),
			Indirect: triagev1alpha1.IndirectExposureNotIndirect}
		if known.indirect {
			out.Reach.Indirect = triagev1alpha1.IndirectExposureIndirect
		}
	}
	return out
}

// ForImage gives the highest exposure of the workloads that run the image: Open, then Unknown, then Controlled, then
// Small. Unknown outranks Controlled because a workload of unknown exposure may be open. An image that no workload
// runs is Unknown.
func (e *Exposure) ForImage(workloads []evidence.PresenceWorkload) configv1alpha1.SSVCExposure {
	e.mu.Lock()
	defer e.mu.Unlock()
	highest := configv1alpha1.SSVCExposure("")
	for _, w := range workloads {
		if value := e.effective(keyOf(w)).ssvc; imageRank(value) > imageRank(highest) {
			highest = value
		}
	}
	if highest == "" {
		return configv1alpha1.SSVCExposureUnknown
	}
	return highest
}

// HasSnapshotsOf reports whether a snapshot of each of the collectors, by name, arrived since the start, so that
// Exposure knows what each says of its workloads.
func (e *Exposure) HasSnapshotsOf(collectors []string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, collector := range collectors {
		if !e.snapshotted[collector] {
			return false
		}
	}
	return true
}

// effective is what all collectors together say of a workload: the highest exposure, Unknown when none says anything,
// the widest reach, and indirect when any says so. The caller holds the lock.
func (e *Exposure) effective(key workloadKey) said {
	out := said{ssvc: configv1alpha1.SSVCExposureUnknown}
	for _, delivered := range e.delivered {
		value, ok := delivered[key]
		if !ok {
			continue
		}
		if out.ssvc == configv1alpha1.SSVCExposureUnknown || collectorRank(value.ssvc) > collectorRank(out.ssvc) {
			out.ssvc = value.ssvc
		}
		if reachRank(value.reach) > reachRank(out.reach) {
			out.reach = value.reach
		}
		out.indirect = out.indirect || value.indirect
	}
	return out
}

// reachRank orders internal reaches from the narrowest: Namespace, Peers, Namespaces, then Cluster. The schema of
// exposure lets no other value through, and an empty one says nothing.
func reachRank(reach string) int {
	return slices.Index([]string{"", string(triagev1alpha1.InternalReachNamespace), string(triagev1alpha1.InternalReachPeers),
		string(triagev1alpha1.InternalReachNamespaces), string(triagev1alpha1.InternalReachCluster)}, reach)
}

// collectorRank orders what collectors say: Open, then Controlled, then Small.
func collectorRank(v configv1alpha1.SSVCExposure) int {
	switch v {
	case configv1alpha1.SSVCExposureOpen:
		return 3
	case configv1alpha1.SSVCExposureControlled:
		return 2
	default:
		return 1
	}
}

// imageRank orders the exposures of an image's workloads: Open, then Unknown, then Controlled, then Small.
func imageRank(v configv1alpha1.SSVCExposure) int {
	switch v {
	case configv1alpha1.SSVCExposureOpen:
		return 4
	case configv1alpha1.SSVCExposureUnknown:
		return 3
	case configv1alpha1.SSVCExposureControlled:
		return 2
	case configv1alpha1.SSVCExposureSmall:
		return 1
	default:
		return 0
	}
}

// exposureValue maps what a collector says of a workload to SSVC's value: exposed from outside is Open, reachable
// indirectly or from beyond its namespace is Controlled, and reachable from its own namespace alone is Small.
func exposureValue(data evidence.Exposure) configv1alpha1.SSVCExposure {
	switch {
	case data.External.Exposed:
		return configv1alpha1.SSVCExposureOpen
	case data.Indirect, data.InternalReach == "Peers", data.InternalReach == "Namespaces",
		data.InternalReach == "Cluster":
		return configv1alpha1.SSVCExposureControlled
	default:
		return configv1alpha1.SSVCExposureSmall
	}
}

// parseExposure reads an exposure event: the workload that it is about, and what it says. Its data must follow the
// schema of exposure, so that an unknown reach isn't taken for the smallest.
func parseExposure(ev cloudevents.Event) (workloadKey, said, error) {
	if ev.Type() != evidence.TypeExposure {
		return workloadKey{}, said{}, errNotExposure
	}
	key, err := workloadOf(ev.Subject())
	if err != nil {
		return workloadKey{}, said{}, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(ev.Data()))
	if err != nil {
		return workloadKey{}, said{}, errors.New("its data isn't JSON")
	}
	if err := exposureSchema.Validate(doc); err != nil {
		return workloadKey{}, said{}, errors.New("its data doesn't follow the schema of exposure")
	}
	var data evidence.Exposure
	if err := json.Unmarshal(ev.Data(), &data); err != nil {
		return workloadKey{}, said{}, errors.New("its data can't be read as exposure")
	}
	return key, said{ssvc: exposureValue(data), reach: data.InternalReach, indirect: data.Indirect}, nil
}

// errNotExposure marks an event of another type than exposure.
var errNotExposure = errors.New("the event isn't exposure")

// workloadOf reads the workload that a subject names.
func workloadOf(about string) (workloadKey, error) {
	parsed, err := subject.Parse(about)
	if err != nil || parsed.Kind != subject.KindWorkload {
		return workloadKey{}, errors.New("its subject is no workload")
	}
	w := parsed.Workload
	return workloadKey{apiGroup: w.Group, kind: w.Kind, namespace: w.Namespace, name: w.Name}, nil
}

// Snapshot replaces what the collector delivered with the exposure of its snapshot. An event that can't be read is
// dropped: its workload is missing from the snapshot.
func (e *Exposure) Snapshot(collector string, events []cloudevents.Event) {
	fresh := map[workloadKey]said{}
	for _, ev := range events {
		key, value, err := parseExposure(ev)
		if err != nil {
			e.drop(collector, err)
			continue
		}
		fresh[key] = value
	}
	e.mu.Lock()
	first := !e.snapshotted[collector]
	e.snapshotted[collector] = true
	changed := e.replace(collector, fresh)
	e.mu.Unlock()
	e.tell(changed, first)
}

// Upsert takes the exposure of one workload after the snapshot.
func (e *Exposure) Upsert(collector string, ev cloudevents.Event) {
	key, value, err := parseExposure(ev)
	if err != nil {
		e.drop(collector, err)
		return
	}
	e.mu.Lock()
	changed := e.setOne(collector, key, &value)
	e.mu.Unlock()
	e.tell(changed, false)
}

// Remove takes a tombstone: the collector's exposure of a workload is gone.
func (e *Exposure) Remove(collector, eventType, about string) {
	if eventType != evidence.TypeExposure {
		return
	}
	key, err := workloadOf(about)
	if err != nil {
		return
	}
	e.mu.Lock()
	changed := e.setOne(collector, key, nil)
	e.mu.Unlock()
	e.tell(changed, false)
}

// SourceChanged does nothing: exposure comes from the collectors' streams.
func (e *Exposure) SourceChanged(string, []string) {}

// Forget drops what the collector delivered, because its Collector is gone, or it no longer delivers exposure. A
// collector of the name that delivers exposure again starts with a snapshot of its own.
func (e *Exposure) Forget(collector string) {
	e.mu.Lock()
	changed := e.replace(collector, nil)
	delete(e.snapshotted, collector)
	e.mu.Unlock()
	e.tell(changed, false)
}

// replace sets what the collector delivered, and returns the workloads whose exposure changed by it. The caller holds
// the lock.
func (e *Exposure) replace(collector string, fresh map[workloadKey]said) map[workloadKey]bool {
	old := e.delivered[collector]
	before := make(map[workloadKey]said, len(old)+len(fresh))
	for key := range old {
		before[key] = e.effective(key)
	}
	for key := range fresh {
		if _, ok := before[key]; !ok {
			before[key] = e.effective(key)
		}
	}
	if len(fresh) == 0 {
		delete(e.delivered, collector)
	} else {
		e.delivered[collector] = fresh
	}
	changed := map[workloadKey]bool{}
	for key, was := range before {
		if e.effective(key) != was {
			changed[key] = true
		}
	}
	return changed
}

// setOne sets what the collector says of one workload, or drops it when value is nil, and returns the workloads whose
// exposure changed by it. The caller holds the lock.
func (e *Exposure) setOne(collector string, key workloadKey, value *said) map[workloadKey]bool {
	before := e.effective(key)
	if value == nil {
		delete(e.delivered[collector], key)
		if len(e.delivered[collector]) == 0 {
			delete(e.delivered, collector)
		}
	} else {
		if e.delivered[collector] == nil {
			e.delivered[collector] = map[workloadKey]said{}
		}
		e.delivered[collector][key] = *value
	}
	if e.effective(key) == before {
		return nil
	}
	return map[workloadKey]bool{key: true}
}

// tell passes a change to the function that watches, outside the lock. all says that the first snapshot of a
// collector arrived, after which any workload's exposure may be known that wasn't.
func (e *Exposure) tell(changed map[workloadKey]bool, all bool) {
	if e.changed != nil && (all || len(changed) > 0) {
		e.changed(changed, all)
	}
}

// drop logs an event that Exposure can't read. The reason repeats nothing of the event, which the collector chose.
func (e *Exposure) drop(collector string, err error) {
	if !errors.Is(err, errNotExposure) {
		e.log.Error(err, "Dropped an exposure event that can't be read", "collector", collector)
	}
}
