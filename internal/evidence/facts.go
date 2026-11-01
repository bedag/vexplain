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

package evidence

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// The limits of the facts of an image, which the schema of an ImageInventory sets.
const (
	maxManifests     = 16
	maxEvidenceFacts = 32
	maxReasonLength  = 64
	maxMessageLength = 256
)

// reasonPattern matches a reason that the facts hold: a word in CamelCase, as the reasons that
// vexplain defines are.
var reasonPattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)

// FactsWriter writes the facts of the images from what their collectors deliver: the manifests that
// the evidence names for each platform, what evidence there is of each source and type, and why the
// last attempt of a collector failed. A reader learns them without knowing any type.
//
// It writes through inventory.Store, which never creates an ImageInventory: only the presence of a
// digest does. Facts about an image that is gone are dropped, and are no error. image is the digest
// that names the ImageInventory, as the container runtime reports it, and source is the name of the
// Collector.
type FactsWriter interface {
	// Succeeded records the manifests per platform of an image, and each event's source, type,
	// version, time and coverage. It never creates an ImageInventory.
	//
	// The manifests are those that the events are about, each with the platform that its events
	// carry, and they replace those that the facts held, as a new scan's do. Events that name no
	// manifest leave them. Each type of the events gets one entry of evidence: when several events
	// share it, the earliest of their times, and the lowest of their coverages, or none when one of
	// them has none. It replaces the entry of the same source and type, and leaves the others. A
	// failure of the source is over.
	//
	// It refuses, and writes nothing, events that aren't evidence, two manifests of one platform, and
	// what the facts can't hold, such as more than 16 manifests or more than 32 entries of evidence.
	Succeeded(ctx context.Context, image string, source, collectorVersion string, events []cloudevents.Event) error
	// Failed records why the last attempt of a collector failed. It keeps the manifests and the
	// evidence, and counts the attempts of the source that have failed in a row: one more than the
	// failure that it replaces counted, if that was of the same source, and one otherwise.
	//
	// reason comes from vexplain's open vocabulary, such as Unauthorized. A reason that the facts
	// can't hold, which is not a word in CamelCase of at most 64 characters, is recorded as Internal:
	// a failure for a reason of its own. message says more: it is made printable and cut to 256
	// characters, and an empty one is left out.
	Failed(ctx context.Context, image string, source, reason, message string) error // keeps the facts, counts attempts
}

// NewFactsWriter returns a FactsWriter that writes through store.
func NewFactsWriter(store inventory.Store) FactsWriter {
	return &factsWriter{store: store}
}

// factsWriter writes the facts through an inventory.Store.
type factsWriter struct {
	store inventory.Store
}

func (w *factsWriter) Succeeded(ctx context.Context, image string, source, collectorVersion string,
	events []cloudevents.Event) error {
	if !isCollectorName(source) {
		return errors.New("source: the name of a Collector, a DNS-1123 label of at most 44 characters")
	}
	if collectorVersion == "" || utf8.RuneCountInString(collectorVersion) > maxCollectorVersionLength {
		return fmt.Errorf("collector version: 1 to %d characters", maxCollectorVersionLength)
	}
	s, err := successOf(source, collectorVersion, events, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("record the evidence of Collector %q about image %s: %w", source, image, err)
	}
	found, err := w.store.UpdateFacts(ctx, image, s.apply)
	if err != nil {
		return fmt.Errorf("record the evidence of Collector %q about image %s: %w", source, image, err)
	}
	if !found {
		logf.FromContext(ctx).Info("Dropped the facts of the evidence of an image that is gone", "image", image, "source", source)
	}
	return nil
}

func (w *factsWriter) Failed(ctx context.Context, image string, source, reason, message string) error {
	if !isCollectorName(source) {
		return errors.New("source: the name of a Collector, a DNS-1123 label of at most 44 characters")
	}
	recorded := inventoryv1alpha1.ScanFailureReason(reason)
	if len(reason) > maxReasonLength || !reasonPattern.MatchString(reason) {
		// The reason is the collector's text, so it isn't logged.
		logf.FromContext(ctx).Info("A collector reported a failure for a reason that the facts can't hold; it is recorded as Internal",
			"image", image, "source", source)
		recorded = inventoryv1alpha1.ScanFailureReasonInternal
	}
	text := printable(message, maxMessageLength)
	failed := metav1.NewTime(time.Now().UTC())
	found, err := w.store.UpdateFacts(ctx, image, func(facts *inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error) {
		attempts := int32(1)
		if facts == nil {
			facts = &inventoryv1alpha1.ImageFacts{}
		} else if earlier := facts.Failure; earlier != nil && earlier.Source == source {
			attempts = earlier.Attempts
			// The count stops at the largest that the API holds, rather than wrap around.
			if attempts < math.MaxInt32 {
				attempts++
			}
		}
		facts.Failure = &inventoryv1alpha1.ScanFailure{Source: source, Reason: recorded, Time: ptr.To(failed), Attempts: attempts}
		if text != "" {
			facts.Failure.Message = ptr.To(text)
		}
		return facts, nil
	})
	if err != nil {
		return fmt.Errorf("record the failure of Collector %q about image %s: %w", source, image, err)
	}
	if !found {
		logf.FromContext(ctx).Info("Dropped the failure of a collector about an image that is gone", "image", image, "source", source)
	}
	return nil
}

// success is what a success of a source records in the facts.
type success struct {
	source string
	// manifests are the manifests that the events are about, sorted by platform. It is empty when
	// the events name none.
	manifests []inventoryv1alpha1.ManifestFact
	// evidence has an entry for each type of the events, sorted by type.
	evidence []inventoryv1alpha1.EvidenceFact
}

// successOf returns what a success of source at version records of events. An event without a time
// counts as received.
func successOf(source, version string, events []cloudevents.Event, received time.Time) (*success, error) {
	manifests := manifestsOf{byPlatform: map[string]string{}, byDigest: map[string]string{}}
	byType := map[string]*inventoryv1alpha1.EvidenceFact{}
	unknownCoverage := map[string]bool{}
	for _, e := range events {
		if err := sdkevidence.Validate(e); err != nil {
			return nil, fmt.Errorf("an event is no evidence: %w", err)
		}
		if len(e.Type()) > maxTypeLength || !sdkevidence.ValidType(e.Type()) {
			return nil, fmt.Errorf("type: reverse-DNS with a version, at most %d characters", maxTypeLength)
		}
		if err := manifests.add(e); err != nil {
			return nil, err
		}
		at := e.Time()
		if at.IsZero() {
			at = received
		}
		fact, seen := byType[e.Type()]
		switch {
		case !seen:
			fact = &inventoryv1alpha1.EvidenceFact{Source: source, Type: e.Type(), CollectorVersion: version, Time: ptr.To(metav1.NewTime(at))}
			byType[e.Type()] = fact
		case at.Before(fact.Time.Time):
			fact.Time = ptr.To(metav1.NewTime(at))
		}
		// An unknown coverage can be any, the lowest included, so the lowest of several is unknown too.
		coverage, hasCoverage := sdkevidence.Coverage(e)
		switch {
		case !hasCoverage:
			unknownCoverage[e.Type()] = true
			fact.Coverage = nil
		case unknownCoverage[e.Type()]:
		case fact.Coverage == nil || coverage < *fact.Coverage:
			fact.Coverage = ptr.To(coverage)
		}
	}
	if len(manifests.byPlatform) > maxManifests {
		return nil, fmt.Errorf("the events name %d manifests, more than the %d that the facts hold",
			len(manifests.byPlatform), maxManifests)
	}
	if len(byType) > maxEvidenceFacts {
		return nil, fmt.Errorf("the events have %d types, more than the %d entries of evidence that the facts hold",
			len(byType), maxEvidenceFacts)
	}

	s := &success{source: source}
	for platform, digest := range manifests.byPlatform {
		s.manifests = append(s.manifests, inventoryv1alpha1.ManifestFact{Platform: platform, Digest: digest})
	}
	slices.SortFunc(s.manifests, func(a, b inventoryv1alpha1.ManifestFact) int { return cmp.Compare(a.Platform, b.Platform) })
	for _, fact := range byType {
		s.evidence = append(s.evidence, *fact)
	}
	slices.SortFunc(s.evidence, compareEvidence)
	return s, nil
}

// apply returns the facts after the success: the manifests replaced when it names some, its entries
// of evidence in place of those of the same source and type, and no failure of its source. It
// refuses facts that would hold more entries of evidence than the schema allows.
func (s *success) apply(facts *inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error) {
	if facts == nil {
		facts = &inventoryv1alpha1.ImageFacts{}
	}
	if len(s.manifests) > 0 {
		facts.Manifests = slices.Clone(s.manifests)
	}
	for _, fact := range s.evidence {
		i := slices.IndexFunc(facts.Evidence, func(f inventoryv1alpha1.EvidenceFact) bool {
			return f.Source == fact.Source && f.Type == fact.Type
		})
		if i < 0 {
			facts.Evidence = append(facts.Evidence, *fact.DeepCopy())
		} else {
			facts.Evidence[i] = *fact.DeepCopy()
		}
	}
	if len(facts.Evidence) > maxEvidenceFacts {
		return nil, fmt.Errorf("the facts would hold evidence of %d sources and types, more than the %d that they hold",
			len(facts.Evidence), maxEvidenceFacts)
	}
	slices.SortFunc(facts.Evidence, compareEvidence)
	if facts.Failure != nil && facts.Failure.Source == s.source {
		facts.Failure = nil
	}
	return facts, nil
}

// compareEvidence orders entries of evidence by source and type, the key of their list.
func compareEvidence(a, b inventoryv1alpha1.EvidenceFact) int {
	return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.Type, b.Type))
}

// manifestsOf collects the manifests that events are about, each with its platform.
type manifestsOf struct {
	byPlatform, byDigest map[string]string
}

// add notes the manifest that e is about, if it is about one. Two manifests of one platform, or one
// manifest of two platforms, contradict each other: an image has one manifest for each platform.
func (m manifestsOf) add(e cloudevents.Event) error {
	about, err := subjects.Parse(e.Subject())
	if err != nil || about.Kind != subjects.KindManifest {
		return nil
	}
	// Validate has seen to it that an event about a manifest has a platform.
	platform, _ := sdkevidence.Platform(e)
	if len(platform) > maxPlatformLength || !platformPattern.MatchString(platform) {
		return fmt.Errorf("platform: os/architecture[/variant] in lower case, at most %d characters", maxPlatformLength)
	}
	if digest, seen := m.byPlatform[platform]; seen && digest != about.Digest {
		return errors.New("two events name different manifests of one platform")
	}
	if other, seen := m.byDigest[about.Digest]; seen && other != platform {
		return errors.New("two events name one manifest with different platforms")
	}
	m.byPlatform[platform] = about.Digest
	m.byDigest[about.Digest] = platform
	return nil
}

// printable returns s with each character that Go doesn't call printable replaced by U+FFFD, and cut
// to at most n characters, which is what the schema's maxLength counts. Control characters, line
// breaks and the format characters that reverse the direction of text are not printable, and bytes
// that aren't valid UTF-8 become U+FFFD too, so that kubectl shows the text as it is.
func printable(s string, n int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count == n {
			break
		}
		if !unicode.IsPrint(r) {
			r = utf8.RuneError
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
