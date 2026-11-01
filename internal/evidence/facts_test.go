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

package evidence_test

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These tests cover the FactsWriter: what it records in the facts of an image about the evidence of
// its collectors, and about their failures.

// imageDigest is the digest of the image whose facts the tests write, and digestA and digestB the
// digests of manifestA and manifestB.
var (
	imageDigest = "sha256:" + strings.Repeat("c", 64)
	digestA     = "sha256:" + strings.Repeat("a", 64)
	digestB     = "sha256:" + strings.Repeat("b", 64)
)

// newFactsWriter returns a FactsWriter over an inventory store on a fake client, and the store.
func newFactsWriter(t *testing.T) (evidence.FactsWriter, inventory.Store) {
	t.Helper()
	store := inventory.NewCRDStore(newClient(t, interceptor.Funcs{}), nil, cluster)
	return evidence.NewFactsWriter(store), store
}

// observe makes the ImageInventory of the image, as the presence of the digest in a cluster does.
func observe(t *testing.T, store inventory.Store) {
	t.Helper()
	require.NoError(t, store.Observe(t.Context(), imageDigest, inventory.Observation{
		Cluster: clusterA, ClusterID: "id-a", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		Repositories: []string{"artifacts.example/team-a/app"}, NamespaceCount: 1,
	}))
}

// factsOf reads the facts of the image.
func factsOf(t *testing.T, store inventory.Store) *inventoryv1alpha1.ImageFacts {
	t.Helper()
	obj, err := store.Get(t.Context(), imageDigest)
	require.NoError(t, err)
	require.NotNil(t, obj, "the image has an ImageInventory")
	return obj.Status.Facts
}

// requireFacts compares facts as the store does, with equality.Semantic, which compares times as
// instants: a time that went through JSON comes back in the local zone.
func requireFacts(t *testing.T, want, got *inventoryv1alpha1.ImageFacts) {
	t.Helper()
	wantJSON, err := json.Marshal(want)
	require.NoError(t, err)
	gotJSON, err := json.Marshal(got)
	require.NoError(t, err)
	require.True(t, equality.Semantic.DeepEqual(want, got), "want %s\ngot  %s", wantJSON, gotJSON)
}

// seen returns the scanner's evidence about the subject of the platform, seen at the time, with the
// coverage, or with none when coverage is negative.
func seen(t *testing.T, subject, platform string, at time.Time, coverage int32) cloudevents.Event {
	t.Helper()
	e := scannerEvent(t, subject, platform)
	e.SetTime(at)
	if coverage < 0 {
		e.SetExtension(sdkevidence.ExtCoverage, nil)
	} else {
		e.SetExtension(sdkevidence.ExtCoverage, coverage)
	}
	return e
}

// scanned returns the facts that the scanner's evidence about manifestA and manifestB records.
func scanned(version string, coverage int32) *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{
		Manifests: []inventoryv1alpha1.ManifestFact{{Platform: amd64, Digest: digestA}, {Platform: arm64, Digest: digestB}},
		Evidence: []inventoryv1alpha1.EvidenceFact{{
			Source: scanner, Type: imageContents, CollectorVersion: version, Time: ptr.To(metav1.NewTime(t0)),
			Coverage: ptr.To(coverage),
		}},
	}
}

// --- Succeeded ---

// The platform of each manifest comes from the platform extension, which every event about a
// manifest carries, so the facts need not know the type.
func TestSucceededRecordsTheManifestsFromThePlatformExtension(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)

	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v1, []cloudevents.Event{
		seen(t, manifestB, arm64, t0, 97), seen(t, manifestA, amd64, t0, 97),
	}))

	requireFacts(t, scanned(v1, 97), factsOf(t, store))
}

// Facts never bring an image back: only the presence of its digest creates its ImageInventory.
func TestSucceededNeverCreatesAnImageInventory(t *testing.T) {
	writer, store := newFactsWriter(t)

	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v1, []cloudevents.Event{seen(t, manifestA, amd64, t0, 97)}))

	obj, err := store.Get(t.Context(), imageDigest)
	require.NoError(t, err)
	require.Nil(t, obj)
}

// The facts hold one entry for each source and type. When several pieces of evidence share them,
// such as the scanner's of each platform, the entry says what holds for all: the lowest coverage, and
// the earliest time. An unknown coverage can be any, the lowest included.
func TestSucceededRecordsTheLowestCoverageAndTheEarliestTime(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)

	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v1, []cloudevents.Event{
		seen(t, manifestA, amd64, t0.Add(time.Hour), 97), seen(t, manifestB, arm64, t0, 80),
	}))
	requireFacts(t, scanned(v1, 80), factsOf(t, store))

	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v2, []cloudevents.Event{
		seen(t, manifestA, amd64, t0, 97), seen(t, manifestB, arm64, t0, -1),
	}))
	want := scanned(v2, 0)
	want.Evidence[0].Coverage = nil
	requireFacts(t, want, factsOf(t, store))
}

// A success names the manifests of the image, as far as it found them: they replace those that the
// facts held. Evidence about the image itself names none, and leaves them.
func TestSucceededReplacesTheManifestsWhenItNamesSome(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)
	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v1, []cloudevents.Event{
		seen(t, manifestA, amd64, t0, 97), seen(t, manifestB, arm64, t0, 97),
	}))

	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v2, []cloudevents.Event{seen(t, manifestB, arm64, t0, 90)}))
	want := scanned(v2, 90)
	want.Manifests = want.Manifests[1:]
	requireFacts(t, want, factsOf(t, store))

	aboutTheImage, err := sdkevidence.New("com.example.provenance.v1", subjects.Image(imageDigest), map[string]any{"builder": "ci"},
		sdkevidence.WithTime(t0), sdkevidence.WithSource("/clusters/cluster-a/collectors/provenance"))
	require.NoError(t, err)
	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, "provenance", v1, []cloudevents.Event{aboutTheImage}))
	want.Evidence = append([]inventoryv1alpha1.EvidenceFact{{
		Source: "provenance", Type: "com.example.provenance.v1", CollectorVersion: v1, Time: ptr.To(metav1.NewTime(t0)),
	}}, want.Evidence...)
	requireFacts(t, want, factsOf(t, store))
}

// Each source and type has its own entry: a success replaces the entries of its own, and leaves the
// others, ordered by source and type.
func TestSucceededKeepsTheEvidenceOfOtherSourcesAndTypes(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)
	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v1, []cloudevents.Event{
		seen(t, manifestA, amd64, t0, 97), seen(t, manifestB, arm64, t0, 97),
	}))

	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, matcher, v2, []cloudevents.Event{
		matcherEvent(t, manifestA, amd64), matcherEvent(t, manifestB, arm64),
	}))

	want := scanned(v1, 97)
	want.Evidence = append([]inventoryv1alpha1.EvidenceFact{{
		Source: matcher, Type: findings, CollectorVersion: v2, Time: ptr.To(metav1.NewTime(t0)),
	}}, want.Evidence...)
	requireFacts(t, want, factsOf(t, store))
}

// A success of a source ends the failures in a row of that source, and of no other.
func TestSucceededClearsTheFailureOfItsSourceOnly(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)

	require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, "Unauthorized", "the registry refused the pull"))
	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v1, []cloudevents.Event{seen(t, manifestA, amd64, t0, 97)}))
	require.Nil(t, factsOf(t, store).Failure, "the scanner's own failure is over")

	require.NoError(t, writer.Failed(t.Context(), imageDigest, matcher, "NotFound", ""))
	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v1, []cloudevents.Event{seen(t, manifestA, amd64, t0, 97)}))
	failure := factsOf(t, store).Failure
	require.NotNil(t, failure, "another source's failure stays")
	require.Equal(t, matcher, failure.Source)

	// A success without events delivered nothing, and still ends the failures of its source.
	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, matcher, v1, nil))
	require.Nil(t, factsOf(t, store).Failure)
}

// Events that the facts can't hold are refused, and the facts stay as they were.
func TestSucceededRefusesEventsThatTheFactsCantHold(t *testing.T) {
	manifestOf := func(i int) string { return subjects.Manifest(fmt.Sprintf("sha256:%064x", i)) }
	cases := map[string]func(t *testing.T) []cloudevents.Event{
		"an event that is no evidence": func(t *testing.T) []cloudevents.Event {
			e := seen(t, manifestA, amd64, t0, 97)
			e.SetExtension(sdkevidence.ExtPlatform, nil)
			return []cloudevents.Event{e}
		},
		"a platform that the API can't hold": func(t *testing.T) []cloudevents.Event {
			return []cloudevents.Event{seen(t, manifestA, "Linux/AMD64", t0, 97)}
		},
		"two manifests of one platform": func(t *testing.T) []cloudevents.Event {
			return []cloudevents.Event{seen(t, manifestA, amd64, t0, 97), seen(t, manifestB, amd64, t0, 97)}
		},
		"one manifest of two platforms": func(t *testing.T) []cloudevents.Event {
			return []cloudevents.Event{seen(t, manifestA, amd64, t0, 97), seen(t, manifestA, arm64, t0, 97)}
		},
		"17 manifests": func(t *testing.T) []cloudevents.Event {
			events := make([]cloudevents.Event, 0, 17)
			for i := range 17 {
				events = append(events, seen(t, manifestOf(i), fmt.Sprintf("linux/arch%d", i), t0, 97))
			}
			return events
		},
		"evidence of 33 types": func(t *testing.T) []cloudevents.Event {
			events := make([]cloudevents.Event, 0, 33)
			for i := range 33 {
				e := seen(t, manifestA, amd64, t0, 97)
				e.SetType(fmt.Sprintf("com.example.type%d.v1", i))
				events = append(events, e)
			}
			return events
		},
	}
	for name, eventsOf := range cases {
		t.Run(name, func(t *testing.T) {
			writer, store := newFactsWriter(t)
			observe(t, store)
			require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v1, []cloudevents.Event{
				seen(t, manifestA, amd64, t0, 97), seen(t, manifestB, arm64, t0, 97),
			}))

			require.Error(t, writer.Succeeded(t.Context(), imageDigest, scanner, v2, eventsOf(t)))

			requireFacts(t, scanned(v1, 97), factsOf(t, store))
		})
	}
}

// The facts hold 32 entries of evidence. A success that would add a 33rd is refused, before the API
// server refuses the write.
func TestSucceededRefusesASourceAndTypeMoreThanTheFactsHold(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)
	for i := range 32 {
		require.NoError(t, writer.Succeeded(t.Context(), imageDigest, fmt.Sprintf("collector-%02d", i), v1,
			[]cloudevents.Event{seen(t, manifestA, amd64, t0, 97)}))
	}

	err := writer.Succeeded(t.Context(), imageDigest, "collector-32", v1, []cloudevents.Event{seen(t, manifestA, amd64, t0, 97)})

	require.Error(t, err)
	require.Len(t, factsOf(t, store).Evidence, 32)
	// The entry of a source and type that the facts hold already is replaced, and no entry is added.
	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, "collector-00", v2, []cloudevents.Event{seen(t, manifestA, amd64, t0, 97)}))
}

func TestSucceededRefusesASourceOrAVersionThatTheAPICantHold(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)
	events := []cloudevents.Event{seen(t, manifestA, amd64, t0, 97)}

	require.Error(t, writer.Succeeded(t.Context(), imageDigest, "Scanner", v1, events))
	require.Error(t, writer.Succeeded(t.Context(), imageDigest, scanner, "", events))
	require.Error(t, writer.Succeeded(t.Context(), imageDigest, scanner, strings.Repeat("v", 129), events))

	require.Nil(t, factsOf(t, store))
}

// --- Failed ---

// A failure keeps what the last success recorded, and counts one failure more than the facts did: the
// hub waits longer before it asks again after each one.
func TestFailedKeepsTheEarlierFactsAndAddsOneAttempt(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)
	require.NoError(t, writer.Succeeded(t.Context(), imageDigest, scanner, v1, []cloudevents.Event{
		seen(t, manifestA, amd64, t0, 97), seen(t, manifestB, arm64, t0, 97),
	}))
	before := time.Now().Truncate(time.Second)

	require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, "PullFailed", "the image could not be pulled"))
	first := factsOf(t, store)
	require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, "Unauthorized", "the registry refused the pull"))
	second := factsOf(t, store)

	require.NotNil(t, first.Failure)
	require.Equal(t, int32(1), first.Failure.Attempts)
	require.NotNil(t, second.Failure)
	require.False(t, second.Failure.Time.Time.Before(before), "the time of the last failure")
	require.False(t, second.Failure.Time.After(time.Now()))
	want := scanned(v1, 97)
	want.Failure = &inventoryv1alpha1.ScanFailure{
		Source: scanner, Reason: inventoryv1alpha1.ScanFailureReasonUnauthorized,
		Message: ptr.To("the registry refused the pull"), Time: second.Failure.Time, Attempts: 2,
	}
	requireFacts(t, want, second)
}

// The attempts count the failures of one source in a row: a failure of another source starts again.
func TestFailedOfAnotherSourceCountsFromOne(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)
	for range 3 {
		require.NoError(t, writer.Failed(t.Context(), imageDigest, matcher, "NotFound", ""))
	}

	require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, "TimedOut", "the Job ran past its deadline"))

	failure := factsOf(t, store).Failure
	require.Equal(t, scanner, failure.Source)
	require.Equal(t, inventoryv1alpha1.ScanFailureReasonTimedOut, failure.Reason)
	require.Equal(t, int32(1), failure.Attempts)
}

// The count stops at the largest that the API holds, rather than wrap around to a negative count,
// which the API would refuse.
func TestFailedStopsCountingAtTheLargestCount(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)
	found, err := store.SetFacts(t.Context(), imageDigest, &inventoryv1alpha1.ImageFacts{Failure: &inventoryv1alpha1.ScanFailure{
		Source: scanner, Reason: inventoryv1alpha1.ScanFailureReasonInternal, Time: ptr.To(metav1.Now()), Attempts: math.MaxInt32,
	}})
	require.NoError(t, err)
	require.True(t, found)

	require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, "Internal", ""))

	require.Equal(t, int32(math.MaxInt32), factsOf(t, store).Failure.Attempts)
}

func TestFailedNeverCreatesAnImageInventory(t *testing.T) {
	writer, store := newFactsWriter(t)

	require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, "NotFound", ""))

	obj, err := store.Get(t.Context(), imageDigest)
	require.NoError(t, err)
	require.Nil(t, obj)
}

// The reasons are an open vocabulary of words, and a collector chooses which it reports. A reason
// that the API can't hold is the failure of a reason of its own, which Internal names, so that the
// failure is recorded all the same.
func TestFailedRecordsAReasonThatTheAPICantHoldAsInternal(t *testing.T) {
	for _, reason := range []string{"", "not found", "unauthorized", "A" + strings.Repeat("a", 64)} {
		t.Run(reason, func(t *testing.T) {
			writer, store := newFactsWriter(t)
			observe(t, store)

			require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, reason, ""))

			require.Equal(t, inventoryv1alpha1.ScanFailureReasonInternal, factsOf(t, store).Failure.Reason)
		})
	}
	writer, store := newFactsWriter(t)
	observe(t, store)
	require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, "RateLimited", ""))
	require.Equal(t, inventoryv1alpha1.ScanFailureReason("RateLimited"), factsOf(t, store).Failure.Reason,
		"a reason of the same form that vexplain doesn't define yet")
}

// A collector chooses the message, and kubectl prints it as it is. It is made printable, cut to the
// 256 characters that the API holds, and left out when it says nothing.
func TestFailedMakesTheMessagePrintableAndCutsIt(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)

	require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, "Internal", "\x1b[31mred\u202e"+strings.Repeat("ß", 300)))
	message := ptr.Deref(factsOf(t, store).Failure.Message, "")
	require.True(t, strings.HasPrefix(message, "�[31mred�"), message)
	require.Equal(t, 256, utf8.RuneCountInString(message))

	require.NoError(t, writer.Failed(t.Context(), imageDigest, scanner, "Internal", ""))
	require.Nil(t, factsOf(t, store).Failure.Message)
}

func TestFailedRefusesASourceThatIsNoCollectorsName(t *testing.T) {
	writer, store := newFactsWriter(t)
	observe(t, store)

	require.Error(t, writer.Failed(t.Context(), imageDigest, "Scanner", "Internal", ""))

	require.Nil(t, factsOf(t, store))
}
