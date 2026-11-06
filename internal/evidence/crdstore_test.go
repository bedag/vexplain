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
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllertest"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/metrics"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These tests cover the CRD store: one Evidence object per subject, type and source, written once
// for each version of its collector.

const (
	// clusterA is the cluster that labels the metrics of the store's writes.
	clusterA = "cluster-a"

	// imageContents is the type of the scanner's evidence, and findings another type.
	imageContents = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"
	findings      = "ch.bedag.vexplain.findings.v1alpha1"
	// scanner and matcher are the names of two Collectors.
	scanner = "scanner"
	matcher = "matcher"
	// scannerEvents is the source of the CloudEvents of the scanner.
	scannerEvents = "/clusters/cluster-a/collectors/scanner"

	// v1 and v2 are two versions of a collector.
	v1 = "1.0.0"
	v2 = "2.0.0"

	// amd64 and arm64 are the platforms of the manifests of the tests.
	amd64 = "linux/amd64"
	arm64 = "linux/arm64/v8"
)

var (
	// manifestA and manifestB are the subjects of two platform manifests, and image the subject of an
	// image digest.
	manifestA = subjects.Manifest("sha256:" + strings.Repeat("a", 64))
	manifestB = subjects.Manifest("sha256:" + strings.Repeat("b", 64))
	image     = subjects.Image("sha256:" + strings.Repeat("c", 64))

	// t0 is when the collectors of the tests saw what their evidence is about: a whole second, as an
	// Evidence keeps a time.
	t0 = time.Date(2026, time.October, 31, 12, 0, 0, 0, time.UTC)

	// evidenceKind is the kind of the Evidence objects, which the reads of metadata name.
	evidenceKind     = inventoryv1alpha1.GroupVersion.WithKind("Evidence")
	evidenceListKind = inventoryv1alpha1.GroupVersion.WithKind("EvidenceList")
)

// --- fixtures ---

// newClient returns a fake client that knows the inventory group, and passes every call through
// funcs, so that a test can make a call fail or let another writer act in the middle of one.
func newClient(t *testing.T, funcs interceptor.Funcs) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&inventoryv1alpha1.ImageInventory{}).
		WithInterceptorFuncs(funcs).
		Build()
}

// cluster is the function through which a store reads the name of its cluster: here, always
// clusterA.
func cluster() string { return clusterA }

// newStore returns a store over a fake client with funcs, and the client. It never watches, so it
// has no cache, and its writes are labelled with clusterA.
func newStore(t *testing.T, funcs interceptor.Funcs) (evidence.Store, client.Client) {
	t.Helper()
	c := newClient(t, funcs)
	return evidence.NewCRDStore(c, nil, cluster), c
}

// contents is the data of the scanner's evidence about a manifest.
type contents struct {
	Platform string   `json:"platform"`
	Packages []string `json:"packages"`
}

// scannerEvent returns the scanner's evidence about a manifest of the platform, which covers 97% of
// it, seen at t0.
func scannerEvent(t *testing.T, subject, platform string) cloudevents.Event {
	t.Helper()
	e, err := sdkevidence.New(imageContents, subject, contents{Platform: platform, Packages: []string{"libexample1"}},
		sdkevidence.WithPlatform(platform), sdkevidence.WithCoverage(97), sdkevidence.WithTime(t0),
		sdkevidence.WithSource(scannerEvents))
	require.NoError(t, err)
	return e
}

// matcherEvent returns evidence of another type and source about the subject, without a coverage.
func matcherEvent(t *testing.T, subject, platform string) cloudevents.Event {
	t.Helper()
	e, err := sdkevidence.New(findings, subject, map[string]any{"matches": []any{}},
		sdkevidence.WithPlatform(platform), sdkevidence.WithTime(t0),
		sdkevidence.WithSource("/clusters/cluster-a/collectors/matcher"))
	require.NoError(t, err)
	return e
}

// jsonOf returns the CloudEvents JSON of an event: the form in which two events are the same event.
func jsonOf(t *testing.T, e cloudevents.Event) string {
	t.Helper()
	raw, err := json.Marshal(e)
	require.NoError(t, err)
	return string(raw)
}

// put stores e for the collector at version, which must succeed.
func put(t *testing.T, store evidence.Store, collector, version string, e cloudevents.Event) {
	t.Helper()
	require.NoError(t, store.Put(t.Context(), collector, version, e))
}

// hashOf returns the first 40 hex digits of the SHA-256 of s.
func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:40]
}

// nameOf returns the name of the Evidence that holds the record of the key.
func nameOf(k evidence.Key) string {
	return "ev-" + hashOf(k.Subject+"|"+k.Type+"|"+k.Source)
}

// stored reads the Evidence of the key behind the store, straight from the client.
func stored(t *testing.T, c client.Client, k evidence.Key) *inventoryv1alpha1.Evidence {
	t.Helper()
	obj := &inventoryv1alpha1.Evidence{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: nameOf(k)}, obj))
	return obj
}

// requireAbsent fails the test when the store holds a record of the key.
func requireAbsent(t *testing.T, store evidence.Store, k evidence.Key) {
	t.Helper()
	record, err := store.Get(t.Context(), k)
	require.NoError(t, err)
	require.Nil(t, record)
}

// incompressible returns the scanner's evidence about manifestA, whose data is random text that gzip
// can't compress below MaxCompressedBytes.
func incompressible(t *testing.T) cloudevents.Event {
	t.Helper()
	// Random base64 holds 6 bits in each character, so gzip makes no less than the random bytes of
	// it: 9/8 of the cap.
	random := rand.New(rand.NewPCG(1, 2))
	raw := make([]byte, evidence.MaxCompressedBytes*9/8)
	for i := range raw {
		raw[i] = byte(random.Uint32())
	}
	e, err := sdkevidence.New(imageContents, manifestA, base64.StdEncoding.EncodeToString(raw),
		sdkevidence.WithPlatform(amd64), sdkevidence.WithTime(t0), sdkevidence.WithSource(scannerEvents))
	require.NoError(t, err)
	return e
}

// writeCounts is what the metrics of the evidence have counted for one cluster: the writes by op,
// and the number of samples in the histogram of object sizes.
type writeCounts struct {
	Create, Update, Delete float64
	Sizes                  uint64
}

// readCounts reads the metrics of the evidence for the cluster.
func readCounts(t *testing.T, cluster string) writeCounts {
	t.Helper()
	counter := func(op string) float64 {
		var m dto.Metric
		require.NoError(t, metrics.EvidenceWritesTotal.WithLabelValues(cluster, op).Write(&m))
		return m.GetCounter().GetValue()
	}
	observer, err := metrics.EvidenceObjectBytes.GetMetricWithLabelValues(cluster)
	require.NoError(t, err)
	histogram, ok := observer.(prometheus.Metric)
	require.True(t, ok, "a histogram is a metric")
	var m dto.Metric
	require.NoError(t, histogram.Write(&m))
	return writeCounts{
		Create: counter("create"), Update: counter("update"), Delete: counter("delete"),
		Sizes: m.GetHistogram().GetSampleCount(),
	}
}

// counted runs call and returns what it added to the metrics of the evidence for the cluster. The
// collectors are global, so a test can only look at the change around a call.
func counted(t *testing.T, cluster string, call func()) writeCounts {
	t.Helper()
	before := readCounts(t, cluster)
	call()
	after := readCounts(t, cluster)
	return writeCounts{
		Create: after.Create - before.Create,
		Update: after.Update - before.Update,
		Delete: after.Delete - before.Delete,
		Sizes:  after.Sizes - before.Sizes,
	}
}

// --- Put and Get ---

// A record gives back the event that carried the evidence, so that it can go to a collector again,
// as the input of an operation, which the collector checks as evidence.
func TestPutThenGetGivesTheSameEvent(t *testing.T) {
	for name, e := range map[string]cloudevents.Event{
		"about a manifest, with every attribute": scannerEvent(t, manifestA, amd64),
		"about an image, without a coverage, a platform or a schema": func() cloudevents.Event {
			e := scannerEvent(t, image, amd64)
			e.SetExtension(sdkevidence.ExtCoverage, nil)
			e.SetExtension(sdkevidence.ExtPlatform, nil)
			e.SetDataSchema("")
			return e
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newStore(t, interceptor.Funcs{})

			put(t, store, scanner, v1, e)
			record, err := store.Get(t.Context(), evidence.Key{Subject: e.Subject(), Type: imageContents, Source: scanner})

			require.NoError(t, err)
			require.NotNil(t, record)
			require.Equal(t, evidence.Key{Subject: e.Subject(), Type: imageContents, Source: scanner}, record.Key)
			require.Equal(t, v1, record.CollectorVersion)
			require.JSONEq(t, jsonOf(t, e), jsonOf(t, record.Event))
			require.NoError(t, sdkevidence.Validate(record.Event), "the event is evidence")
		})
	}
}

// The name and the labels of an Evidence are hashes, which kubectl and a selector can use: the
// subject and the type can hold characters that neither allows. The annotation holds the subject
// itself.
func TestPutStoresTheRecordUnderItsKey(t *testing.T) {
	store, c := newStore(t, interceptor.Funcs{})
	e := scannerEvent(t, manifestA, amd64)
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}

	put(t, store, scanner, v1, e)

	obj := stored(t, c, key)
	require.Regexp(t, `^ev-[0-9a-f]{40}$`, obj.Name)
	require.Equal(t, map[string]string{
		evidence.CollectorLabel:   scanner,
		evidence.SubjectHashLabel: hashOf(manifestA),
		evidence.TypeHashLabel:    hashOf(imageContents),
	}, obj.Labels)
	require.Equal(t, map[string]string{evidence.SubjectAnnotation: manifestA, evidence.CollectorVersionAnnotation: v1},
		obj.Annotations)

	spec := obj.Spec
	require.Equal(t, manifestA, spec.Subject)
	require.Equal(t, imageContents, spec.Type)
	require.Equal(t, scanner, spec.Source)
	require.Equal(t, e.ID(), spec.EventID)
	require.Equal(t, scannerEvents, spec.EventSource)
	require.Equal(t, v1, spec.CollectorVersion)
	require.True(t, t0.Equal(spec.Time.Time), "the time of the event, %s", spec.Time)
	require.Equal(t, ptr.To[int32](97), spec.Coverage)
	require.Equal(t, ptr.To(amd64), spec.Platform)
	require.Equal(t, ptr.To("urn:vexplain:schema:"+imageContents), spec.DataSchema)
	require.Equal(t, inventoryv1alpha1.EvidenceEncodingGzipJSON, spec.Encoding)
	require.Equal(t, ptr.To(int64(len(e.Data()))), spec.UncompressedBytes)
	zr, err := gzip.NewReader(bytes.NewReader(spec.Data))
	require.NoError(t, err, "the data is compressed with gzip")
	data, err := io.ReadAll(zr)
	require.NoError(t, err)
	require.Equal(t, e.Data(), data)
}

// CompressedSize tells what the data of an event takes in a record, which is what counts against the
// cap, without a write.
func TestCompressedSizeIsTheSizeOfTheDataInARecord(t *testing.T) {
	store, c := newStore(t, interceptor.Funcs{})
	e := scannerEvent(t, manifestA, amd64)
	put(t, store, scanner, v1, e)

	size, err := evidence.CompressedSize(e.Data())

	require.NoError(t, err)
	require.Len(t, stored(t, c, evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}).Spec.Data, size)
}

// An Evidence keeps its time to the second, as the API keeps every time.
func TestPutKeepsTheTimeToTheSecond(t *testing.T) {
	store, _ := newStore(t, interceptor.Funcs{})
	e := scannerEvent(t, manifestA, amd64)
	e.SetTime(t0.Add(750 * time.Millisecond))

	put(t, store, scanner, v1, e)

	record, err := store.Get(t.Context(), evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner})
	require.NoError(t, err)
	require.Equal(t, t0, record.Event.Time())
}

// CloudEvents makes the time optional, and the API requires one: what vexplain knows is when it
// received the event.
func TestPutStoresAnEventWithoutATimeWithTheTimeItReceivedIt(t *testing.T) {
	store, _ := newStore(t, interceptor.Funcs{})
	e := scannerEvent(t, manifestA, amd64)
	e.SetTime(time.Time{})
	before := time.Now().Truncate(time.Second)

	put(t, store, scanner, v1, e)

	record, err := store.Get(t.Context(), evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner})
	require.NoError(t, err)
	require.False(t, record.Event.Time().Before(before), "received no earlier than the test started")
	require.False(t, record.Event.Time().After(time.Now()), "received no later than Put returned")
	require.True(t, e.Time().IsZero(), "the caller's event is left as it was")
}

// The store keeps what the core reads: the data, which is JSON, and the coverage and the platform.
func TestPutKeepsTheDataAsJSONAndNoExtensionButCoverageAndPlatform(t *testing.T) {
	store, _ := newStore(t, interceptor.Funcs{})
	e := scannerEvent(t, manifestA, amd64)
	e.SetDataContentType("application/json; charset=utf-8")
	e.SetExtension("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	want := scannerEvent(t, manifestA, amd64)
	want.SetID(e.ID())

	put(t, store, scanner, v1, e)

	record, err := store.Get(t.Context(), evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner})
	require.NoError(t, err)
	require.JSONEq(t, jsonOf(t, want), jsonOf(t, record.Event))
}

func TestGetOfAnAbsentRecord(t *testing.T) {
	store, _ := newStore(t, interceptor.Funcs{})
	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))

	for name, k := range map[string]evidence.Key{
		"another subject": {Subject: manifestB, Type: imageContents, Source: scanner},
		"another type":    {Subject: manifestA, Type: findings, Source: scanner},
		"another source":  {Subject: manifestA, Type: imageContents, Source: matcher},
	} {
		t.Run(name, func(t *testing.T) {
			requireAbsent(t, store, k)
		})
	}
}

// --- written once for each version ---

func TestPutOfTheSameVersionWritesNothing(t *testing.T) {
	store, c := newStore(t, interceptor.Funcs{})
	first := scannerEvent(t, manifestA, amd64)
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	put(t, store, scanner, v1, first)
	version := stored(t, c, key).ResourceVersion

	again := scannerEvent(t, manifestA, amd64)
	again.SetTime(t0.Add(time.Hour))
	counts := counted(t, clusterA, func() { put(t, store, scanner, v1, again) })

	require.Equal(t, writeCounts{}, counts)
	require.Equal(t, version, stored(t, c, key).ResourceVersion, "nothing was written")
	record, err := store.Get(t.Context(), key)
	require.NoError(t, err)
	require.JSONEq(t, jsonOf(t, first), jsonOf(t, record.Event), "the record of the version is left as it is")
}

// The spec of an Evidence can't change, so the evidence of another version replaces the object: it
// is deleted, but only if it is still the object that was read, and created again.
func TestPutOfAnotherVersionReplacesTheRecord(t *testing.T) {
	var preconditions []*metav1.Preconditions
	store, c := newStore(t, interceptor.Funcs{
		Delete: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			var options client.DeleteOptions
			options.ApplyOptions(opts)
			preconditions = append(preconditions, options.Preconditions)
			return other.Delete(ctx, obj, opts...)
		},
	})
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))
	read := stored(t, c, key)

	newer := scannerEvent(t, manifestA, amd64)
	newer.SetExtension(sdkevidence.ExtCoverage, int32(99))
	counts := counted(t, clusterA, func() { put(t, store, scanner, v2, newer) })

	require.Equal(t, writeCounts{Create: 1, Delete: 1, Sizes: 1}, counts)
	require.Equal(t, []*metav1.Preconditions{{ResourceVersion: ptr.To(read.ResourceVersion)}}, preconditions,
		"only the object that was read is deleted")
	record, err := store.Get(t.Context(), key)
	require.NoError(t, err)
	require.Equal(t, v2, record.CollectorVersion)
	require.JSONEq(t, jsonOf(t, newer), jsonOf(t, record.Event))
}

// replaceWith plays another writer that replaces the record of the key with one of version.
func replaceWith(t *testing.T, other client.Client, k evidence.Key, version string) {
	t.Helper()
	obj := stored(t, other, k)
	require.NoError(t, other.Delete(t.Context(), obj))
	obj.ResourceVersion, obj.Spec.CollectorVersion = "", version
	require.NoError(t, other.Create(t.Context(), obj))
}

// Another writer replaced the record after this Put read it, with one of the same newer version. The
// delete of the object that was read meets a conflict, and the next round finds the record that it
// wanted to write.
func TestPutLeavesARecordReplacedSinceItsRead(t *testing.T) {
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	armed := false
	store, c := newStore(t, interceptor.Funcs{
		Delete: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if armed {
				armed = false
				replaceWith(t, other, key, v2)
				// The precondition names the object that was read, and the API server refuses it.
				return apierrors.NewConflict(schema.GroupResource{Group: inventoryv1alpha1.GroupVersion.Group,
					Resource: "evidences"}, obj.GetName(), errors.New("the object has been replaced"))
			}
			return other.Delete(ctx, obj, opts...)
		},
	})
	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))

	armed = true
	counts := counted(t, clusterA, func() { put(t, store, scanner, v2, scannerEvent(t, manifestA, amd64)) })

	require.False(t, armed, "the other writer acted")
	require.Equal(t, writeCounts{}, counts, "the other writer replaced it: this one wrote nothing")
	require.Equal(t, v2, stored(t, c, key).Spec.CollectorVersion)
}

// Another writer created the record between this Put's delete and its create. The create meets the
// object, and the next round finds the record that it wanted to write.
func TestPutLeavesARecordCreatedSinceItsDelete(t *testing.T) {
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	armed := false
	store, c := newStore(t, interceptor.Funcs{
		Create: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if armed {
				armed = false
				created, ok := obj.DeepCopyObject().(*inventoryv1alpha1.Evidence)
				require.True(t, ok)
				require.NoError(t, other.Create(ctx, created))
			}
			return other.Create(ctx, obj, opts...)
		},
	})
	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))

	armed = true
	counts := counted(t, clusterA, func() { put(t, store, scanner, v2, scannerEvent(t, manifestA, amd64)) })

	require.False(t, armed, "the other writer acted")
	require.Equal(t, writeCounts{Delete: 1}, counts, "this one deleted the old record, and created nothing")
	require.Equal(t, v2, stored(t, c, key).Spec.CollectorVersion)
}

// --- what Put refuses ---

// Evidence over the cap can't be stored, and Put writes nothing: it neither creates a record nor
// deletes the record of an older version.
func TestPutRefusesAnEventOverTheCap(t *testing.T) {
	store, c := newStore(t, interceptor.Funcs{})
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))
	version := stored(t, c, key).ResourceVersion

	counts := counted(t, clusterA, func() {
		err := store.Put(t.Context(), scanner, v2, incompressible(t))
		require.ErrorIs(t, err, evidence.ErrTooLarge)
		require.NotErrorIs(t, err, evidence.ErrRefused, "evidence over the cap has a reason of its own")

		other := incompressible(t)
		other.SetSubject(manifestB)
		require.ErrorIs(t, store.Put(t.Context(), scanner, v2, other), evidence.ErrTooLarge)
	})

	require.Equal(t, writeCounts{}, counts)
	require.Equal(t, version, stored(t, c, key).ResourceVersion, "the record of the older version stays")
	requireAbsent(t, store, evidence.Key{Subject: manifestB, Type: imageContents, Source: scanner})
}

// Only evidence goes into the store, so that what Get gives back is evidence too. The errors never
// repeat what a collector chose.
func TestPutRefusesAnEventThatIsNotEvidence(t *testing.T) {
	for name, change := range map[string]func(e *cloudevents.Event){
		"no id":                       func(e *cloudevents.Event) { e.SetID("") },
		"data that is not JSON":       func(e *cloudevents.Event) { e.DataEncoded = []byte("not JSON at all") },
		"a manifest with no platform": func(e *cloudevents.Event) { e.SetExtension(sdkevidence.ExtPlatform, nil) },
		"a coverage above 100":        func(e *cloudevents.Event) { e.SetExtension(sdkevidence.ExtCoverage, int32(101)) },
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newStore(t, interceptor.Funcs{})
			e := scannerEvent(t, manifestA, amd64)
			change(&e)

			counts := counted(t, clusterA, func() {
				// Asking again changes nothing, so the error says that the store refuses it.
				require.ErrorIs(t, store.Put(t.Context(), scanner, v1, e), evidence.ErrRefused)
			})

			require.Equal(t, writeCounts{}, counts)
			requireAbsent(t, store, evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner})
		})
	}
}

// The store refuses what the API server would refuse, so that a write never fails half way, and
// says which attribute is at fault without repeating it.
func TestPutRefusesWhatAnEvidenceCantHold(t *testing.T) {
	const marker = "ZZ"
	long := func(n int) string { return marker + strings.Repeat("z", n-len(marker)) }
	cases := map[string]struct {
		source, version string
		change          func(e *cloudevents.Event)
	}{
		"a source that is no Collector's name":  {source: "Scanner" + marker, version: v1},
		"a source of 45 characters":             {source: strings.Repeat("s", 45), version: v1},
		"no collector version":                  {source: scanner},
		"a collector version of 129 characters": {source: scanner, version: long(129)},
		"a subject of 513 characters":           {source: scanner, version: v1, change: func(e *cloudevents.Event) { e.SetSubject("vm/" + long(510)) }},
		"a type that has no version":            {source: scanner, version: v1, change: func(e *cloudevents.Event) { e.SetType("com.example." + marker) }},
		"a type of 254 characters": {source: scanner, version: v1, change: func(e *cloudevents.Event) {
			e.SetType(strings.Repeat("z", 249) + ".b.v1")
		}},
		"an id of 257 characters":                 {source: scanner, version: v1, change: func(e *cloudevents.Event) { e.SetID(long(257)) }},
		"a source of the event of 513 characters": {source: scanner, version: v1, change: func(e *cloudevents.Event) { e.SetSource("/" + long(512)) }},
		"a schema of 513 characters":              {source: scanner, version: v1, change: func(e *cloudevents.Event) { e.SetDataSchema("urn:" + long(509)) }},
		// CloudEvents takes any os/arch[/variant], and the API only lower case.
		"a platform in upper case": {source: scanner, version: v1, change: func(e *cloudevents.Event) {
			e.SetExtension(sdkevidence.ExtPlatform, "Linux/"+marker)
		}},
		"a platform of 65 characters": {source: scanner, version: v1, change: func(e *cloudevents.Event) {
			e.SetExtension(sdkevidence.ExtPlatform, "linux/"+strings.Repeat("z", 59))
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store, c := newStore(t, interceptor.Funcs{})
			e := scannerEvent(t, manifestA, amd64)
			if tc.change != nil {
				tc.change(&e)
			}

			err := store.Put(t.Context(), tc.source, tc.version, e)

			require.ErrorIs(t, err, evidence.ErrRefused, "asking again changes nothing")
			require.NotContains(t, err.Error(), marker, "the error doesn't repeat what the collector chose")
			var list inventoryv1alpha1.EvidenceList
			require.NoError(t, c.List(t.Context(), &list))
			require.Empty(t, list.Items, "nothing is written")
		})
	}
}

// --- what Get refuses ---

// Only the store writes an Evidence, but another writer can, past the schema. Get decodes only what
// it can trust, never reads more than the object says it holds, and gives back nothing but evidence.
func TestGetRefusesARecordItCannotRead(t *testing.T) {
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	gzipped := func(t *testing.T, data []byte) []byte {
		t.Helper()
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, err := zw.Write(data)
		require.NoError(t, err)
		require.NoError(t, zw.Close())
		return buf.Bytes()
	}
	for name, change := range map[string]func(t *testing.T, s *inventoryv1alpha1.EvidenceSpec){
		"an encoding that this version doesn't know": func(_ *testing.T, s *inventoryv1alpha1.EvidenceSpec) {
			s.Encoding = "ZstdJSON"
		},
		"no size of the decoded data": func(_ *testing.T, s *inventoryv1alpha1.EvidenceSpec) { s.UncompressedBytes = nil },
		"a size of zero":              func(_ *testing.T, s *inventoryv1alpha1.EvidenceSpec) { s.UncompressedBytes = ptr.To[int64](0) },
		"a size over 64 MiB": func(_ *testing.T, s *inventoryv1alpha1.EvidenceSpec) {
			s.UncompressedBytes = ptr.To[int64](64<<20 + 1)
		},
		"data that decodes to more than its size": func(_ *testing.T, s *inventoryv1alpha1.EvidenceSpec) { *s.UncompressedBytes-- },
		"data that decodes to less than its size": func(_ *testing.T, s *inventoryv1alpha1.EvidenceSpec) { *s.UncompressedBytes++ },
		"data that is not gzip":                   func(_ *testing.T, s *inventoryv1alpha1.EvidenceSpec) { s.Data = []byte("data") },
		"data that is not JSON": func(t *testing.T, s *inventoryv1alpha1.EvidenceSpec) {
			s.Data, s.UncompressedBytes = gzipped(t, []byte("not JSON")), ptr.To[int64](8)
		},
		"a manifest without a platform": func(_ *testing.T, s *inventoryv1alpha1.EvidenceSpec) { s.Platform = nil },
		"the record of another key":     func(_ *testing.T, s *inventoryv1alpha1.EvidenceSpec) { s.Subject = manifestB },
	} {
		t.Run(name, func(t *testing.T) {
			store, c := newStore(t, interceptor.Funcs{})
			put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))
			obj := stored(t, c, key)
			change(t, &obj.Spec)
			require.NoError(t, c.Update(t.Context(), obj)) // the fake client knows no schema

			record, err := store.Get(t.Context(), key)

			require.Error(t, err)
			require.Nil(t, record)
		})
	}
}

func TestReadErrorsAreReturned(t *testing.T) {
	errRead := errors.New("read failed")
	store, _ := newStore(t, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errRead
		},
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errRead
		},
	})
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}

	_, err := store.Get(t.Context(), key)
	require.ErrorIs(t, err, errRead, "a failed read is not an absent record")
	counts := counted(t, clusterA, func() {
		require.ErrorIs(t, store.Put(t.Context(), scanner, v1, scannerEvent(t, manifestA, amd64)), errRead)
	})
	require.Equal(t, writeCounts{}, counts, "nothing is written after a failed read")
	_, err = store.ListBySubject(t.Context(), manifestA)
	require.ErrorIs(t, err, errRead)
	require.ErrorIs(t, store.DeleteSubject(t.Context(), manifestA), errRead)
	require.ErrorIs(t, store.DeleteBySource(t.Context(), scanner), errRead)
	_, err = store.Subjects(t.Context())
	require.ErrorIs(t, err, errRead)
}

// --- Version: the metadata in the cache, and the API server when the cache has none ---

// requireMetadataOfEvidence fails the test unless obj is the metadata of an Evidence, which is all
// that Version reads: never the data.
func requireMetadataOfEvidence(t *testing.T, obj client.Object) {
	t.Helper()
	metadata, ok := obj.(*metav1.PartialObjectMetadata)
	require.True(t, ok, "the read is of metadata only, not %T", obj)
	require.Equal(t, evidenceKind, metadata.GroupVersionKind())
}

// Version says whether there is a record of a key, and of which version, from the metadata alone, so
// that a check costs neither the transfer nor the decoding of the data.
func TestVersionTellsTheVersionOfARecordFromItsMetadata(t *testing.T) {
	var read []client.Object
	store, _ := newStore(t, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			read = append(read, obj)
			return c.Get(ctx, key, obj, opts...)
		},
	})
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	version := func() (string, bool) {
		t.Helper()
		read = nil
		got, held, err := store.Version(t.Context(), key)
		require.NoError(t, err)
		require.Len(t, read, 1)
		requireMetadataOfEvidence(t, read[0])
		return got, held
	}

	got, held := version()
	require.False(t, held, "no record yet")
	require.Empty(t, got)

	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))
	got, held = version()
	require.True(t, held)
	require.Equal(t, v1, got)

	put(t, store, scanner, v2, scannerEvent(t, manifestA, amd64))
	got, held = version()
	require.True(t, held)
	require.Equal(t, v2, got, "the version of the record that replaced the first")
}

// metadataCache is the cache of informers of a store under test. It holds the metadata of the
// records in held, by name, and answers a read of any other with NotFound, as a cache does that
// hasn't seen an object yet. It fails a read with err when that isn't nil, and records what it was
// asked to read. Any other call panics on the nil cache.Cache inside.
type metadataCache struct {
	cache.Cache
	held map[string]*metav1.PartialObjectMetadata
	err  error
	read []client.Object
}

func (c *metadataCache) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	c.read = append(c.read, obj)
	if c.err != nil {
		return c.err
	}
	held, ok := c.held[key.Name]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Group: inventoryv1alpha1.GroupVersion.Group, Resource: "evidences"}, key.Name)
	}
	held.DeepCopyInto(obj.(*metav1.PartialObjectMetadata))
	return nil
}

// cachedMetadataOf returns the metadata of the record of the key at version, as the store writes it.
func cachedMetadataOf(k evidence.Key, version string) *metav1.PartialObjectMetadata {
	obj := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Name: nameOf(k),
		Labels: map[string]string{
			evidence.CollectorLabel: k.Source, evidence.SubjectHashLabel: hashOf(k.Subject), evidence.TypeHashLabel: hashOf(k.Type),
		},
		Annotations: map[string]string{evidence.SubjectAnnotation: k.Subject, evidence.CollectorVersionAnnotation: version},
	}}
	obj.SetGroupVersionKind(evidenceKind)
	return obj
}

// The cache is the cheap place to look: the metadata that Source watches is there.
func TestVersionReadsTheMetadataInTheCache(t *testing.T) {
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	informers := &metadataCache{held: map[string]*metav1.PartialObjectMetadata{nameOf(key): cachedMetadataOf(key, v1)}}
	store := evidence.NewCRDStore(newClient(t, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("the API server is not asked when the cache holds the record")
		},
	}), informers, cluster)

	version, held, err := store.Version(t.Context(), key)

	require.NoError(t, err)
	require.True(t, held)
	require.Equal(t, v1, version)
	require.Len(t, informers.read, 1)
	requireMetadataOfEvidence(t, informers.read[0])
}

// A cache can lag behind the API server, such as right after a record was stored: only the API
// server says that a record is absent.
func TestVersionAsksTheAPIServerWhenTheCacheHasNone(t *testing.T) {
	var asked []client.Object
	informers := &metadataCache{}
	store := evidence.NewCRDStore(newClient(t, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			asked = append(asked, obj)
			return c.Get(ctx, key, obj, opts...)
		},
	}), informers, cluster)
	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))
	asked = nil

	version, held, err := store.Version(t.Context(), evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner})
	require.NoError(t, err)
	require.True(t, held, "the API server holds what the cache hasn't seen yet")
	require.Equal(t, v1, version)
	_, held, err = store.Version(t.Context(), evidence.Key{Subject: manifestB, Type: imageContents, Source: scanner})
	require.NoError(t, err)
	require.False(t, held)

	require.Len(t, asked, 2)
	for _, obj := range asked {
		requireMetadataOfEvidence(t, obj)
	}
}

// A failed read is never mistaken for an absent record.
func TestVersionReturnsAFailedRead(t *testing.T) {
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	errCache := errors.New("the cache is not synced")
	store := evidence.NewCRDStore(newClient(t, interceptor.Funcs{}), &metadataCache{err: errCache}, cluster)
	_, _, err := store.Version(t.Context(), key)
	require.ErrorIs(t, err, errCache)

	errRead := errors.New("the API server is unavailable")
	store, _ = newStore(t, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errRead
		},
	})
	_, _, err = store.Version(t.Context(), key)
	require.ErrorIs(t, err, errRead)
}

// Version reads no data, so a record whose data can't be read counts as held, at its version.
func TestVersionHoldsARecordWhoseDataCantBeRead(t *testing.T) {
	store, c := newStore(t, interceptor.Funcs{})
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))
	obj := stored(t, c, key)
	obj.Spec.Encoding = "ZstdJSON"
	require.NoError(t, c.Update(t.Context(), obj)) // the fake client knows no schema
	_, err := store.Get(t.Context(), key)
	require.Error(t, err, "Get can't read it")

	version, held, err := store.Version(t.Context(), key)

	require.NoError(t, err)
	require.True(t, held)
	require.Equal(t, v1, version)
}

// A record that another writer made without the annotation has a version that the metadata doesn't
// say: it is held, and its version is unknown, which is never a current one.
func TestVersionOfARecordWithoutTheAnnotationIsUnknown(t *testing.T) {
	store, c := newStore(t, interceptor.Funcs{})
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))
	obj := stored(t, c, key)
	delete(obj.Annotations, evidence.CollectorVersionAnnotation)
	require.NoError(t, c.Update(t.Context(), obj))

	version, held, err := store.Version(t.Context(), key)

	require.NoError(t, err)
	require.True(t, held)
	require.Empty(t, version)
}

// The name of a record is a hash of its key. An object of that name that holds another key, which
// only another writer can make, is refused, as Get refuses it.
func TestVersionRefusesAnObjectThatHoldsAnotherKey(t *testing.T) {
	store, c := newStore(t, interceptor.Funcs{})
	key := evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner}
	put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64))
	obj := stored(t, c, key)
	obj.Annotations[evidence.SubjectAnnotation] = manifestB
	require.NoError(t, c.Update(t.Context(), obj))

	_, _, err := store.Version(t.Context(), key)

	require.Error(t, err)
}

// --- across records ---

// storeThree stores the scanner's and the matcher's evidence about manifestA, and the scanner's
// about manifestB. It returns the scanner's event about manifestA.
func storeThree(t *testing.T, store evidence.Store) cloudevents.Event {
	t.Helper()
	scanned := scannerEvent(t, manifestA, amd64)
	put(t, store, scanner, v1, scanned)
	put(t, store, matcher, v1, matcherEvent(t, manifestA, amd64))
	put(t, store, scanner, v1, scannerEvent(t, manifestB, arm64))
	return scanned
}

// keysOf returns the keys of the records.
func keysOf(records []evidence.Record) []evidence.Key {
	keys := make([]evidence.Key, 0, len(records))
	for _, record := range records {
		keys = append(keys, record.Key)
	}
	return keys
}

func TestListBySubjectReturnsTheRecordsAboutASubjectByTypeAndSource(t *testing.T) {
	var selectors []labels.Selector
	store, _ := newStore(t, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			var options client.ListOptions
			options.ApplyOptions(opts)
			selectors = append(selectors, options.LabelSelector)
			return c.List(ctx, list, opts...)
		},
	})
	scanned := storeThree(t, store)

	records, err := store.ListBySubject(t.Context(), manifestA)

	require.NoError(t, err)
	require.Equal(t, []evidence.Key{
		{Subject: manifestA, Type: findings, Source: matcher},
		{Subject: manifestA, Type: imageContents, Source: scanner},
	}, keysOf(records))
	require.JSONEq(t, jsonOf(t, scanned), jsonOf(t, records[1].Event), "the record holds the event")
	require.Equal(t, []string{evidence.SubjectHashLabel + "=" + hashOf(manifestA)}, []string{selectors[0].String()},
		"the list asks for the hash of the subject")

	none, err := store.ListBySubject(t.Context(), image)
	require.NoError(t, err)
	require.Empty(t, none)
}

func TestDeleteSubjectRemovesEveryRecordAboutTheSubject(t *testing.T) {
	store, _ := newStore(t, interceptor.Funcs{})
	storeThree(t, store)

	counts := counted(t, clusterA, func() {
		require.NoError(t, store.DeleteSubject(t.Context(), manifestA))
		require.NoError(t, store.DeleteSubject(t.Context(), manifestA), "a subject without records is no error")
	})

	require.Equal(t, writeCounts{Delete: 2}, counts)
	records, err := store.ListBySubject(t.Context(), manifestA)
	require.NoError(t, err)
	require.Empty(t, records)
	records, err = store.ListBySubject(t.Context(), manifestB)
	require.NoError(t, err)
	require.Len(t, records, 1, "the records of other subjects stay")
}

// Deleting a Collector removes its evidence, and only its own: another collector's evidence about the
// same subject stays.
func TestDeleteBySourceRemovesOnlyThatCollectorsRecords(t *testing.T) {
	store, _ := newStore(t, interceptor.Funcs{})
	storeThree(t, store)

	counts := counted(t, clusterA, func() {
		require.NoError(t, store.DeleteBySource(t.Context(), scanner))
		require.NoError(t, store.DeleteBySource(t.Context(), scanner), "a source without records is no error")
	})

	require.Equal(t, writeCounts{Delete: 2}, counts)
	recordsA, err := store.ListBySubject(t.Context(), manifestA)
	require.NoError(t, err)
	require.Equal(t, []evidence.Key{{Subject: manifestA, Type: findings, Source: matcher}}, keysOf(recordsA))
	recordsB, err := store.ListBySubject(t.Context(), manifestB)
	require.NoError(t, err)
	require.Empty(t, recordsB)
}

// The source of a record is a label, so a source that no label holds names no record.
func TestDeleteBySourceRefusesANameThatIsNoCollectors(t *testing.T) {
	store, _ := newStore(t, interceptor.Funcs{})
	storeThree(t, store)

	require.Error(t, store.DeleteBySource(t.Context(), "not a name"))

	records, err := store.ListBySubject(t.Context(), manifestA)
	require.NoError(t, err)
	require.Len(t, records, 2)
}

// --- the reads of metadata, and the watch ---

// The subjects are in an annotation, so Subjects reads the metadata of the objects and never their
// data.
func TestSubjectsReadsTheMetadataOnly(t *testing.T) {
	var listed []client.ObjectList
	store, c := newStore(t, interceptor.Funcs{
		List: func(ctx context.Context, other client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			listed = append(listed, list)
			return other.List(ctx, list, opts...)
		},
	})
	empty, err := store.Subjects(t.Context())
	require.NoError(t, err)
	require.Empty(t, empty)
	storeThree(t, store)
	// An object that the store didn't write has no annotation, and names no subject.
	require.NoError(t, c.Create(t.Context(), &inventoryv1alpha1.Evidence{ObjectMeta: metav1.ObjectMeta{Name: "by-hand"}}))
	listed = nil

	got, err := store.Subjects(t.Context())

	require.NoError(t, err)
	require.Equal(t, []string{manifestA, manifestB}, got, "each subject once, sorted")
	require.Len(t, listed, 1)
	metadata, ok := listed[0].(*metav1.PartialObjectMetadataList)
	require.True(t, ok, "the list holds metadata only, not %T", listed[0])
	require.Equal(t, evidenceListKind, metadata.GroupVersionKind())
}

// listingCache is the cache of informers of a store under test. It holds the metadata of the records
// about the subjects. It fails a list with err when that isn't nil. Any call but a list panics on the
// nil cache.Cache inside.
type listingCache struct {
	cache.Cache
	subjects []string
	err      error
}

func (c *listingCache) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	if c.err != nil {
		return c.err
	}
	metadata, ok := list.(*metav1.PartialObjectMetadataList)
	if !ok {
		return errors.New("the cache holds metadata only")
	}
	for i, subject := range c.subjects {
		item := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
			Name:        nameOf(evidence.Key{Subject: subject, Type: imageContents, Source: scanner}) + strings.Repeat("x", i),
			Annotations: map[string]string{evidence.SubjectAnnotation: subject},
		}}
		item.SetGroupVersionKind(evidenceKind)
		metadata.Items = append(metadata.Items, item)
	}
	return nil
}

// The cache holds the metadata that Source watches, so the subjects are there without a request to
// the API server, whose failure can't lose them.
func TestSubjectsReadTheMetadataInTheCache(t *testing.T) {
	informers := &listingCache{subjects: []string{manifestB, manifestA, manifestB}}
	store := evidence.NewCRDStore(newClient(t, interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("the API server is not asked when the store has a cache")
		},
	}), informers, cluster)

	got, err := store.Subjects(t.Context())

	require.NoError(t, err)
	require.Equal(t, []string{manifestA, manifestB}, got)

	informers.err = errors.New("the context ended before the cache synced")
	_, err = store.Subjects(t.Context())
	require.ErrorIs(t, err, informers.err)
}

// oneInformer is the cache of a Source under test. It hands out one fake informer, through which the
// test plays the events of a watch, and records what the Source asked to watch. It has what a
// source.Kind uses, and any other call panics on the nil cache.Cache inside.
type oneInformer struct {
	cache.Cache
	informer *controllertest.FakeInformer
	watched  []client.Object
}

func (o *oneInformer) GetInformer(_ context.Context, obj client.Object, _ ...cache.InformerGetOption) (cache.Informer, error) {
	o.watched = append(o.watched, obj)
	return o.informer, nil
}

func (o *oneInformer) WaitForCacheSync(context.Context) bool { return true }

// metadataOf returns the metadata of the record of the subject, as a watch of metadata delivers it.
func metadataOf(subject string, uid types.UID) *metav1.PartialObjectMetadata {
	obj := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Name:        nameOf(evidence.Key{Subject: subject, Type: imageContents, Source: scanner}),
		UID:         uid,
		Annotations: map[string]string{evidence.SubjectAnnotation: subject},
	}}
	obj.SetGroupVersionKind(evidenceKind)
	return obj
}

// drain returns the requests in the queue, and marks them done.
func drain(queue workqueue.TypedRateLimitingInterface[reconcile.Request]) []reconcile.Request {
	var requests []reconcile.Request
	for queue.Len() > 0 {
		request, _ := queue.Get()
		queue.Done(request)
		requests = append(requests, request)
	}
	return requests
}

// The source watches metadata only, so the cache never holds data. It delivers one request, named by
// the subject, for each record that is created or deleted. A record never changes, so an update is a
// resync or a change of metadata, unless the UID changed: then the record was replaced while the
// watch was down, and the update stands for a deletion and a creation.
func TestSourceWatchesMetadataAndEnqueuesCreatesAndDeletesBySubject(t *testing.T) {
	informers := &oneInformer{informer: controllertest.NewFakeInformer(controllertest.Synced)}
	store := evidence.NewCRDStore(newClient(t, interceptor.Funcs{}), informers, cluster)
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(queue.ShutDown)

	src := store.Source()
	require.NoError(t, src.Start(t.Context(), queue))
	syncing, ok := src.(source.SyncingSource)
	require.True(t, ok, "a source of a cache can be waited for")
	require.NoError(t, syncing.WaitForSync(t.Context()))

	require.Len(t, informers.watched, 1)
	watched, ok := informers.watched[0].(*metav1.PartialObjectMetadata)
	require.True(t, ok, "the source watches metadata only, not %T", informers.watched[0])
	require.Equal(t, evidenceKind, watched.GroupVersionKind())

	object := metadataOf(manifestA, "uid-1")
	want := []reconcile.Request{{NamespacedName: types.NamespacedName{Name: manifestA}}}

	informers.informer.Add(object)
	require.Equal(t, want, drain(queue), "a created record")

	labelled := object.DeepCopy()
	labelled.Labels = map[string]string{"team": "team-a"}
	informers.informer.Update(object, labelled)
	informers.informer.Update(labelled, labelled)
	require.Empty(t, drain(queue), "a change of metadata, and a resync")

	replaced := metadataOf(manifestA, "uid-2")
	informers.informer.Update(labelled, replaced)
	require.Equal(t, want, drain(queue), "a replacement seen across a gap in the watch")

	informers.informer.Delete(replaced)
	require.Equal(t, want, drain(queue), "a deleted record")

	unannotated := metadataOf(manifestB, "uid-3")
	unannotated.Annotations = nil
	informers.informer.Add(unannotated)
	require.Empty(t, drain(queue), "an object that names no subject")
}

// --- metrics ---

// Each write that the API server accepted is counted, with the size of the object written. A write
// while the name of the cluster can't be read is not.
func TestPutAndDeletesAreCounted(t *testing.T) {
	name := clusterA
	store := evidence.NewCRDStore(newClient(t, interceptor.Funcs{}), nil, func() string { return name })

	counts := counted(t, clusterA, func() { put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64)) })
	require.Equal(t, writeCounts{Create: 1, Sizes: 1}, counts)

	counts = counted(t, clusterA, func() { require.NoError(t, store.DeleteSubject(t.Context(), manifestA)) })
	require.Equal(t, writeCounts{Delete: 1}, counts)

	name = ""
	counts = counted(t, "", func() { put(t, store, scanner, v1, scannerEvent(t, manifestA, amd64)) })
	require.Equal(t, writeCounts{}, counts, "no series for a cluster without a name")
	_, err := store.Get(t.Context(), evidence.Key{Subject: manifestA, Type: imageContents, Source: scanner})
	require.NoError(t, err, "the record is written all the same")
}
