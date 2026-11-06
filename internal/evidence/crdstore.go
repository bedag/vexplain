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
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	ctrlsource "sigs.k8s.io/controller-runtime/pkg/source"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/metrics"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// The metadata of an Evidence. Its name and its labels hold hashes, because a subject and a type can
// hold characters, and be longer, than a name or a label value takes.
const (
	// SubjectAnnotation holds the subject of a record, so that Subjects and Source learn it from the
	// metadata alone, without the data.
	SubjectAnnotation = "vexplain.bedag.ch/subject"
	// CollectorVersionAnnotation holds the version of the collector that delivered a record, so that
	// Version learns it from the metadata alone.
	CollectorVersionAnnotation = "vexplain.bedag.ch/collector-version"
	// CollectorLabel holds the name of the Collector that delivered a record. A Collector's name is a
	// label value, and the label is the one that every object of a Collector carries.
	CollectorLabel = "vexplain.bedag.ch/collector"
	// SubjectHashLabel and TypeHashLabel hold the first 40 hex digits of the SHA-256 of the subject
	// and of the type of a record, so that a selector finds the records of either.
	SubjectHashLabel = "vexplain.bedag.ch/subject-hash"
	TypeHashLabel    = "vexplain.bedag.ch/type-hash"
)

const (
	// namePrefix starts the name of each Evidence, which the first 40 hex digits of the SHA-256 of
	// subject|type|source follow.
	namePrefix = "ev-"
	// hashDigits is how many hex digits of a SHA-256 a name or a label holds: 160 bits, which no two
	// keys share by chance.
	hashDigits = 40

	// The limits of the schema of an Evidence, which Put checks before it writes.
	maxSubjectLength          = 512
	maxTypeLength             = 253
	maxSourceLength           = 44
	maxCollectorVersionLength = 128
	maxEventIDLength          = 256
	maxEventSourceLength      = 512
	maxDataSchemaLength       = 512
	maxPlatformLength         = 64

	// The values of the op label of the counter of writes.
	opCreate = "create"
	opDelete = "delete"
)

var (
	// collectorName matches the name of a Collector: a DNS-1123 label. It is the pattern of
	// spec.source in the schema of an Evidence.
	collectorName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	// platformPattern matches a platform as the schema of an Evidence holds one:
	// os/architecture[/variant], in lower case.
	platformPattern = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)

	// evidenceKind and evidenceListKind are the kinds of the Evidence objects and of their list,
	// which the reads and the watch of metadata name.
	evidenceKind     = inventoryv1alpha1.GroupVersion.WithKind("Evidence")
	evidenceListKind = inventoryv1alpha1.GroupVersion.WithKind("EvidenceList")
)

// crdStore keeps the evidence as Evidence custom resources.
type crdStore struct {
	api client.Client
	// informers is the cache that Source watches through, and that Subjects reads, or nil for a
	// store that never watches.
	informers cache.Cache
	// cluster returns the name of this cluster, which labels the metrics of the writes.
	cluster func() string
}

// The store reads an object, creates it, and deletes it, to remove it or to replace it. It never
// updates one: the evidence is written once. It lists objects, whole or their metadata, and its
// Source watches the metadata through an informer, which lists and watches.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=evidences,verbs=get;list;watch;create;delete

// NewCRDStore returns a Store that keeps the evidence in the Evidence API, through c.
//
// Get, Put and ListBySubject read whole objects through c, data included. Pass a client that reads
// Evidence from the API server and not from a cache, such as the manager's client with
// setup.ClientOptions: a cache would hold the data of every record in memory. DeleteSubject and
// DeleteBySource list the metadata of the objects only, through c, so that they see every record
// that the API server holds. Source watches the metadata only, through informers, and Subjects reads
// that metadata there. Pass the manager's cache. A store that never watches passes nil, and its
// Subjects asks the API server.
//
// cluster returns the name of this cluster, the label of the metrics of the writes. The store reads
// it at each write, so that the label follows a rename.
func NewCRDStore(c client.Client, informers cache.Cache, cluster func() string) Store {
	return &crdStore{api: c, informers: informers, cluster: cluster}
}

func (s *crdStore) Put(ctx context.Context, source, collectorVersion string, e cloudevents.Event) error {
	// The event is the caller's, and a copy of it shares its attributes.
	e = e.Clone()
	if e.Time().IsZero() {
		// The API requires a time, where CloudEvents doesn't: vexplain knows when it received the event.
		e.SetTime(time.Now().UTC())
	}
	key := Key{Subject: e.Subject(), Type: e.Type(), Source: source}
	spec, err := specOf(source, collectorVersion, e)
	if err != nil {
		return err
	}
	name := nameOf(key)
	// Every round reads the object again, and applies the same rule to what is there now. A delete
	// that finds the object changed since the read (a conflict), or a create that finds one made
	// since (it already exists), is the sign of another writer. Neither is an error, as long as the
	// next round works.
	return retry.OnError(retry.DefaultBackoff, isRaced, func() error {
		existing, err := s.read(ctx, name)
		if err != nil {
			return err
		}
		if existing != nil {
			if keyOf(existing.Spec) != key {
				return fmt.Errorf("the Evidence %q holds the record of another key", name)
			}
			if existing.Spec.CollectorVersion == collectorVersion {
				return nil // The record of this version is written once.
			}
			// The spec can't change, so the record of another version is replaced. It is deleted only if
			// it is still the object that was read, and then created again.
			precondition := client.Preconditions{ResourceVersion: ptr.To(existing.ResourceVersion)}
			if err = s.delete(ctx, existing, precondition); err != nil {
				return err
			}
		}
		return s.create(ctx, &inventoryv1alpha1.Evidence{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					CollectorLabel:   key.Source,
					SubjectHashLabel: hashOf(key.Subject),
					TypeHashLabel:    hashOf(key.Type),
				},
				Annotations: map[string]string{SubjectAnnotation: key.Subject, CollectorVersionAnnotation: collectorVersion},
			},
			Spec: *spec.DeepCopy(),
		})
	})
}

func (s *crdStore) Get(ctx context.Context, k Key) (*Record, error) {
	encoded, err := s.GetEncoded(ctx, k)
	if err != nil || encoded == nil {
		return nil, err
	}
	return encoded.Decode()
}

func (s *crdStore) GetEncoded(ctx context.Context, k Key) (*Encoded, error) {
	obj, err := s.read(ctx, nameOf(k))
	if err != nil || obj == nil {
		return nil, err
	}
	if keyOf(obj.Spec) != k {
		return nil, fmt.Errorf("the Evidence %q holds the record of another key", obj.Name)
	}
	return encodedOf(obj)
}

// Version reads the metadata of the object only, so a check costs neither the transfer nor the
// decoding of the data. In the cache, it reads the metadata that Source's informer holds. Only the API
// server says that a record is absent: in the manager's client, the Evidence bypass the cache.
func (s *crdStore) Version(ctx context.Context, k Key) (string, bool, error) {
	key := client.ObjectKey{Name: nameOf(k)}
	metadata := newMetadata()
	found := false
	if s.informers != nil {
		err := s.informers.Get(ctx, key, metadata)
		switch {
		case err == nil:
			found = true
		case !apierrors.IsNotFound(err):
			return "", false, fmt.Errorf("read the metadata of Evidence %q from the cache: %w", key.Name, err)
		}
	}
	if !found {
		metadata = newMetadata()
		if err := s.api.Get(ctx, key, metadata); err != nil {
			if apierrors.IsNotFound(err) {
				return "", false, nil
			}
			// A failed read is never mistaken for an absent record.
			return "", false, fmt.Errorf("read the metadata of Evidence %q: %w", key.Name, err)
		}
	}
	if !holdsKey(metadata, k) {
		return "", false, fmt.Errorf("the Evidence %q holds the record of another key", key.Name)
	}
	return metadata.Annotations[CollectorVersionAnnotation], true, nil
}

// holdsKey reports whether metadata is that of the record of k, as far as the metadata tells: the
// subject in its annotation, and the source and the hash of the type in its labels.
func holdsKey(metadata *metav1.PartialObjectMetadata, k Key) bool {
	return metadata.Annotations[SubjectAnnotation] == k.Subject &&
		metadata.Labels[CollectorLabel] == k.Source &&
		metadata.Labels[TypeHashLabel] == hashOf(k.Type)
}

// ListBySubject lists the objects whose label holds the hash of the subject, and keeps those whose
// spec holds the subject itself.
func (s *crdStore) ListBySubject(ctx context.Context, subject string) ([]Record, error) {
	var list inventoryv1alpha1.EvidenceList
	if err := s.api.List(ctx, &list, client.MatchingLabels{SubjectHashLabel: hashOf(subject)}); err != nil {
		return nil, fmt.Errorf("list the Evidence of a subject: %w", err)
	}
	records := make([]Record, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.Subject != subject {
			continue
		}
		encoded, err := encodedOf(&list.Items[i])
		if err != nil {
			return nil, err
		}
		record, err := encoded.Decode()
		if err != nil {
			return nil, err
		}
		records = append(records, *record)
	}
	slices.SortFunc(records, func(a, b Record) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Source, b.Source))
	})
	return records, nil
}

func (s *crdStore) DeleteSubject(ctx context.Context, subject string) error {
	items, err := listMetadata(ctx, s.api, client.MatchingLabels{SubjectHashLabel: hashOf(subject)})
	if err != nil {
		return fmt.Errorf("list the Evidence of a subject: %w", err)
	}
	for i := range items {
		if items[i].Annotations[SubjectAnnotation] != subject {
			continue
		}
		if err := s.delete(ctx, &inventoryv1alpha1.Evidence{ObjectMeta: metav1.ObjectMeta{Name: items[i].Name}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *crdStore) DeleteBySource(ctx context.Context, source string) error {
	if !isCollectorName(source) {
		return errors.New("source: the name of a Collector, a DNS-1123 label of at most 44 characters")
	}
	items, err := listMetadata(ctx, s.api, client.MatchingLabels{CollectorLabel: source})
	if err != nil {
		return fmt.Errorf("list the Evidence of Collector %q: %w", source, err)
	}
	for i := range items {
		if err := s.delete(ctx, &inventoryv1alpha1.Evidence{ObjectMeta: metav1.ObjectMeta{Name: items[i].Name}}); err != nil {
			return err
		}
	}
	return nil
}

// Subjects reads the metadata that Source's informer holds, or the metadata through the API server
// for a store without informers.
func (s *crdStore) Subjects(ctx context.Context) ([]string, error) {
	var reader client.Reader = s.api
	if s.informers != nil {
		reader = s.informers
	}
	items, err := listMetadata(ctx, reader)
	if err != nil {
		return nil, fmt.Errorf("list the subjects of the Evidence: %w", err)
	}
	subjects := make([]string, 0, len(items))
	for i := range items {
		// An object that the store didn't write may lack the annotation, and names no subject.
		if subject := items[i].Annotations[SubjectAnnotation]; subject != "" {
			subjects = append(subjects, subject)
		}
	}
	slices.Sort(subjects)
	return slices.Compact(subjects), nil
}

// Source watches the metadata of the objects only, so the cache that it watches through holds no
// data. It enqueues the subject of an object when the object is created or deleted. An object never
// changes, so an update is a resync or a change of its metadata, and enqueues nothing, unless the UID
// changed: then the object was replaced while the watch was down, and the update stands for a
// deletion and a creation.
func (s *crdStore) Source() ctrlsource.Source {
	return ctrlsource.Kind[client.Object](s.informers, newMetadata(), handler.EnqueueRequestsFromMapFunc(subjectRequest),
		predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectOld.GetUID() != e.ObjectNew.GetUID()
		}})
}

// subjectRequest maps an object to a request named by its subject. An object without the annotation
// names none.
func subjectRequest(_ context.Context, obj client.Object) []reconcile.Request {
	subject := obj.GetAnnotations()[SubjectAnnotation]
	if subject == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: subject}}}
}

// newMetadata returns an empty object for the metadata of an Evidence.
func newMetadata() *metav1.PartialObjectMetadata {
	metadata := &metav1.PartialObjectMetadata{}
	metadata.SetGroupVersionKind(evidenceKind)
	return metadata
}

// listMetadata lists the metadata of the Evidence objects through reader.
func listMetadata(ctx context.Context, reader client.Reader, opts ...client.ListOption) ([]metav1.PartialObjectMetadata, error) {
	list := &metav1.PartialObjectMetadataList{}
	list.SetGroupVersionKind(evidenceListKind)
	// The objects are only read, and none leaves the store, so a cache needn't copy them.
	if err := reader.List(ctx, list, append(opts, client.UnsafeDisableDeepCopy)...); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// read returns the object of a name, or nil when there is none.
func (s *crdStore) read(ctx context.Context, name string) (*inventoryv1alpha1.Evidence, error) {
	obj := &inventoryv1alpha1.Evidence{}
	if err := s.api.Get(ctx, client.ObjectKey{Name: name}, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		// A failed read is never mistaken for an absent record.
		return nil, fmt.Errorf("read Evidence %q: %w", name, err)
	}
	return obj, nil
}

// create makes an object, and counts and measures the write.
func (s *crdStore) create(ctx context.Context, obj *inventoryv1alpha1.Evidence) error {
	if err := s.api.Create(ctx, obj); err != nil {
		return fmt.Errorf("create Evidence %q: %w", obj.Name, err)
	}
	cluster := s.cluster()
	countWrite(cluster, opCreate)
	measure(cluster, obj)
	return nil
}

// delete removes an object, under the preconditions in opts. An object that is already gone is what
// the caller wants, so it is no error.
func (s *crdStore) delete(ctx context.Context, obj *inventoryv1alpha1.Evidence, opts ...client.DeleteOption) error {
	err := s.api.Delete(ctx, obj, opts...)
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("delete Evidence %q: %w", obj.Name, err)
	}
	countWrite(s.cluster(), opDelete)
	return nil
}

// isRaced says whether a failed write is worth another round of reading: another writer changed the
// object since it was read, or created it since the read found none.
func isRaced(err error) bool {
	return apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err)
}

// countWrite counts a write that the API server accepted. A cluster whose name can't be read just
// now, "", gets no series, so its write is not counted.
func countWrite(cluster, op string) {
	if cluster == "" {
		return
	}
	metrics.EvidenceWritesTotal.WithLabelValues(cluster, op).Inc()
}

// measure records the size of an object that was just written: the length of the whole object as
// json.Marshal encodes it, which is close to what the storage holds for it. A cluster whose name
// can't be read just now, "", gets no series.
func measure(cluster string, obj client.Object) {
	if cluster == "" {
		return
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return // A metric must not fail a write that went through.
	}
	metrics.EvidenceObjectBytes.WithLabelValues(cluster).Observe(float64(len(raw)))
}

// hashOf returns the first hashDigits hex digits of the SHA-256 of s.
func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:hashDigits]
}

// nameOf returns the name of the object that holds the record of k. A '|' joins the parts: neither a
// type nor a source can hold one, so no two keys join to the same text.
func nameOf(k Key) string {
	return namePrefix + hashOf(k.Subject+"|"+k.Type+"|"+k.Source)
}

// keyOf returns the key of the record that spec holds.
func keyOf(spec inventoryv1alpha1.EvidenceSpec) Key {
	return Key{Subject: spec.Subject, Type: spec.Type, Source: spec.Source}
}

// specOf returns the spec of the record of an event from source at collectorVersion. It refuses an
// event that isn't evidence, or that doesn't fit what a record holds, with ErrRefused, and data that
// is more than a record holds, with ErrTooLarge.
func specOf(source, collectorVersion string, e cloudevents.Event) (*inventoryv1alpha1.EvidenceSpec, error) {
	if err := sdkevidence.Validate(e); err != nil {
		return nil, fmt.Errorf("%w: the event is no evidence: %w", ErrRefused, err)
	}
	if err := fits(source, collectorVersion, e); err != nil {
		return nil, fmt.Errorf("%w: the event doesn't fit a record: %w", ErrRefused, err)
	}
	data := e.Data()
	if len(data) > MaxUncompressedBytes {
		return nil, fmt.Errorf("%w: %d bytes of data, at most %d", ErrTooLarge, len(data), MaxUncompressedBytes)
	}
	compressed, err := compress(data)
	if err != nil {
		return nil, fmt.Errorf("compress the data of the event: %w", err)
	}
	if len(compressed) > MaxCompressedBytes {
		return nil, fmt.Errorf("%w: %d bytes compressed, at most %d", ErrTooLarge, len(compressed), MaxCompressedBytes)
	}
	spec := &inventoryv1alpha1.EvidenceSpec{
		Subject:           e.Subject(),
		Type:              e.Type(),
		Source:            source,
		EventID:           e.ID(),
		EventSource:       e.Source(),
		CollectorVersion:  collectorVersion,
		Time:              ptr.To(metav1.NewTime(e.Time())),
		Encoding:          inventoryv1alpha1.EvidenceEncodingGzipJSON,
		Data:              compressed,
		UncompressedBytes: ptr.To(int64(len(data))),
	}
	if coverage, ok := sdkevidence.Coverage(e); ok {
		spec.Coverage = ptr.To(coverage)
	}
	if platform, ok := sdkevidence.Platform(e); ok {
		spec.Platform = ptr.To(platform)
	}
	if schema := e.DataSchema(); schema != "" {
		spec.DataSchema = ptr.To(schema)
	}
	return spec, nil
}

// fits returns why the source, the version or an attribute of an event is more than the schema of an
// Evidence holds, or nil when they fit. Validate has checked the event against CloudEvents, which
// allows more. So the store refuses what the API server would, before it writes anything. An error
// names the attribute, and never repeats its value, which a collector chose.
func fits(source, collectorVersion string, e cloudevents.Event) error {
	platform, hasPlatform := sdkevidence.Platform(e)
	switch {
	case !isCollectorName(source):
		return errors.New("source: the name of a Collector, a DNS-1123 label of at most 44 characters")
	case collectorVersion == "" || utf8.RuneCountInString(collectorVersion) > maxCollectorVersionLength:
		return fmt.Errorf("collector version: 1 to %d characters", maxCollectorVersionLength)
	case utf8.RuneCountInString(e.Subject()) > maxSubjectLength:
		return fmt.Errorf("subject: at most %d characters", maxSubjectLength)
	case len(e.Type()) > maxTypeLength || !sdkevidence.ValidType(e.Type()):
		return fmt.Errorf("type: reverse-DNS with a version, at most %d characters", maxTypeLength)
	case utf8.RuneCountInString(e.ID()) > maxEventIDLength:
		return fmt.Errorf("id: at most %d characters", maxEventIDLength)
	case utf8.RuneCountInString(e.Source()) > maxEventSourceLength:
		return fmt.Errorf("source of the event: at most %d characters", maxEventSourceLength)
	case utf8.RuneCountInString(e.DataSchema()) > maxDataSchemaLength:
		return fmt.Errorf("dataschema: at most %d characters", maxDataSchemaLength)
	case hasPlatform && (len(platform) > maxPlatformLength || !platformPattern.MatchString(platform)):
		return fmt.Errorf("platform: os/architecture[/variant] in lower case, at most %d characters", maxPlatformLength)
	}
	return nil
}

// isCollectorName reports whether name is the name of a Collector: a DNS-1123 label of at most 44
// characters, which is a label value too.
func isCollectorName(name string) bool {
	return len(name) <= maxSourceLength && collectorName.MatchString(name)
}

// CompressedSize returns how many bytes data takes in a record, once compressed: the size that
// counts against MaxCompressedBytes.
func CompressedSize(data []byte) (int, error) {
	compressed, err := compress(data)
	if err != nil {
		return 0, err
	}
	return len(compressed), nil
}

// compress returns the gzip of data, at the best compression: these bytes are scarce in an etcd
// object, and the time it takes is small next to that of collecting them.
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err = zw.Write(data); err != nil {
		return nil, err
	}
	if err = zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodedOf returns the record that obj holds, without decoding its data. It takes only what it can
// trust to decode later: the encoding it knows, and a size of the decoded data within what a record
// holds, which bounds the decoder, so that a few bytes of gzip can't unpack into gigabytes. Its
// errors are fixed texts, and never repeat the data.
func encodedOf(obj *inventoryv1alpha1.Evidence) (*Encoded, error) {
	spec := obj.Spec
	if spec.Encoding != inventoryv1alpha1.EvidenceEncodingGzipJSON {
		return nil, fmt.Errorf("the Evidence %q holds data in an encoding that this operator can't read", obj.Name)
	}
	size := ptr.Deref(spec.UncompressedBytes, 0)
	if size <= 0 || size > MaxUncompressedBytes {
		return nil, fmt.Errorf("the Evidence %q doesn't say how large its data is once decoded, within what a record holds",
			obj.Name)
	}
	encoded := &Encoded{
		Key:              keyOf(spec),
		CollectorVersion: spec.CollectorVersion,
		EventID:          spec.EventID,
		Size:             size,
		decode:           func() (*Record, error) { return recordOf(obj, size) },
	}
	if spec.Time != nil {
		encoded.Time = spec.Time.UTC()
	}
	if spec.Coverage != nil {
		encoded.Coverage = ptr.To(*spec.Coverage)
	}
	return encoded, nil
}

// recordOf returns the record that obj holds, whose data encodedOf has found to be of an encoding
// that it knows, and of size bytes once decoded. It decodes no more than that, and gives back nothing
// but evidence. Its errors are fixed texts, and never repeat the data.
func recordOf(obj *inventoryv1alpha1.Evidence, size int64) (*Record, error) {
	spec := obj.Spec
	data, err := decompress(spec.Data, size)
	if err != nil {
		return nil, fmt.Errorf("decode the data of Evidence %q: %w", obj.Name, err)
	}
	e := cloudevents.NewEvent(cloudevents.VersionV1)
	e.SetID(spec.EventID)
	e.SetSource(spec.EventSource)
	e.SetType(spec.Type)
	e.SetSubject(spec.Subject)
	if spec.Time != nil {
		e.SetTime(spec.Time.UTC())
	}
	e.SetDataContentType(cloudevents.ApplicationJSON)
	if spec.DataSchema != nil {
		e.SetDataSchema(*spec.DataSchema)
	}
	// SetData would take a []byte for binary data, and mark it as base64, but this is JSON text.
	e.DataEncoded = data
	if spec.Coverage != nil {
		e.SetExtension(sdkevidence.ExtCoverage, *spec.Coverage)
	}
	if spec.Platform != nil {
		e.SetExtension(sdkevidence.ExtPlatform, *spec.Platform)
	}
	if err := sdkevidence.Validate(e); err != nil {
		return nil, fmt.Errorf("the Evidence %q holds no valid evidence: %w", obj.Name, err)
	}
	return &Record{Key: keyOf(spec), CollectorVersion: spec.CollectorVersion, Event: e}, nil
}

// decompress returns the data that compressed holds, which must be exactly size bytes long.
func decompress(compressed []byte, size int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, errors.New("the data is not gzip")
	}
	// The reader has nothing to release, and a Close would only repeat what the reads report. One
	// byte more than the size tells data of exactly that size from longer data.
	data, err := io.ReadAll(io.LimitReader(zr, size+1))
	if err != nil {
		return nil, errors.New("the gzip data is corrupt")
	}
	if int64(len(data)) != size {
		return nil, errors.New("the data is not as long as the object says")
	}
	return data, nil
}
