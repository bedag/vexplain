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

// Package evidence keeps the evidence that collectors deliver, and the facts of each image that
// vexplain records from it (decision 0032).
//
// Every piece of evidence is a CloudEvent. A Store keeps one record of it for each subject, type and
// source, the source being the Collector that delivered it, and for each cluster whose stream
// delivered it. It keeps each record current: a changed event, of any version of the collector, is
// written in place (decision 0058). The Store is the only door to the evidence (decision 0004):
// nothing else reads, writes or watches its objects, but the hub's copier of a spoke's records, which
// watches the spoke's objects and decodes them with RecordOf (decision 0063).
//
// A FactsWriter records in the facts of an image what evidence there is about it: the manifests that
// the evidence names for each platform, and for each source and type the collector's version, the
// time and the coverage, so that a reader learns them without knowing the type. It records the
// failures of the collectors too.
//
// Hub and spoke both use the two interfaces: a spoke stores what its collectors deliver, and the hub
// reads it there, without calling the spoke.
package evidence

import (
	"context"
	"errors"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	ctrlsource "sigs.k8s.io/controller-runtime/pkg/source"
)

// DefaultMaxCompressedBytes is the most data that a record holds once compressed, unless the
// operator is set otherwise: 768 KiB. As base64, the form in which JSON carries bytes, that is 1 MiB,
// which keeps the object below etcd's limit of 1.5 MiB for a request.
const DefaultMaxCompressedBytes = 786432

// MaxUncompressedBytes is the most data that a record holds before it is compressed: 64 MiB, as the
// schema of an Evidence allows.
const MaxUncompressedBytes = 64 << 20

// ErrTooLarge means that the data of an event is more than a record holds: more than
// the cap once compressed, or more than MaxUncompressedBytes before. Put returns it, and writes
// nothing. The error it returns is a TooLargeError.
var ErrTooLarge = errors.New("the evidence is larger than the store's cap")

// TooLargeError says how far evidence is over the cap. It is an ErrTooLarge.
type TooLargeError struct {
	// Bytes is the size of the data, and Cap the most that the store holds.
	Bytes, Cap int64
	// Compressed says whether Bytes is the size once compressed, or before.
	Compressed bool
}

func (e *TooLargeError) Error() string {
	form := "of data"
	if e.Compressed {
		form = "compressed"
	}
	return fmt.Sprintf("%s: %d bytes %s, at most %d", ErrTooLarge, e.Bytes, form, e.Cap)
}

// Is reports that a TooLargeError is an ErrTooLarge.
func (e *TooLargeError) Is(target error) bool { return target == ErrTooLarge }

// Key names a record: what its evidence is about, its type, the Collector that delivered it, and the
// cluster whose stream delivered it. Cluster is empty for the evidence that an operation returns,
// which the clusters that run an image share.
type Key struct{ Subject, Type, Source, Cluster string }

// HubSource is the source of the records that the hub writes itself, where a Collector delivers no
// evidence: the copies of the labels of each spoke's namespaces (decision 0063).
const HubSource = "vexplain"

// PutOption changes how Put stores an event.
type PutOption func(*putOptions)

// putOptions are what the PutOptions of a Put set.
type putOptions struct {
	// cluster is the cluster of the key, or "" for none.
	cluster string
	// refreshAfter is the age past which an equal record gets the event's time, or nil for never.
	refreshAfter *time.Duration
}

// InCluster keys the record with the cluster of the name, whose stream delivered the event, so that
// each cluster keeps a record of its own. An empty name is no cluster. A name that isn't a DNS-1123
// label of at most 63 characters makes Put return ErrRefused.
func InCluster(name string) PutOption {
	return func(o *putOptions) { o.cluster = name }
}

// RefreshAfter has Put write an event that equals its record when the record is older than d, and
// the event newer: the record then takes the event's time and ID, and nothing else changes. An answer
// that the hub asked for again so stays within its maxAge while the collector confirms it.
func RefreshAfter(d time.Duration) PutOption {
	return func(o *putOptions) { o.refreshAfter = &d }
}

// Record is the evidence of one key.
type Record struct {
	Key
	// CollectorVersion is the version of the collector that delivered the evidence.
	CollectorVersion string
	// Event is the CloudEvent that carried the evidence.
	Event cloudevents.Event
}

// Encoded is a record whose data isn't decoded yet: what the record says of its evidence, and how
// large the data is once decoded, so that a reader can tell what decoding it will hold before it
// does. Decode decodes it.
type Encoded struct {
	Key
	// CollectorVersion is the version of the collector that delivered the evidence.
	CollectorVersion string
	// EventID and Time are the ID and the time of the CloudEvent that carried the evidence, and
	// Coverage is its coverage, or nil when it has none.
	EventID  string
	Time     time.Time
	Coverage *int32
	// Size is the length of the data once decoded, in bytes, as the record says it. Decode refuses
	// data of another length, so no decoding holds more.
	Size int64
	// decode decodes the data, and returns the record.
	decode func() (*Record, error)
}

// Decode decodes the data, and returns the record, as Get does. A record whose data can't be read
// returns an error, and never nil, nil.
func (e *Encoded) Decode() (*Record, error) {
	return e.decode()
}

// Store keeps the evidence: one record for each subject, type and source, and for each cluster of
// streamed evidence. It is the only way to read, write or watch it.
//
// A record gives back the event that Put stored, but for what a record can't hold. Its time is kept
// to the second. Its data is JSON, and comes back as application/json, without any parameter of the
// media type. Of the extension attributes, it keeps coverage and platform, the two that the core
// reads, and no other. So a record goes to a collector again as valid evidence, such as the input of
// an operation.
type Store interface {
	// Put keeps the record of an event current. It writes the record in place when the event differs
	// from it: in its data, in an attribute that the record keeps, or in the collector's version. An
	// event that differs only in its ID and time writes nothing, unless RefreshAfter says otherwise.
	// A write that meets another writer's reads the record again, and decides again.
	//
	// source is the name of the Collector that delivered the event; the event's subject and type
	// complete the key, and InCluster adds a cluster to it. The event must be valid evidence, as the
	// SDK's evidence.Validate checks, and fit what a record holds, or Put returns ErrRefused and
	// writes nothing. An event without a time is stored with the time at which Put received it. Data
	// that is more than a record holds returns ErrTooLarge, and writes nothing.
	Put(ctx context.Context, source, collectorVersion string, e cloudevents.Event, opts ...PutOption) error
	// MaxCompressedBytes returns the cap in force: the most data that Put takes in a record once
	// compressed, as CompressedSize measures it. It follows its setting, so two calls can differ.
	MaxCompressedBytes() int64
	// Get returns the record of a key. A record that can't be read, such as one in an encoding that
	// this version doesn't know, returns an error, and never nil, nil.
	Get(ctx context.Context, k Key) (*Record, error) // nil, nil when absent
	// GetEncoded returns the record of a key as Get does, but without decoding its data, which
	// Encoded.Decode does. A record that can't be decoded at all, such as one in an encoding that this
	// version doesn't know, or one that doesn't say how large its data is, returns an error, and
	// never nil, nil.
	GetEncoded(ctx context.Context, k Key) (*Encoded, error) // nil, nil when absent
	// Version says whether there is a record of a key, and which version of its collector delivered
	// it, from the metadata of the record alone. It reads no data, so a record whose data can't be
	// read is held all the same. It reads the metadata that Source watches, from the cache, and asks
	// the API server when the cache has none, so that a record that was just stored is held before
	// the cache has seen it. A cache that lags can still give the version of a record that was just
	// written in place. A store without a cache asks the API server. A record whose metadata doesn't
	// say its version, which only another writer can make, is held at an empty version, which is no
	// collector's. A failed read returns an error, and never "not held".
	Version(ctx context.Context, k Key) (version string, held bool, err error)
	// ListBySubject returns the records about a subject, ordered by type, by source, and then by
	// cluster. A store with a cache finds them in the metadata that the cache holds, so a record
	// stored a moment ago may be missing until the cache has seen it.
	ListBySubject(ctx context.Context, subject string) ([]Record, error)
	// Delete removes the record of a key. No error if there is none. A key whose source isn't the name
	// of a Collector, or whose cluster isn't the name of a cluster, returns an error, and so does an
	// object of the key's name that holds the record of another key, which stays.
	Delete(ctx context.Context, k Key) error
	// DeleteStreamed removes the records of the cluster that the Collector named source delivered of a
	// type, but for each whose key keep holds: every one, when keep is nil. No error if there is none.
	DeleteStreamed(ctx context.Context, cluster, source, eventType string, keep func(Key) bool) error
	// DeleteSubject removes every record about a subject. No error if there is none.
	DeleteSubject(ctx context.Context, subject string) error
	// DeleteBySource removes the records that the Collector named source delivered: its asked evidence and
	// its streamed records of the store's own cluster. The records that it streamed in other clusters stay, for
	// a hub holds copies of them. No error if there is none.
	DeleteBySource(ctx context.Context, source string) error
	// Subjects returns each subject that has a record, once, sorted.
	Subjects(ctx context.Context) ([]string, error)
	// Source delivers a request whose name is the subject of a record, whenever a record is created,
	// written in place or deleted. A controller watches the evidence through it.
	Source() ctrlsource.Source // one request per created, written or deleted record, named by subject
}
