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
// source, the source being the Collector that delivered it, and writes it once for each version of
// that collector: what a new version delivers replaces what an older one did. The Store is the only
// door to the evidence (decision 0004): nothing else reads, writes or watches its objects.
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
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	ctrlsource "sigs.k8s.io/controller-runtime/pkg/source"
)

// MaxCompressedBytes is the most data that a record holds once compressed: 768 KiB. As base64, the
// form in which JSON carries bytes, that is 1 MiB, the length that the schema of an Evidence allows
// for its data, which keeps the object below etcd's limit of 1.5 MiB for a request.
const MaxCompressedBytes = 786432

// MaxUncompressedBytes is the most data that a record holds before it is compressed: 64 MiB, as the
// schema of an Evidence allows.
const MaxUncompressedBytes = 64 << 20

// ErrTooLarge means that the data of an event is more than a record holds: more than
// MaxCompressedBytes once compressed, or more than MaxUncompressedBytes before. Put returns it, and
// writes nothing.
var ErrTooLarge = errors.New("the evidence is larger than the store's cap")

// Key names a record: what its evidence is about, its type, and the Collector that delivered it.
type Key struct{ Subject, Type, Source string }

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

// Store keeps the evidence: one record for each subject, type and source. It is the only way to read,
// write or watch it.
//
// A record gives back the event that Put stored, but for what a record can't hold. Its time is kept
// to the second. Its data is JSON, and comes back as application/json, without any parameter of the
// media type. Of the extension attributes, it keeps coverage and platform, the two that the core
// reads, and no other. So a record goes to a collector again as valid evidence, such as the input of
// an operation.
type Store interface {
	// Put stores an event once per key and collector version. A record of another version is
	// replaced; one of the same version is left as it is.
	//
	// source is the name of the Collector that delivered the event; the event's subject and type
	// complete the key. The event must be valid evidence, as the SDK's evidence.Validate checks, and
	// fit what a record holds, or Put returns ErrRefused and writes nothing. An event without a time
	// is stored with the time at which Put received it. Data that is more than a record holds
	// returns ErrTooLarge, and writes nothing.
	Put(ctx context.Context, source, collectorVersion string, e cloudevents.Event) error
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
	// replaced. A store without a cache asks the API server. A record whose metadata doesn't say its
	// version, which only another writer can make, is held at an empty version, which is no
	// collector's. A failed read returns an error, and never "not held".
	Version(ctx context.Context, k Key) (version string, held bool, err error)
	// ListBySubject returns the records about a subject, ordered by type and then by source.
	ListBySubject(ctx context.Context, subject string) ([]Record, error)
	// DeleteSubject removes every record about a subject. No error if there is none.
	DeleteSubject(ctx context.Context, subject string) error
	// DeleteBySource removes every record that the Collector named source delivered. No error if
	// there is none.
	DeleteBySource(ctx context.Context, source string) error
	// Subjects returns each subject that has a record, once, sorted.
	Subjects(ctx context.Context) ([]string, error)
	// Source delivers a request whose name is the subject of a record, whenever a record is created
	// or deleted. A controller watches the evidence through it.
	Source() ctrlsource.Source // one request per created or deleted record, named by subject
}
