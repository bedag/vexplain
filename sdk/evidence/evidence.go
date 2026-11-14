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

// Package evidence builds, checks and converts the evidence that collectors send to vexplain, and
// defines the core types (decisions 0032 and 0044).
//
// Every piece of evidence is a CloudEvent of version 1.0, and its data is JSON. Besides the
// attributes that CloudEvents defines, it can carry two extension attributes: coverage, a whole
// number from 0 to 100, and platform, as os/arch[/variant]. An event about a manifest carries
// platform, so that the platforms of a digest can be listed without knowing the type. Validate
// checks all of this.
//
// The core reads three types, which Presence, Findings and Exposure describe. The fourth core type,
// which SBOM describes, is a neutral package inventory that any producer can write and any consumer,
// such as a vulnerability matcher, can read. A collector defines as many other types as it needs,
// and the core passes those on.
package evidence

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	protobuf "github.com/cloudevents/sdk-go/binding/format/protobuf/v2"
	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/google/uuid"

	subjects "github.com/bedag/vexplain/sdk/subject"
)

// The types that the core reads.
const (
	// TypePresence is what runs where: one reported image digest, and the workloads that run it.
	// Its scope is Spoke.
	TypePresence = "ch.bedag.vexplain.presence.v1alpha1"
	// TypeFindings is what a source found in a manifest. Its scope is Hub.
	TypeFindings = "ch.bedag.vexplain.findings.v1alpha1"
	// TypeExposure is how far a workload can be reached. Its scope is Spoke.
	TypeExposure = "ch.bedag.vexplain.exposure.v1alpha1"
	// TypeSBOM is a subject's package inventory: its distribution, and each package with its identities. An event of
	// it is about a manifest, carries platform and coverage, and its scope is Hub.
	TypeSBOM = "ch.bedag.vexplain.sbom.v1alpha1"
)

// TypePattern is what the name of a type of evidence looks like, as a regular expression: reverse-DNS, and versioned,
// such as ch.bedag.vexplain.presence.v1alpha1 or com.example.hello.v2beta1. The version is a v and a number, and
// may go on with alpha or beta and a number. It is the pattern of Go's regexp and of a CRD's validation alike, so
// that the conformance suite, which checks the types that a collector produces, and whatever else checks the name
// of a type, such as a CRD's validation, use one text. A change to it changes what every collector may name its
// types.
const TypePattern = `^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`

var typePattern = regexp.MustCompile(TypePattern)

// ValidType reports whether s is a valid name for a type of evidence: it matches TypePattern.
func ValidType(s string) bool { return typePattern.MatchString(s) }

// The extension attributes of evidence.
const (
	// ExtCoverage is an integer from 0 to 100: how much of the subject the evidence covers. The core
	// shows and records it, and never interprets it. Each type says what it counts.
	ExtCoverage = "coverage"
	// ExtPlatform is the platform that the evidence is about, as os/arch[/variant].
	ExtPlatform = "platform"
)

const (
	// maxCoverage is the largest coverage: a percentage.
	maxCoverage = 100
	// schemaURNPrefix starts the dataschema of every event. What follows is the event's type, and
	// the schema that Schema returns for the type has the same URN as its $id.
	schemaURNPrefix = "urn:vexplain:schema:"
)

// Option changes an event that New built.
type Option func(*cloudevents.Event)

// WithCoverage sets the extension coverage. Validate refuses a value outside 0 to 100.
func WithCoverage(percent int32) Option {
	return func(e *cloudevents.Event) { e.SetExtension(ExtCoverage, percent) }
}

// WithPlatform sets the extension platform, as os/arch[/variant]. Validate refuses any other form.
func WithPlatform(platform string) Option {
	return func(e *cloudevents.Event) { e.SetExtension(ExtPlatform, platform) }
}

// WithTime sets when the collector saw what the event is about. The event keeps the instant and
// writes it in UTC, as the protobuf format reads it back.
func WithTime(t time.Time) Option {
	return func(e *cloudevents.Event) { e.SetTime(t.UTC()) }
}

// WithSource sets the source: the collector, and its cluster or the hub, such as
// /clusters/cluster-a/collectors/vulnerabilities.
func WithSource(source string) Option {
	return func(e *cloudevents.Event) { e.SetSource(source) }
}

// New builds an event: a random UUID, specversion 1.0, the time now unless WithTime,
// application/json, and the dataschema "urn:vexplain:schema:<type>". The data is encoded with
// encoding/json, so a json.RawMessage is kept as it is. It has no source unless WithSource sets
// one, and Validate refuses an event without.
func New(eventType, subject string, data any, opts ...Option) (cloudevents.Event, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return cloudevents.Event{}, fmt.Errorf("encoding the data of a %s event: %w", eventType, err)
	}
	e := cloudevents.NewEvent(cloudevents.VersionV1)
	e.SetID(uuid.NewString())
	e.SetType(eventType)
	e.SetSubject(subject)
	e.SetTime(time.Now().UTC())
	e.SetDataSchema(schemaURNPrefix + eventType)
	e.SetDataContentType(cloudevents.ApplicationJSON)
	// SetData would take a []byte for binary data and mark it as base64, but this is JSON text.
	e.DataEncoded = encoded
	for _, opt := range opts {
		opt(&e)
	}
	return e, nil
}

// Coverage returns the extension coverage. It returns false when the event has none, or when it
// isn't an integer. It doesn't check the range: Validate does.
func Coverage(e cloudevents.Event) (int32, bool) {
	coverage, ok := e.Extensions()[ExtCoverage].(int32)
	return coverage, ok
}

// Platform returns the extension platform. It returns false when the event has none, or when it
// isn't a string. It doesn't check the form: Validate does.
func Platform(e cloudevents.Event) (string, bool) {
	platform, ok := e.Extensions()[ExtPlatform].(string)
	return platform, ok
}

// nonEmptyString is what CloudEvents asks of several of its attributes.
const nonEmptyString = "must be a non-empty string"

// attributeRules say, in this package's words, what CloudEvents asks of each of its attributes. They are
// keyed by the name under which the CloudEvents SDK reports a problem with the attribute, and they are the
// only names that Validate takes from the SDK: any other name is a collector's own.
var attributeRules = map[string]string{
	"specversion":     "must be 1.0",
	"id":              nonEmptyString,
	"source":          "must be a non-empty URI reference",
	"type":            nonEmptyString,
	"subject":         nonEmptyString,
	"time":            "must be a timestamp",
	"datacontenttype": "must be a media type",
	"dataschema":      "must be an absolute URI",
}

const (
	// extensionKeyPrefix starts the name under which the SDK reports a problem with an extension
	// attribute. What follows is the name that a collector gave the attribute.
	extensionKeyPrefix = "extension:"
	// extensionAttribute names every extension attribute that the SDK refuses, whatever it is called.
	extensionAttribute = "extension"
	extensionRule      = "needs a name of ASCII letters and digits, and a value of a CloudEvents type"
	// otherAttribute names a problem that the SDK reports under a name that is neither of the above.
	otherAttribute = "attribute"
	otherRule      = "is not valid in CloudEvents 1.0"
)

// attributeProblems says what the CloudEvents SDK found wrong with an event, in this package's words. The
// SDK's messages repeat the names and the values that a collector chose, and an error can reach logs and the
// failures of a stream. So nothing of them is used but a name from attributeRules, in alphabetical order.
func attributeProblems(err error) error {
	var invalid event.ValidationError
	if !errors.As(err, &invalid) {
		return errors.New("the event is not valid in CloudEvents 1.0")
	}
	rules := make(map[string]string, len(invalid))
	for name := range invalid {
		if rule, known := attributeRules[name]; known {
			rules[name] = rule
		} else if strings.HasPrefix(name, extensionKeyPrefix) {
			rules[extensionAttribute] = extensionRule
		} else {
			rules[otherAttribute] = otherRule
		}
	}
	problems := make([]string, 0, len(rules))
	for _, name := range slices.Sorted(maps.Keys(rules)) {
		problems = append(problems, name+": "+rules[name])
	}
	return errors.New(strings.Join(problems, "; "))
}

// Validate checks that the event is evidence:
//   - It is CloudEvents 1.0, its attributes are valid and its subject parses.
//   - Its data is JSON, and its datacontenttype is application/json. The case of the media type and any
//     parameter of it, such as a charset, don't matter.
//   - Its coverage is from 0 to 100, if it has one.
//   - Its platform is os/arch[/variant], if it has one. An event about a manifest always has one, so that the
//     platforms of a digest can be listed without knowing the type.
//
// It returns the first check that fails, except that the attributes that CloudEvents refuses come
// together. Its errors name an attribute from a fixed list and say what is wrong in this package's words.
// They never repeat anything that a collector chose, such as the name of an extension attribute, because an
// error can reach logs and the failures of a stream.
func Validate(e cloudevents.Event) error {
	if e.SpecVersion() != cloudevents.VersionV1 {
		return errors.New("specversion: evidence is CloudEvents " + cloudevents.VersionV1)
	}
	if err := e.Validate(); err != nil {
		return attributeProblems(err)
	}
	if !strings.EqualFold(e.DataMediaType(), cloudevents.ApplicationJSON) {
		return errors.New("datacontenttype: the data of evidence is " + cloudevents.ApplicationJSON)
	}
	if !json.Valid(e.Data()) {
		return errors.New("data: the data of evidence is JSON, and this is not")
	}
	if e.Subject() == "" {
		return errors.New("subject: evidence is about a subject, and this has none")
	}
	about, err := subjects.Parse(e.Subject())
	if err != nil {
		return fmt.Errorf("subject: %w", err)
	}
	if err = validateCoverage(e); err != nil {
		return err
	}
	return validatePlatform(e, about.Kind == subjects.KindManifest)
}

// validateCoverage checks the extension coverage, when the event has it.
func validateCoverage(e cloudevents.Event) error {
	value, ok := e.Extensions()[ExtCoverage]
	if !ok {
		return nil
	}
	if coverage, isInteger := value.(int32); !isInteger || coverage < 0 || coverage > maxCoverage {
		return errors.New("coverage: a whole number from 0 to 100")
	}
	return nil
}

// validatePlatform checks the extension platform, which an event about a manifest has to have.
func validatePlatform(e cloudevents.Event, aboutManifest bool) error {
	value, ok := e.Extensions()[ExtPlatform]
	if !ok {
		if aboutManifest {
			return errors.New("platform: an event about a manifest has one")
		}
		return nil
	}
	if platform, isString := value.(string); !isString || !isPlatform(platform) {
		return errors.New("platform: os/arch or os/arch/variant, with no empty part")
	}
	return nil
}

// isPlatform reports whether s is os/arch or os/arch/variant, the form of OCI platforms. It
// doesn't limit which names are used.
func isPlatform(s string) bool {
	parts := strings.Split(s, "/")
	return (len(parts) == 2 || len(parts) == 3) && !slices.Contains(parts, "")
}

// ToProto converts an event to the CloudEvent of the collector API's messages.
func ToProto(e cloudevents.Event) (*pb.CloudEvent, error) {
	return protobuf.ToProto(&e)
}

// FromProto converts a CloudEvent of the collector API's messages to an event. It doesn't check the event:
// Validate does. A collector can send its JSON data as text_data instead of binary_data, and FromProto keeps
// that text as the data, whatever the content type says. Its errors never repeat anything that a collector
// chose, such as the name or the value of an attribute: an error can reach logs and the failures of a stream.
func FromProto(p *pb.CloudEvent) (cloudevents.Event, error) {
	if p == nil {
		return cloudevents.Event{}, errors.New("no CloudEvent")
	}
	// The conversion below dereferences these. A message that came over the wire has neither, but
	// one that was built in memory can, and an error is better than a panic.
	for _, value := range p.GetAttributes() {
		if value == nil {
			return cloudevents.Event{}, errors.New("an attribute has no value")
		}
	}
	if data, ok := p.GetData().(*pb.CloudEvent_ProtoData); ok && data.ProtoData == nil {
		return cloudevents.Event{}, errors.New("proto_data has no message")
	}
	converted := p
	if data, ok := p.GetData().(*pb.CloudEvent_TextData); ok {
		// The conversion would encode the text again for the data content type, which turns JSON text into
		// a quoted string, and which fails for a content type that it doesn't know, with an error that
		// repeats it. The text is the data, so it goes in as binary_data, which the conversion keeps as it is.
		converted = &pb.CloudEvent{
			Id:          p.GetId(),
			Source:      p.GetSource(),
			SpecVersion: p.GetSpecVersion(),
			Type:        p.GetType(),
			Attributes:  p.GetAttributes(),
			Data:        &pb.CloudEvent_BinaryData{BinaryData: []byte(data.TextData)},
		}
	}
	e, err := protobuf.FromProto(converted)
	if err != nil {
		// What is left to fail is the conversion of an attribute. The error names it and repeats its value.
		return cloudevents.Event{}, errors.New("an attribute has a value that CloudEvents can't hold")
	}
	return *e, nil
}

//go:embed schemas/*.json
var schemas embed.FS

// schemaFiles are the files of the core types' schemas.
var schemaFiles = map[string]string{
	TypePresence: "schemas/" + TypePresence + ".json",
	TypeFindings: "schemas/" + TypeFindings + ".json",
	TypeExposure: "schemas/" + TypeExposure + ".json",
	TypeSBOM:     "schemas/" + TypeSBOM + ".json",
}

// Schema returns the JSON Schema of one of the core types' data, which a collector returns from
// GetCapabilities for the type. It returns false for any other type. The schema's $id is the
// dataschema of the type's events.
func Schema(eventType string) ([]byte, bool) {
	file, ok := schemaFiles[eventType]
	if !ok {
		return nil, false
	}
	schema, err := schemas.ReadFile(file)
	if err != nil {
		return nil, false
	}
	return schema, true
}
