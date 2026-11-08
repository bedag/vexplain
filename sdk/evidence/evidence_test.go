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
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	source = "/clusters/cluster-a/collectors/vulnerabilities"
	// otherType is a type of a collector's own, which the core doesn't know.
	otherType = "example.type"
	// specVersion is the version of CloudEvents that evidence is.
	specVersion = "1.0"
)

// fullEvent is an event with every attribute and both extensions.
func fullEvent(t *testing.T) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(evidence.TypeFindings, subject.Manifest(digest), sampleFindings(),
		evidence.WithSource(source),
		evidence.WithTime(time.Date(2026, time.October, 31, 12, 30, 5, 123456789, time.UTC)),
		evidence.WithCoverage(87),
		evidence.WithPlatform("linux/arm64/v8"))
	require.NoError(t, err)
	return e
}

// The names of attributes that the tests of Validate name again and again.
const (
	attrSubject         = "subject"
	attrDataContentType = "datacontenttype"
)

// marker is text that a collector chose, put where an error could repeat it. With its hyphen it is not a valid
// name of an attribute and not a valid media type, and with the DEL character after it, not a valid URI.
const marker = "marker-text"

// eventAbout returns an event about subjectText that a collector at source could send. It is valid, unless an option
// makes it not.
func eventAbout(t *testing.T, subjectText string, opts ...evidence.Option) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(evidence.TypeFindings, subjectText, sampleFindings(),
		append([]evidence.Option{evidence.WithSource(source)}, opts...)...)
	require.NoError(t, err)
	return e
}

// withContentType sets the content type of e, which it returns. The event's context is shared by copies of it, so
// a test builds each event it changes on its own.
func withContentType(e cloudevents.Event, contentType string) cloudevents.Event {
	e.SetDataContentType(contentType)
	return e
}

// withData sets the data of e, which it returns, to text that is not checked.
func withData(e cloudevents.Event, data string) cloudevents.Event {
	e.DataEncoded = []byte(data)
	return e
}

func TestNewSetsEveryAttribute(t *testing.T) {
	// The time has a zone other than UTC and a nanosecond part: New keeps the instant, and writes it
	// in UTC, so that an event is the same after a round trip through the protobuf format.
	at := time.Date(2026, time.October, 31, 14, 30, 5, 123456789, time.FixedZone("UTC+2", 2*60*60))
	data := sampleFindings()

	e, err := evidence.New(evidence.TypeFindings, subject.Manifest(digest), data,
		evidence.WithSource(source),
		evidence.WithTime(at),
		evidence.WithCoverage(87),
		evidence.WithPlatform("linux/arm64/v8"))
	require.NoError(t, err)

	id, err := uuid.Parse(e.ID())
	require.NoError(t, err)
	require.Equal(t, uuid.Version(4), id.Version(), "a random UUID")
	require.Equal(t, specVersion, e.SpecVersion())
	require.Equal(t, evidence.TypeFindings, e.Type())
	require.Equal(t, subject.Manifest(digest), e.Subject())
	require.Equal(t, source, e.Source())
	require.True(t, at.Equal(e.Time()), "the instant is kept")
	require.Equal(t, time.UTC, e.Time().Location())
	require.Equal(t, "application/json", e.DataContentType())
	require.Equal(t, "urn:vexplain:schema:ch.bedag.vexplain.findings.v1alpha1", e.DataSchema())
	require.False(t, e.DataBase64, "the data is JSON text, not binary")
	require.JSONEq(t, jsonOf(t, data), string(e.Data()))

	coverage, ok := evidence.Coverage(e)
	require.True(t, ok)
	require.Equal(t, int32(87), coverage)
	platform, ok := evidence.Platform(e)
	require.True(t, ok)
	require.Equal(t, "linux/arm64/v8", platform)

	require.NoError(t, evidence.Validate(e))
}

func TestNewDefaults(t *testing.T) {
	before := time.Now()
	e, err := evidence.New(evidence.TypePresence, subject.Image(digest), samplePresence())
	after := time.Now()
	require.NoError(t, err)

	require.False(t, e.Time().Before(before), "the time is now")
	require.False(t, e.Time().After(after), "the time is now")
	require.Equal(t, time.UTC, e.Time().Location())
	require.Empty(t, e.Source(), "the source is the caller's to set")

	_, ok := evidence.Coverage(e)
	require.False(t, ok, "no coverage unless asked for")
	_, ok = evidence.Platform(e)
	require.False(t, ok, "no platform unless asked for")

	other, err := evidence.New(evidence.TypePresence, subject.Image(digest), samplePresence())
	require.NoError(t, err)
	require.NotEqual(t, e.ID(), other.ID())
}

func TestNewEncodesTheDataAsJSON(t *testing.T) {
	t.Run("JSON that is already encoded is kept as text", func(t *testing.T) {
		e, err := evidence.New(otherType, subject.Image(digest), json.RawMessage(`{"a": 1}`))
		require.NoError(t, err)
		require.JSONEq(t, `{"a":1}`, string(e.Data()))
		require.False(t, e.DataBase64)
	})
	t.Run("data that can't be encoded is refused", func(t *testing.T) {
		_, err := evidence.New(otherType, subject.Image(digest), make(chan int))
		require.Error(t, err)
		_, err = evidence.New(otherType, subject.Image(digest), json.RawMessage(`{not json`))
		require.Error(t, err)
	})
}

func TestValidate(t *testing.T) {
	image := subject.Image(digest)
	manifest := subject.Manifest(digest)

	t.Run("accepts", func(t *testing.T) {
		tests := map[string]cloudevents.Event{
			"an event with every attribute":            fullEvent(t),
			"no extension":                             eventAbout(t, image),
			"a collector's own kind of subject":        eventAbout(t, "vm/cluster-a/db-1"),
			"a workload subject":                       eventAbout(t, "workload/cluster-a/team-a/Deployment.apps/web"),
			"coverage 0":                               eventAbout(t, image, evidence.WithCoverage(0)),
			"coverage 100":                             eventAbout(t, image, evidence.WithCoverage(100)),
			"a platform with an os and an arch":        eventAbout(t, image, evidence.WithPlatform("linux/amd64")),
			"a platform with a variant":                eventAbout(t, image, evidence.WithPlatform("linux/arm64/v8")),
			"a manifest with a platform":               eventAbout(t, manifest, evidence.WithPlatform("linux/amd64")),
			"a content type with a parameter":          withContentType(eventAbout(t, image), "application/json; charset=utf-8"),
			"a content type in another case":           withContentType(eventAbout(t, image), "Application/JSON"),
			"data that is a JSON array, not an object": withData(eventAbout(t, image), `[1, 2]`),
		}
		for name, e := range tests {
			t.Run(name, func(t *testing.T) {
				require.NoError(t, evidence.Validate(e))
			})
		}
	})

	t.Run("refuses", func(t *testing.T) {
		wrongType := func(name string, value any) cloudevents.Event {
			e := eventAbout(t, image)
			e.SetExtension(name, value)
			return e
		}
		withSpecVersion := func(version string) cloudevents.Event {
			e := eventAbout(t, image)
			e.SetSpecVersion(version)
			return e
		}
		// Each group is about one attribute, which the error has to name, followed by a colon.
		groups := []struct {
			attribute string
			events    map[string]cloudevents.Event
		}{
			{evidence.ExtCoverage, map[string]cloudevents.Event{
				"101":                eventAbout(t, image, evidence.WithCoverage(101)),
				"-1":                 eventAbout(t, image, evidence.WithCoverage(-1)),
				"a string":           wrongType(evidence.ExtCoverage, "50"),
				"a boolean":          wrongType(evidence.ExtCoverage, true),
				"the largest number": eventAbout(t, image, evidence.WithCoverage(math.MaxInt32)),
			}},
			{evidence.ExtPlatform, map[string]cloudevents.Event{
				"only an os":                      eventAbout(t, image, evidence.WithPlatform("linux")),
				"a trailing slash":                eventAbout(t, image, evidence.WithPlatform("linux/")),
				"no os":                           eventAbout(t, image, evidence.WithPlatform("/amd64")),
				"an empty variant":                eventAbout(t, image, evidence.WithPlatform("linux/amd64/")),
				"an empty arch":                   eventAbout(t, image, evidence.WithPlatform("linux//v8")),
				"four parts":                      eventAbout(t, image, evidence.WithPlatform("linux/arm64/v8/extra")),
				"an empty platform":               eventAbout(t, image, evidence.WithPlatform("")),
				"an integer, not a string":        wrongType(evidence.ExtPlatform, 5),
				"a manifest that has no platform": eventAbout(t, manifest),
			}},
			{attrSubject, map[string]cloudevents.Event{
				"an empty subject":                 eventAbout(t, ""),
				"a subject without a path":         eventAbout(t, "vm"),
				"an image subject with a bad hash": eventAbout(t, "image/sha256:abc"),
			}},
			{attrDataContentType, map[string]cloudevents.Event{
				"text/plain":               withContentType(eventAbout(t, image), "text/plain"),
				"application/xml":          withContentType(eventAbout(t, image), "application/xml"),
				"a longer name than JSON":  withContentType(eventAbout(t, image), "application/jsonx"),
				"no content type":          withContentType(eventAbout(t, image), ""),
				"what is not a media type": withContentType(eventAbout(t, image), "json"),
			}},
			{"data", map[string]cloudevents.Event{
				"text that is not JSON":      withData(eventAbout(t, image), "{not json"),
				"JSON that stops short":      withData(eventAbout(t, image), `{"version":`),
				"JSON followed by more text": withData(eventAbout(t, image), `{} x`),
				"no data":                    withData(eventAbout(t, image), ""),
			}},
			{"source", map[string]cloudevents.Event{
				"no source": eventAbout(t, image, evidence.WithSource("")),
			}},
			{"specversion", map[string]cloudevents.Event{
				"another version of the spec": withSpecVersion("0.3"),
			}},
		}
		for _, group := range groups {
			for name, e := range group.events {
				t.Run(group.attribute+"/"+name, func(t *testing.T) {
					err := evidence.Validate(e)
					require.Error(t, err)
					require.ErrorContains(t, err, group.attribute+":")
				})
			}
		}

		t.Run("no event at all", func(t *testing.T) {
			require.Error(t, evidence.Validate(cloudevents.Event{}))
		})
	})
}

// A collector chooses the names and the values of its attributes, and an error of Validate or FromProto can reach logs
// and the failures of a stream. So no error repeats them, and that includes the errors that come from the CloudEvents
// SDK, whose messages do repeat them. An error names an attribute from a fixed list instead.
func TestErrorsDoNotRepeatWhatACollectorChose(t *testing.T) {
	image := subject.Image(digest)
	withExtension := func(name string, value any) cloudevents.Event {
		e := eventAbout(t, image)
		e.SetExtension(name, value)
		return e
	}
	// The type of an event goes into its dataschema, where the DEL character makes an invalid URI.
	typed, err := evidence.New(marker+"\x7f", image, sampleFindings(), evidence.WithSource(source))
	require.NoError(t, err)

	requireNothingRepeated := func(t *testing.T, err error, says string) {
		t.Helper()
		require.Error(t, err)
		if says != "" {
			require.ErrorContains(t, err, says+":")
		}
		require.NotContains(t, strings.ToLower(err.Error()), "marker")
	}

	t.Run("Validate", func(t *testing.T) {
		tests := []struct {
			name  string
			event cloudevents.Event
			says  string // the attribute that the error names instead
		}{
			{"the name of an extension attribute", withExtension(marker, "x"), "extension"},
			{"the name of an extension attribute, in other case", withExtension("Marker-Text-Name", "x"), "extension"},
			{"the type of the event, in its dataschema", typed, "dataschema"},
			{"the source", eventAbout(t, image, evidence.WithSource(marker+"\x7f")), "source"},
			{"a content type that is not a media type", withContentType(eventAbout(t, image), marker), attrDataContentType},
			{"a media type that is not JSON", withContentType(eventAbout(t, image), marker+"/"+marker), attrDataContentType},
			{"data that is not JSON", withData(eventAbout(t, image), "{"+marker), "data"},
			{"a subject without a path", eventAbout(t, marker), attrSubject},
			{"a subject of the wrong form", eventAbout(t, "image/sha256:"+marker), attrSubject},
			{"a platform", eventAbout(t, image, evidence.WithPlatform(marker)), evidence.ExtPlatform},
			{"a coverage that is a string", withExtension(evidence.ExtCoverage, marker), "coverage"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				requireNothingRepeated(t, evidence.Validate(tc.event), tc.says)
			})
		}
	})

	// The SDK reports a problem with the attribute datacontentencoding of CloudEvents 0.3 under that name. A name
	// that is not in the fixed list is not repeated, whoever chose it.
	t.Run("Validate names an attribute outside the list as just an attribute", func(t *testing.T) {
		e := eventAbout(t, image)
		e.SetDataContentEncoding("base64")
		err := evidence.Validate(e)
		requireNothingRepeated(t, err, "attribute")
		require.NotContains(t, err.Error(), "datacontentencoding")
	})

	t.Run("Validate names several attributes in one order", func(t *testing.T) {
		e := eventAbout(t, image, evidence.WithSource(marker+"\x7f"))
		e.SetExtension(marker, "x")
		e.SetID("")
		first := evidence.Validate(e)
		requireNothingRepeated(t, first, "id")
		for range 20 {
			require.EqualError(t, evidence.Validate(e), first.Error(), "the order doesn't change")
		}
		// Alphabetical, so the same for any event with the same problems.
		extension, id, src := strings.Index(first.Error(), "extension:"), strings.Index(first.Error(), "id:"),
			strings.Index(first.Error(), "source:")
		require.True(t, 0 <= extension && extension < id && id < src, first.Error())
	})

	t.Run("Validate, for a message from the wire", func(t *testing.T) {
		p, err := evidence.ToProto(fullEvent(t))
		require.NoError(t, err)
		p.Attributes["Marker-Text-Name"] = &pb.CloudEventAttributeValue{
			Attr: &pb.CloudEventAttributeValue_CeString{CeString: marker},
		}
		wire, err := proto.Marshal(p)
		require.NoError(t, err)
		var received pb.CloudEvent
		require.NoError(t, proto.Unmarshal(wire, &received))

		e, err := evidence.FromProto(&received)
		require.NoError(t, err)
		requireNothingRepeated(t, evidence.Validate(e), "extension")
	})

	t.Run("FromProto", func(t *testing.T) {
		attribute := func(value *pb.CloudEventAttributeValue) *pb.CloudEvent {
			return &pb.CloudEvent{
				Id: "1", Source: source, SpecVersion: specVersion, Type: otherType,
				Attributes: map[string]*pb.CloudEventAttributeValue{marker: value},
			}
		}
		tests := map[string]*pb.CloudEvent{
			"a URI that can't be read": attribute(
				&pb.CloudEventAttributeValue{Attr: &pb.CloudEventAttributeValue_CeUri{CeUri: marker + "\x7f"}}),
			"a URI reference that can't be read": attribute(
				&pb.CloudEventAttributeValue{Attr: &pb.CloudEventAttributeValue_CeUriRef{CeUriRef: marker + "\x7f"}}),
			"an attribute of no type":      attribute(&pb.CloudEventAttributeValue{}),
			"an attribute without a value": attribute(nil),
		}
		for name, p := range tests {
			t.Run(name, func(t *testing.T) {
				_, err := evidence.FromProto(p)
				requireNothingRepeated(t, err, "")
			})
		}
	})
}

func TestProtoRoundTrip(t *testing.T) {
	e := fullEvent(t)

	p, err := evidence.ToProto(e)
	require.NoError(t, err)

	// What a collector in another language has to send.
	require.Equal(t, e.ID(), p.GetId())
	require.Equal(t, source, p.GetSource())
	require.Equal(t, specVersion, p.GetSpecVersion())
	require.Equal(t, evidence.TypeFindings, p.GetType())
	require.Equal(t, int32(87), p.GetAttributes()[evidence.ExtCoverage].GetCeInteger(), "coverage is an integer")
	require.Equal(t, "linux/arm64/v8", p.GetAttributes()[evidence.ExtPlatform].GetCeString(), "platform is a string")
	require.Equal(t, subject.Manifest(digest), p.GetAttributes()["subject"].GetCeString())
	require.JSONEq(t, jsonOf(t, sampleFindings()), string(p.GetBinaryData()))

	got, err := evidence.FromProto(p)
	require.NoError(t, err)
	require.Equal(t, e, got)

	// And through the wire, as gRPC sends it.
	wire, err := proto.Marshal(p)
	require.NoError(t, err)
	var received pb.CloudEvent
	require.NoError(t, proto.Unmarshal(wire, &received))
	got, err = evidence.FromProto(&received)
	require.NoError(t, err)
	require.Equal(t, e, got)
	require.NoError(t, evidence.Validate(got))
}

func TestFromProto(t *testing.T) {
	attributes := func(contentType string) map[string]*pb.CloudEventAttributeValue {
		return map[string]*pb.CloudEventAttributeValue{
			"datacontenttype": {Attr: &pb.CloudEventAttributeValue_CeString{CeString: contentType}},
		}
	}

	t.Run("keeps JSON text that a collector sends as text_data", func(t *testing.T) {
		p := &pb.CloudEvent{
			Id: "1", Source: source, SpecVersion: specVersion, Type: evidence.TypeFindings,
			Attributes: attributes("application/json"),
			Data:       &pb.CloudEvent_TextData{TextData: `{"version":"v1","matches":[]}`},
		}
		e, err := evidence.FromProto(p)
		require.NoError(t, err)
		require.Equal(t, `{"version":"v1","matches":[]}`, string(e.Data()))
		require.False(t, e.DataBase64)
	})

	t.Run("keeps text_data whatever its content type, and leaves the content type to Validate", func(t *testing.T) {
		p := &pb.CloudEvent{
			Id: "1", Source: source, SpecVersion: specVersion, Type: evidence.TypeFindings,
			Attributes: attributes(marker + "/" + marker),
			Data:       &pb.CloudEvent_TextData{TextData: `{"version":"v1","matches":[]}`},
		}
		e, err := evidence.FromProto(p)
		require.NoError(t, err)
		require.Equal(t, `{"version":"v1","matches":[]}`, string(e.Data()))
		require.ErrorContains(t, evidence.Validate(e), attrDataContentType+":")
	})

	t.Run("refuses what it can't read, and doesn't panic", func(t *testing.T) {
		tests := map[string]*pb.CloudEvent{
			"no event": nil,
			"an attribute without a value": {
				Id: "1", Source: source, SpecVersion: specVersion, Type: otherType,
				Attributes: map[string]*pb.CloudEventAttributeValue{"coverage": nil},
			},
			"proto_data without a message": {
				Id: "1", Source: source, SpecVersion: specVersion, Type: otherType,
				Data: &pb.CloudEvent_ProtoData{},
			},
		}
		for name, p := range tests {
			t.Run(name, func(t *testing.T) {
				require.NotPanics(t, func() {
					_, err := evidence.FromProto(p)
					require.Error(t, err)
				})
			})
		}
	})

	t.Run("leaves an event that is not valid for Validate to refuse", func(t *testing.T) {
		p := &pb.CloudEvent{Id: "1", Source: source, SpecVersion: specVersion, Type: otherType}
		e, err := evidence.FromProto(p)
		require.NoError(t, err)
		require.Error(t, evidence.Validate(e), "an empty subject")
	})
}

func TestSchema(t *testing.T) {
	coreTypes := []string{evidence.TypePresence, evidence.TypeFindings, evidence.TypeExposure, evidence.TypeSBOM}
	for _, eventType := range coreTypes {
		t.Run(eventType, func(t *testing.T) {
			schema, ok := evidence.Schema(eventType)
			require.True(t, ok)

			var doc struct {
				ID     string `json:"$id"`
				Schema string `json:"$schema"`
			}
			require.NoError(t, json.Unmarshal(schema, &doc))
			require.Equal(t, "https://json-schema.org/draft/2020-12/schema", doc.Schema)

			// The dataschema of an event names the schema that Schema returns.
			e, err := evidence.New(eventType, subject.Image(digest), json.RawMessage(`{}`))
			require.NoError(t, err)
			require.Equal(t, doc.ID, e.DataSchema())

			// The caller can change what it gets without changing the next answer.
			original := string(schema)
			schema[0] = 'X'
			again, ok := evidence.Schema(eventType)
			require.True(t, ok)
			require.Equal(t, original, string(again))
		})
	}

	t.Run("only the core types have one", func(t *testing.T) {
		for _, eventType := range []string{
			"ch.bedag.vexplain.scanner.image-contents.v1alpha1", "../evidence", "", "presence",
		} {
			schema, ok := evidence.Schema(eventType)
			require.False(t, ok, eventType)
			require.Nil(t, schema)
		}
	})
}

func TestValidType(t *testing.T) {
	valid := []string{
		evidence.TypePresence,
		evidence.TypeFindings,
		evidence.TypeExposure,
		evidence.TypeSBOM,
		"ch.bedag.vexplain.scanner.image-contents.v1alpha1",
		"com.example.hello.v1",
		"com.example.hello.v12",
		"com.example.hello.v2beta3",
		"com.example.hello.v1alpha10",
		"example.hello.v1",
		"a-b.c-d.v1",
	}
	for _, name := range valid {
		require.True(t, evidence.ValidType(name), "%q is a valid type", name)
	}

	invalid := map[string]string{
		"":                                "nothing",
		"hello":                           "a name without a domain",
		"hello.v1alpha1":                  "a version and a name of one part",
		"com.example.hello":               "no version",
		"com.example.hello.1":             "a version without its v",
		"com.example.hello.v":             "a v without a number",
		"com.example.hello.v1alpha":       "alpha without a number",
		"com.example.hello.v1alpha1beta1": "alpha and beta together",
		"com.example.hello.v1gamma1":      "a stage that is neither alpha nor beta",
		"com.example.Hello.v1alpha1":      "capitals",
		"com.example.hello_world.v1":      "an underscore",
		"com.example.hello.v1alpha1.x":    "something after the version",
		"com..hello.v1":                   "an empty part",
		"com.example. hello.v1":           "a space",
		"com.example.hello.v1\n":          "a line end after the version",
	}
	for name, why := range invalid {
		require.False(t, evidence.ValidType(name), "%q is not a valid type: %s", name, why)
	}
}

// TestTypePatternIsTheContracts pins the text of TypePattern, which other code repeats, such as the CRD marker that
// validates the types a Collector declares. A change to the pattern changes what every collector may name its types.
func TestTypePatternIsTheContracts(t *testing.T) {
	require.Equal(t, `^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`, evidence.TypePattern)
}
