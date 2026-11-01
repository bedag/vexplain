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
	source = "/clusters/cluster-a/collectors/matcher"
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
	build := func(subjectText string, opts ...evidence.Option) cloudevents.Event {
		e, err := evidence.New(evidence.TypeFindings, subjectText, sampleFindings(),
			append([]evidence.Option{evidence.WithSource(source)}, opts...)...)
		require.NoError(t, err)
		return e
	}
	image := subject.Image(digest)

	t.Run("accepts", func(t *testing.T) {
		tests := map[string]cloudevents.Event{
			"an event with every attribute":     fullEvent(t),
			"no extension":                      build(image),
			"a collector's own kind of subject": build("vm/cluster-a/db-1"),
			"a workload subject":                build("workload/cluster-a/team-a/Deployment.apps/web"),
			"coverage 0":                        build(image, evidence.WithCoverage(0)),
			"coverage 100":                      build(image, evidence.WithCoverage(100)),
			"a platform with an os and an arch": build(image, evidence.WithPlatform("linux/amd64")),
			"a platform with a variant":         build(image, evidence.WithPlatform("linux/arm64/v8")),
		}
		for name, e := range tests {
			t.Run(name, func(t *testing.T) {
				require.NoError(t, evidence.Validate(e))
			})
		}
	})

	t.Run("refuses", func(t *testing.T) {
		wrongType := func(name string, value any) cloudevents.Event {
			e := build(image)
			e.SetExtension(name, value)
			return e
		}
		withSpecVersion := func(version string) cloudevents.Event {
			e := build(image)
			e.SetSpecVersion(version)
			return e
		}
		// Each group is about one attribute, which the error has to name.
		groups := []struct {
			attribute string
			events    map[string]cloudevents.Event
		}{
			{evidence.ExtCoverage, map[string]cloudevents.Event{
				"101":                build(image, evidence.WithCoverage(101)),
				"-1":                 build(image, evidence.WithCoverage(-1)),
				"a string":           wrongType(evidence.ExtCoverage, "50"),
				"a boolean":          wrongType(evidence.ExtCoverage, true),
				"the largest number": build(image, evidence.WithCoverage(math.MaxInt32)),
			}},
			{evidence.ExtPlatform, map[string]cloudevents.Event{
				"only an os":               build(image, evidence.WithPlatform("linux")),
				"a trailing slash":         build(image, evidence.WithPlatform("linux/")),
				"no os":                    build(image, evidence.WithPlatform("/amd64")),
				"an empty variant":         build(image, evidence.WithPlatform("linux/amd64/")),
				"an empty arch":            build(image, evidence.WithPlatform("linux//v8")),
				"four parts":               build(image, evidence.WithPlatform("linux/arm64/v8/extra")),
				"an empty platform":        build(image, evidence.WithPlatform("")),
				"an integer, not a string": wrongType(evidence.ExtPlatform, 5),
			}},
			{"subject", map[string]cloudevents.Event{
				"an empty subject":                 build(""),
				"a subject without a path":         build("vm"),
				"an image subject with a bad hash": build("image/sha256:abc"),
			}},
			{"source", map[string]cloudevents.Event{
				"no source": build(image, evidence.WithSource("")),
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
					require.ErrorContains(t, err, group.attribute)
				})
			}
		}

		t.Run("no event at all", func(t *testing.T) {
			require.Error(t, evidence.Validate(cloudevents.Event{}))
		})
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
	for _, eventType := range []string{evidence.TypePresence, evidence.TypeFindings, evidence.TypeExposure} {
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
