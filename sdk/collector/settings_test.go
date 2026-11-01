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

package collector_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
)

// The problems of settings that the tests expect.
const (
	missingGreeting = "at '': missing property 'greeting'"
	notJSONProblem  = "the settings are not JSON"
)

// requiredSchema needs a greeting, so that no settings at all break it.
const requiredSchema = `{
	"type": "object",
	"properties": {
		"greeting": {"type": "string"},
		"repeat": {"type": "integer", "minimum": 1}
	},
	"required": ["greeting"],
	"additionalProperties": false
}`

// validated records the settings that reach a collector's own validator.
type validated struct {
	mu       sync.Mutex
	settings []string
}

func (v *validated) record(settings json.RawMessage) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.settings = append(v.settings, string(settings))
}

// take returns what was recorded since the last call.
func (v *validated) take() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	taken := v.settings
	v.settings = nil
	return taken
}

// problems asks the server what is wrong with settings.
func (s *testServer) problems(t *testing.T, settings string) []string {
	t.Helper()
	resp, err := s.identityClient().ValidateSettings(callContext(t),
		&collectorv1alpha1.ValidateSettingsRequest{Settings: []byte(settings)})
	require.NoError(t, err)
	return resp.GetProblems()
}

func TestValidateSettings(t *testing.T) {
	seen := &validated{}
	c := &fakeCollector{
		caps: collector.Capabilities{SettingsSchema: []byte(requiredSchema)},
		validate: func(settings json.RawMessage) []string {
			seen.record(settings)
			if string(settings) == refusedSettings {
				return []string{refusal}
			}
			return nil
		},
	}
	s := serve(t, c)

	tests := []struct {
		name     string
		settings string
		problems []string
		// validated is whether the settings reach the collector's own validator.
		validated bool
	}{
		{name: "settings that the schema and the collector take", settings: `{"greeting": "hello"}`, validated: true},
		{
			name:     "a violation of the schema, which the collector doesn't see",
			settings: `{"greeting": "hello", "repeat": 0}`,
			problems: []string{"at '/repeat': minimum: got 0, want 1"},
		},
		{
			name:      "then the collector's own problem",
			settings:  refusedSettings,
			problems:  []string{refusal},
			validated: true,
		},
		{
			name:     "every violation of the schema, sorted",
			settings: `{"repeat": 0, "extra": true}`,
			problems: []string{
				"at '': additional properties 'extra' not allowed",
				missingGreeting,
				"at '/repeat': minimum: got 0, want 1",
			},
		},
		{name: "what isn't JSON", settings: `{"greeting":`, problems: []string{notJSONProblem}},
		{
			name:     "no settings, which are an empty object",
			settings: "",
			problems: []string{missingGreeting},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Several times, because the schema's properties are a map, which has no order.
			for range 5 {
				require.Equal(t, tc.problems, s.problems(t, tc.settings))
			}
			if tc.validated {
				require.Equal(t, []string{tc.settings, tc.settings, tc.settings, tc.settings, tc.settings}, seen.take())
			} else {
				require.Empty(t, seen.take(), "settings that break their schema don't reach the collector")
			}
		})
	}
}

func TestValidateSettingsWithoutASchemaOrAValidator(t *testing.T) {
	t.Run("without a schema, the collector's own validator", func(t *testing.T) {
		s := serve(t, &fakeCollector{})
		require.Empty(t, s.problems(t, validSettings))
		require.Equal(t, []string{refusal}, s.problems(t, refusedSettings))
		require.Equal(t, []string{notJSONProblem}, s.problems(t, `{"greeting":`))
	})
	t.Run("without a validator, the schema", func(t *testing.T) {
		s := serve(t, plainCollector{caps: collector.Capabilities{SettingsSchema: []byte(requiredSchema)}})
		require.Empty(t, s.problems(t, refusedSettings))
		require.Equal(t, []string{missingGreeting}, s.problems(t, `{}`))
	})
	t.Run("with neither, any JSON", func(t *testing.T) {
		s := serve(t, plainCollector{})
		require.Empty(t, s.problems(t, `{"anything": [1, 2]}`))
		require.Empty(t, s.problems(t, ""))
		require.Equal(t, []string{notJSONProblem}, s.problems(t, `{"greeting":`))
	})
}

func TestServeRefusesASchemaThatDoesNotCompile(t *testing.T) {
	// A schema stands alone: the operator compiles it too, without the collector's files. So even a
	// file that holds a valid schema can't be referenced.
	other := filepath.Join(t.TempDir(), "other.json")
	require.NoError(t, os.WriteFile(other, []byte(`{"type": "object"}`), 0o600))
	schemas := map[string]string{
		"a schema that isn't JSON":             `{"type":`,
		"a schema that breaks the metaschema":  `{"type": "nope"}`,
		"a schema that refers to another file": `{"$ref": "file://` + filepath.ToSlash(other) + `"}`,
	}
	// collectors are a collector with a schema, for each schema that it can have.
	collectors := map[string]func(schema string) collector.Collector{
		"the settings schema": func(schema string) collector.Collector {
			return plainCollector{caps: collector.Capabilities{SettingsSchema: []byte(schema)}}
		},
		"the parameter schema of an operation": func(schema string) collector.Collector {
			caps := capabilities()
			caps.Operations[0].ParameterSchema = []byte(schema)
			return &fakeCollector{caps: caps}
		},
	}

	for which, collectorWith := range collectors {
		for name, schema := range schemas {
			t.Run(which+", "+name, func(t *testing.T) {
				registry := prometheus.NewRegistry()
				requireRefused(t, collectorWith(schema), collector.Options{
					GRPCAddress: freeAddress(t), HealthAddress: freeAddress(t), Insecure: true, Registry: registry,
				})
				// A collector that is refused leaves nothing in the registry, so the counter registers.
				require.NoError(t, registry.Register(prometheus.NewCounterVec(prometheus.CounterOpts{
					Name: "vexplain_collector_requests_total", Help: "The calls of the collector API.",
				}, []string{"cluster", "method", "code"})))
			})
		}
	}
}
