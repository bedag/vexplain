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
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/collector"
)

func TestEntryPointParameterSchema(t *testing.T) {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(collector.EntryPointParameterSchema))
	require.NoError(t, err)
	compiler := jsonschema.NewCompiler()
	require.NoError(t, compiler.AddResource("urn:test:parameters", doc))
	schema, err := compiler.Compile("urn:test:parameters")
	require.NoError(t, err)

	check := func(instance string) error {
		inst, err := jsonschema.UnmarshalJSON(strings.NewReader(instance))
		require.NoError(t, err)
		return schema.Validate(inst)
	}
	require.NoError(t, check(`{"hosts": ["a.app.example"]}`))
	require.NoError(t, check(`{"addresses": ["192.0.2.10:443"]}`))
	require.NoError(t, check(`{"hosts": ["a.app.example"], "addresses": ["192.0.2.10"]}`))
	require.Error(t, check(`{}`))
	require.Error(t, check(`{"hosts": [`+strings.TrimSuffix(strings.Repeat(`"a.app.example",`, 65), ",")+`]}`))
	require.Error(t, check(`{"hosts": [""]}`))
	require.Error(t, check(`{"hosts": ["a.app.example"], "ports": [1]}`))
	require.Equal(t, 64, collector.MaxPointsPerCall)
}
