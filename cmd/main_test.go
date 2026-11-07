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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/setup"
)

func TestOptionsComeFromTheEnvironmentOfTheManager(t *testing.T) {
	environment := map[string]string{
		"POD_NAMESPACE": "vexplain-ops",
		// The matcher is a collector of its own, which its Collector configures: this says nothing to the manager
		// any more.
		"VEXPLAIN_MATCHER_URL": "http://matcher.vexplain-ops.svc:8080",
		// The scanner is a collector of its own, which its Collector configures: these say nothing to the
		// manager any more.
		"VEXPLAIN_SCANNER_IMAGE":         "scanner.example/vexplain-scanner:1.0",
		"VEXPLAIN_SCAN_REGISTRY_MIRRORS": "localhost:5001=http://registry.example:5000",
		// The manager's proxy is its own: no collector gets it (decision 0037).
		"HTTPS_PROXY": "http://proxy.example:3128",
		"no_proxy":    "10.0.0.0/8,.cluster.local",
	}

	opts := optionsFromEnvironment(func(name string) string { return environment[name] })

	require.Equal(t, setup.Options{OperatorNamespace: "vexplain-ops"}, opts)
}

// Outside the cluster, nothing is set: the operator runs in its default namespace.
func TestOptionsOfAnEmptyEnvironment(t *testing.T) {
	opts := optionsFromEnvironment(func(string) string { return "" })

	require.Equal(t, setup.Options{OperatorNamespace: "vexplain-system"}, opts)
}
