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
	corev1 "k8s.io/api/core/v1"

	"github.com/bedag/vexplain/internal/setup"
)

// httpsProxyVariable and noProxyVariable are proxy variables, in the case that the test sets them.
const httpsProxyVariable, noProxyVariable = "HTTPS_PROXY", "no_proxy"

func TestOptionsComeFromTheEnvironmentOfTheManager(t *testing.T) {
	environment := map[string]string{
		"POD_NAMESPACE":          "vexplain-ops",
		"VEXPLAIN_SCANNER_IMAGE": "scanner.example/vexplain-scanner:1.0",
		"VEXPLAIN_MATCHER_URL":   "http://matcher.vexplain-ops.svc:8080",
		// Empty entries, and the spaces around an entry, are dropped.
		"VEXPLAIN_SCAN_REGISTRY_MIRRORS": "localhost:5001=http://registry.example:5000, ," +
			"artifacts.example=https://mirror.example ,",
		// The proxy variables, in either case, as far as they are set.
		httpsProxyVariable: "http://proxy.example:3128",
		noProxyVariable:    "10.0.0.0/8,.cluster.local",
		"http_proxy":       "",
		// No other variable reaches a scan Job.
		"ALL_PROXY": "socks5://proxy.example:1080",
	}

	opts := optionsFromEnvironment(func(name string) string { return environment[name] })

	require.Equal(t, setup.Options{
		OperatorNamespace: "vexplain-ops",
		ScannerImage:      "scanner.example/vexplain-scanner:1.0",
		MatcherURL:        "http://matcher.vexplain-ops.svc:8080",
		ScanRegistryMirrors: []string{
			"localhost:5001=http://registry.example:5000",
			"artifacts.example=https://mirror.example",
		},
		ProxyEnv: []corev1.EnvVar{
			{Name: httpsProxyVariable, Value: "http://proxy.example:3128"},
			{Name: noProxyVariable, Value: "10.0.0.0/8,.cluster.local"},
		},
	}, opts)
}

// Outside the cluster, nothing is set: the operator runs in its default namespace, and scans and
// matches nothing.
func TestOptionsOfAnEmptyEnvironment(t *testing.T) {
	opts := optionsFromEnvironment(func(string) string { return "" })

	require.Equal(t, setup.Options{OperatorNamespace: "vexplain-system"}, opts)
}
