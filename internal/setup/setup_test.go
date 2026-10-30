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

package setup_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/bedag/vexplain/internal/setup"
)

// An empty namespace means every namespace to the manager's cache, so the cache of Secrets would
// span the cluster. Register checks its options before it uses the manager, so the test needs
// none.
func TestRegisterRefusesAnEmptyOperatorNamespace(t *testing.T) {
	err := setup.Register(nil, setup.Options{})

	require.ErrorContains(t, err, "operator namespace")
}

// The evidence and the facts of every scan name the scanner image, and the API records 512
// characters of it at most, so a longer one would fail every scan.
func TestRegisterRefusesAScannerImageLongerThanTheAPIRecords(t *testing.T) {
	err := setup.Register(nil, setup.Options{
		OperatorNamespace: operatorNamespace,
		ScannerImage:      "scanner.example/" + strings.Repeat("a", 497),
	})

	require.ErrorContains(t, err, "scanner image")
}

// A matcher URL that can't be called would make every match and every read of the database fail,
// over and over, and the hub would write no sheet. It is refused at start instead.
func TestRegisterRefusesAMatcherURLThatIsNoHTTPURL(t *testing.T) {
	for _, url := range []string{"matcher:8080", "ftp://matcher.example", "http://", "http//matcher:8080", "http://matcher:port"} {
		err := setup.Register(nil, setup.Options{OperatorNamespace: operatorNamespace, MatcherURL: url})

		require.ErrorContains(t, err, "matcher URL", url)
	}
}

// A scan Job's environment holds the location of its credentials and the proxy variables, and
// nothing else: another variable, such as DOCKER_AUTH_CONFIG, could hand the scanner other
// credentials.
func TestRegisterRefusesAVariableInProxyEnvThatIsNoProxyVariable(t *testing.T) {
	for _, variable := range []string{"DOCKER_AUTH_CONFIG", "DOCKER_CONFIG", "ALL_PROXY", "Https_Proxy"} {
		err := setup.Register(nil, setup.Options{
			OperatorNamespace: operatorNamespace,
			ProxyEnv:          []corev1.EnvVar{{Name: "HTTPS_PROXY", Value: "http://proxy.example:3128"}, {Name: variable}},
		})

		require.ErrorContains(t, err, variable)
	}
}
