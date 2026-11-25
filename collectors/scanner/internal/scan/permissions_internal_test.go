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

package scan

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/conformance"
)

// installedCeilings are the install's files of the ceilings and of the scanner's defaults of them, which the operator
// may grant a collector, from the directory of this package.
var installedCeilings = []string{"../../../../config/rbac/collector.yaml", "../../../../config/rbac/scanner/roles.yaml"}

// The install's defaults cover every permission that the collector declares, each in its own scope, those on kinds
// that a cluster may not serve included: the operator grants a collector nothing beyond the ceilings, so a permission
// that the defaults lack keeps the collector from being Ready on a fresh install.
func TestTheInstallsDefaultsCoverThePermissions(t *testing.T) {
	var manifests []byte
	for _, file := range installedCeilings {
		raw, err := os.ReadFile(file)
		require.NoError(t, err)
		manifests = append(manifests, append(raw, "\n---\n"...)...)
	}

	uncovered, err := conformance.Uncovered(manifests, permissions)

	require.NoError(t, err)
	require.Empty(t, uncovered, "the defaults in %s lack them", installedCeilings)
}
