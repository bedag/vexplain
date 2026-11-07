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

package inventory_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/inventory"
)

func TestPlatformCoveredBySameOSArchitectureAndVariantOrAnyWhenOneNamesNone(t *testing.T) {
	// Each case is the manifest's platform and the pod's, and whether the first covers the second.
	for want, cases := range map[bool][]string{
		true: {
			"linux/arm64 linux/arm64", "linux/arm64/v8 linux/arm64", "linux/arm64 linux/arm64/v8", "linux/arm/v7 linux/arm/v7",
		},
		false: {
			"linux/arm/v6 linux/arm/v7", "linux/amd64 linux/arm64", "windows/amd64 linux/amd64", "unknown/unknown linux/amd64",
			"linux linux/amd64",
		},
	} {
		for _, c := range cases {
			platforms := strings.Fields(c)
			require.Equal(t, want, inventory.PlatformCovers(platforms[0], platforms[1]), c)
		}
	}
	require.False(t, inventory.PlatformCovers("linux/amd64", ""), "no platform is covered by none")
}
