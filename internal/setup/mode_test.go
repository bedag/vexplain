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
	"testing"

	"github.com/stretchr/testify/require"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/setup"
)

func TestParseMode(t *testing.T) {
	for in, want := range map[string]setup.Mode{
		"": setup.ModeHubAndSpoke, "Hub": setup.ModeHub, "Spoke": setup.ModeSpoke, "HubAndSpoke": setup.ModeHubAndSpoke,
	} {
		got, err := setup.ParseMode(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}

	_, err := setup.ParseMode("hub")
	require.ErrorContains(t, err, `unknown mode "hub"`)
}

func TestEachModeRunsItsRoles(t *testing.T) {
	hub, spoke := configv1alpha1.CollectorRoleHub, configv1alpha1.CollectorRoleSpoke
	require.True(t, setup.ModeHub.Runs(hub))
	require.False(t, setup.ModeHub.Runs(spoke))
	require.False(t, setup.ModeSpoke.Runs(hub))
	require.True(t, setup.ModeSpoke.Runs(spoke))
	require.True(t, setup.ModeHubAndSpoke.Runs(hub))
	require.True(t, setup.ModeHubAndSpoke.Runs(spoke))
	// The zero mode is the default.
	require.True(t, setup.Mode("").Runs(hub))
	require.True(t, setup.Mode("").Runs(spoke))
}
