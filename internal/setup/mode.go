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

package setup

import (
	"fmt"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// Mode says which roles one manager runs: the spoke's, which collects in its own cluster, the hub's, which judges what
// the spokes collected, or both.
type Mode string

const (
	// ModeHub runs the hub's controllers and the executor, and no presence: the clusters it serves collect on their own.
	ModeHub Mode = "Hub"
	// ModeSpoke only collects in its own cluster.
	ModeSpoke Mode = "Spoke"
	// ModeHubAndSpoke runs both. It is the default, and what a single cluster needs.
	ModeHubAndSpoke Mode = "HubAndSpoke"
)

// ParseMode returns the mode that s names. The empty string is ModeHubAndSpoke. Case matters, as it does for the
// values of the API's enums.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case "":
		return ModeHubAndSpoke, nil
	case ModeHub, ModeSpoke, ModeHubAndSpoke:
		return m, nil
	}
	return "", fmt.Errorf("unknown mode %q: want %s, %s or %s", s, ModeHub, ModeSpoke, ModeHubAndSpoke)
}

// Runs says whether the mode runs the role. A mode that isn't set runs both, so a zero Options is what it was before
// the modes.
func (m Mode) Runs(role configv1alpha1.CollectorRole) bool {
	switch role {
	case configv1alpha1.CollectorRoleHub:
		return m != ModeSpoke
	case configv1alpha1.CollectorRoleSpoke:
		return m != ModeHub
	}
	return false
}
