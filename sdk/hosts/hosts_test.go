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

package hosts_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/hosts"
)

func TestAHostIsAllowedByNameOrAsASubdomainOfADottedEntry(t *testing.T) {
	domains, bad := hosts.Domains([]string{"security.alpinelinux.org", ".debian.org", "Ubuntu.COM"})
	require.Empty(t, bad)
	for host, allowed := range map[string]bool{
		"security.alpinelinux.org":    true,
		"Security.AlpineLinux.ORG":    true,
		"security-tracker.debian.org": true,
		"debian.org":                  false,
		"ubuntu.com":                  true,
		"www.ubuntu.com":              false,
		"lists.busybox.net":           false,
		"127.0.0.1":                   false,
		"":                            false,
	} {
		require.Equal(t, allowed, hosts.Allows(domains, host), host)
	}
}

func TestDomainsNamesTheEntriesThatAreNoHost(t *testing.T) {
	_, bad := hosts.Domains([]string{"github.com", "1.2.3.4", "a..b", ".", "host:443", "*.example.org"})
	require.Equal(t, []int{1, 2, 3, 4, 5}, bad)
}

// Check refuses what a fetch never takes, before any connection, each for a reason of its own in a fixed text.
func TestCheckRefusesAURLThatAFetchNeverTakes(t *testing.T) {
	domains, _ := hosts.Domains([]string{"security-tracker.debian.org"})
	for raw, want := range map[string]error{
		"https://security-tracker.debian.org/tracker/CVE-2026-0001":        nil,
		"https://security-tracker.debian.org:443/tracker":                  nil,
		"http://security-tracker.debian.org/tracker":                       hosts.RefusedScheme,
		"mailto:security@security-tracker.debian.org":                      hosts.RefusedScheme,
		"https://security-tracker.debian.org:8443/tracker":                 hosts.RefusedPort,
		"https://someone:secret@security-tracker.debian.org/tracker":       hosts.RefusedUser,
		"https://192.0.2.1/tracker":                                        hosts.RefusedIP,
		"https://[2001:db8::1]/tracker":                                    hosts.RefusedIP,
		"https://www.cve.org/CVERecord?id=CVE-2026-0001":                   hosts.RefusedHost,
		"https://security-tracker.debian.org/" + strings.Repeat("a", 2048): hosts.RefusedLength,
	} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		require.Equal(t, want, hosts.Check(domains, u), raw)
	}
}

// The default is what the advisories collector reaches without settings: the hosts of Grype's providers' advisories.
func TestTheDefaultHoldsTheProvidersHosts(t *testing.T) {
	domains, bad := hosts.Domains(hosts.Default)
	require.Empty(t, bad)
	require.True(t, hosts.Allows(domains, "security.alpinelinux.org"))
	require.True(t, hosts.Allows(domains, "security-tracker.debian.org"))
	require.False(t, hosts.Allows(domains, "www.cve.org"))
}
