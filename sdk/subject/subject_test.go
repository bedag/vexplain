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

package subject_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/subject"
)

// hash is 64 lowercase hex digits, the hash part of a sha256 digest.
const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const digest = "sha256:" + hash

const (
	clusterA = "cluster-a"
	teamA    = "team-a"
	web      = "web"
)

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		// build makes the subject with the package's own constructor. It is nil for a subject that
		// no constructor makes: the test then only reads text.
		build func() string
		text  string
		want  subject.Subject
	}{
		{
			name:  "an image",
			build: func() string { return subject.Image(digest) },
			text:  "image/" + digest,
			want:  subject.Subject{Kind: subject.KindImage, Digest: digest},
		},
		{
			name:  "a platform manifest",
			build: func() string { return subject.Manifest(digest) },
			text:  "manifest/" + digest,
			want:  subject.Subject{Kind: subject.KindManifest, Digest: digest},
		},
		{
			name: "a Deployment in apps",
			build: func() string {
				return subject.ForWorkload(subject.Workload{
					Cluster: clusterA, Namespace: teamA, Group: "apps", Kind: "Deployment", Name: web,
				})
			},
			text: "workload/cluster-a/team-a/Deployment.apps/web",
			want: subject.Subject{Kind: subject.KindWorkload, Workload: subject.Workload{
				Cluster: clusterA, Namespace: teamA, Group: "apps", Kind: "Deployment", Name: web,
			}},
		},
		{
			name: "a core Pod has no group suffix",
			build: func() string {
				return subject.ForWorkload(subject.Workload{
					Cluster: clusterA, Namespace: teamA, Kind: "Pod", Name: "web-0",
				})
			},
			text: "workload/cluster-a/team-a/Pod/web-0",
			want: subject.Subject{Kind: subject.KindWorkload, Workload: subject.Workload{
				Cluster: clusterA, Namespace: teamA, Kind: "Pod", Name: "web-0",
			}},
		},
		{
			name: "a group with dots splits at the first dot",
			build: func() string {
				return subject.ForWorkload(subject.Workload{
					Cluster: clusterA, Namespace: teamA, Group: "networking.k8s.io", Kind: "Ingress", Name: web,
				})
			},
			text: "workload/cluster-a/team-a/Ingress.networking.k8s.io/web",
			want: subject.Subject{Kind: subject.KindWorkload, Workload: subject.Workload{
				Cluster: clusterA, Namespace: teamA, Group: "networking.k8s.io", Kind: "Ingress", Name: web,
			}},
		},
		{
			name: "a name with dots",
			build: func() string {
				return subject.ForWorkload(subject.Workload{
					Cluster: clusterA, Namespace: teamA, Group: "batch", Kind: "Job", Name: "report.2026-10-31",
				})
			},
			text: "workload/cluster-a/team-a/Job.batch/report.2026-10-31",
			want: subject.Subject{Kind: subject.KindWorkload, Workload: subject.Workload{
				Cluster: clusterA, Namespace: teamA, Group: "batch", Kind: "Job", Name: "report.2026-10-31",
			}},
		},
		{
			name:  "a host",
			build: func() string { return must(t)(subject.Host("Shop.App.Example.")) },
			text:  "host/shop.app.example",
			want:  subject.Subject{Kind: subject.KindHost, Host: "shop.app.example"},
		},
		{
			name:  "an IPv4 address with a port",
			build: func() string { return must(t)(subject.Address("192.0.2.10", 30443)) },
			text:  "address/192.0.2.10:30443",
			want:  subject.Subject{Kind: subject.KindAddress, Addr: netip.MustParseAddr("192.0.2.10"), Port: 30443},
		},
		{
			name:  "an IPv6 address has no brackets without a port",
			build: func() string { return must(t)(subject.Address("2001:db8::1", 0)) },
			text:  "address/2001:db8::1",
			want:  subject.Subject{Kind: subject.KindAddress, Addr: netip.MustParseAddr("2001:db8::1")},
		},
		{
			name:  "an IPv6 address is bracketed before a port",
			build: func() string { return must(t)(subject.Address("2001:db8::1", 443)) },
			text:  "address/[2001:db8::1]:443",
			want:  subject.Subject{Kind: subject.KindAddress, Addr: netip.MustParseAddr("2001:db8::1"), Port: 443},
		},
		{
			name: "a bare IPv6 address that ends like a port is still only an address",
			text: "address/2001:db8::1:443",
			want: subject.Subject{Kind: subject.KindAddress, Addr: netip.MustParseAddr("2001:db8::1:443")},
		},
		{
			name: "a collector's own prefix keeps the whole subject in Raw",
			text: "vm/cluster-a/db-1",
			want: subject.Subject{Kind: "vm", Raw: "vm/cluster-a/db-1"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.build != nil {
				require.Equal(t, tc.text, tc.build())
			}
			got, err := subject.Parse(tc.text)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestParseRefusesADigestThatIsNotSHA256(t *testing.T) {
	bad := map[string]string{
		"empty":                       "",
		"no hash":                     "sha256:",
		"hash too short":              "sha256:" + hash[:63],
		"hash too long":               "sha256:" + hash + "0",
		"upper case hex":              "sha256:" + strings.ToUpper(hash),
		"a character that is not hex": "sha256:" + hash[:63] + "g",
		"another algorithm":           "sha512:" + hash,
		"no algorithm":                hash,
		"algorithm in upper case":     "SHA256:" + hash,
		"leading space":               " " + digest,
		"trailing newline":            digest + "\n",
	}
	for _, kind := range []subject.Kind{subject.KindImage, subject.KindManifest} {
		for name, d := range bad {
			t.Run(string(kind)+"/"+name, func(t *testing.T) {
				_, err := subject.Parse(string(kind) + "/" + d)
				require.Error(t, err)
			})
		}
	}
}

// The error of a digest that isn't sha256 names the kind of its subject, with its article.
func TestTheErrorOfABadDigestNamesTheKindOfItsSubject(t *testing.T) {
	for kind, want := range map[subject.Kind]string{
		subject.KindImage:    "the digest of an image subject",
		subject.KindManifest: "the digest of a manifest subject",
	} {
		_, err := subject.Parse(string(kind) + "/sha256:")
		require.ErrorContains(t, err, want)
	}
}

func TestParseRefusesAMalformedWorkload(t *testing.T) {
	bad := map[string]string{
		"no fields":           "workload/",
		"no name":             "workload/cluster-a/team-a/Deployment.apps",
		"an extra field":      "workload/cluster-a/team-a/Deployment.apps/web/extra",
		"empty cluster":       "workload//team-a/Deployment.apps/web",
		"empty namespace":     "workload/cluster-a//Deployment.apps/web",
		"empty kind":          "workload/cluster-a/team-a//web",
		"empty kind, a group": "workload/cluster-a/team-a/.apps/web",
		"empty group":         "workload/cluster-a/team-a/Deployment./web",
		"empty name":          "workload/cluster-a/team-a/Deployment.apps/",
	}
	for name, text := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := subject.Parse(text)
			require.Error(t, err)
		})
	}
}

func TestParseRefusesWhatHasNoPrefixOrNoRest(t *testing.T) {
	for _, text := range []string{"", "/", "image", "vm", "vm/", "/cluster-a/db-1"} {
		t.Run(text, func(t *testing.T) {
			_, err := subject.Parse(text)
			require.Error(t, err)
		})
	}
}

// A collector chooses its subjects, so no error repeats one: a refusal can reach logs and events.
func TestParseErrorsDoNotRepeatTheSubject(t *testing.T) {
	for _, text := range []string{
		"image/sha256:marker-text",
		"manifest/marker-text",
		"workload/marker-text",
		"workload/marker-text/b/c/d/e",
		"workload/a/b/.marker-text/d",
		"host/marker-text",
		"host/Marker-text.example",
		"address/marker-text",
		"address/192.0.2.10:marker-text",
		"marker-text",
		"marker-text/",
		"/marker-text",
	} {
		t.Run(text, func(t *testing.T) {
			_, err := subject.Parse(text)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "marker-text")
		})
	}
}

// must returns a function that fails the test on an error and otherwise passes the value on.
func must(t *testing.T) func(string, error) string {
	return func(s string, err error) string {
		t.Helper()
		require.NoError(t, err)
		return s
	}
}

func TestHostIsNormalized(t *testing.T) {
	for in, want := range map[string]string{
		"Shop.App.Example.": "host/shop.app.example",
		"*.app.example":     "host/*.app.example",
	} {
		got, err := subject.Host(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got)
	}
	for _, in := range []string{
		"", "localhost", "*.example", "shop_app.example", "-shop.app.example", "shop..app.example",
		"shop.*.example", strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 126) + "ab", // 254 characters
	} {
		_, err := subject.Host(in)
		require.Error(t, err, in)
	}
	_, err := subject.Host(strings.Repeat("a.", 125) + "abc") // 253 characters
	require.NoError(t, err)
}

func TestAddressIsNormalized(t *testing.T) {
	for _, tc := range []struct {
		addr string
		port uint16
		want string
	}{
		{"::ffff:192.0.2.10", 0, "address/192.0.2.10"},
		{"2001:DB8::1", 0, "address/2001:db8::1"},
		{"2001:DB8::1", 443, "address/[2001:db8::1]:443"},
		{"192.0.2.10", 30443, "address/192.0.2.10:30443"},
	} {
		got, err := subject.Address(tc.addr, tc.port)
		require.NoError(t, err, tc.addr)
		require.Equal(t, tc.want, got)
	}
	for _, in := range []string{"fe80::1%eth0", "192.0.2.256", "shop.app.example", ""} {
		_, err := subject.Address(in, 0)
		require.Error(t, err, in)
	}
}

// A namespace's subject names its cluster and its name, each a DNS label, as Kubernetes names a namespace: the hub's
// copy of the namespace's labels is about it.
func TestNamespaceSubjects(t *testing.T) {
	built, err := subject.Namespace(clusterA, teamA)
	require.NoError(t, err)
	require.Equal(t, "namespace/cluster-a/team-a", built)
	parsed, err := subject.Parse(built)
	require.NoError(t, err)
	require.Equal(t, subject.Subject{Kind: subject.KindNamespace, Cluster: clusterA, Namespace: teamA}, parsed)

	label := strings.Repeat("a", 63)
	_, err = subject.Namespace(label, label)
	require.NoError(t, err, "a label of 63 characters")
	for _, names := range [][2]string{
		{"", teamA}, {clusterA, ""}, {"Cluster-a", teamA}, {clusterA, "team.a"}, {clusterA, "team/a"},
		{"-cluster", teamA}, {clusterA, "team-"}, {label + "a", teamA}, {clusterA, label + "a"},
	} {
		_, err := subject.Namespace(names[0], names[1])
		require.Error(t, err, names)
	}
	for _, text := range []string{
		"namespace/cluster-a", "namespace/cluster-a/", "namespace//team-a", "namespace/cluster-a/team-a/web",
		"namespace/Cluster-a/team-a", "namespace/cluster-a/team.a", "namespace/cluster-a/" + label + "a",
		"namespace/marker-text/Marker-text",
	} {
		_, err := subject.Parse(text)
		require.Error(t, err, text)
		require.NotContains(t, err.Error(), "marker-text", "the error doesn't repeat the subject")
	}
}

func TestParseRefusesAHostOrAnAddressOutOfNormalForm(t *testing.T) {
	for _, text := range []string{
		"host/Shop.app.example", "host/shop.app.example.", "host/localhost",
		"address/::ffff:192.0.2.10", "address/[2001:db8::1]", "address/192.0.2.10:0",
	} {
		_, err := subject.Parse(text)
		require.Error(t, err, text)
	}
}
