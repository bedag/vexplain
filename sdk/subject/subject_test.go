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
