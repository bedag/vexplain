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

package match_test

import (
	"testing"

	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/grype/grype/pkg/qualifier/rpmmodularity"
	grypeversion "github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/evidence"
)

// AlmaLinux rebuilds RHEL, so Grype v0.121.0 matches an AlmaLinux RPM against RHEL's advisories. Then it drops each
// vulnerability that one of AlmaLinux's own advisories says a release fixed, by its unaffected records. Both are per
// module stream: with an RPM's modularity label, only the records of its own stream apply to it; without the label,
// those of every stream do, and a stream that fixed a vulnerability hides it in another stream that didn't. The
// document gives Grype the label of the sbom evidence, as Syft's JSON gave it in phase 2b.
//
// The records: one CVE that RHEL discloses for the streams nodejs:18 and nodejs:20, and AlmaLinux's advisories that
// fix it in each stream. nodejs:18 has the fix in a version below any of nodejs:20.
func TestAnRPMOfAModuleStreamKeepsTheMatchesOfItsStreamOnAlmaLinux(t *testing.T) {
	const cve = "CVE-2024-0001"
	record := func(id, namespace, constraint, stream string, unaffected bool) vulnerability.Vulnerability {
		v := vulnerability.Vulnerability{
			Reference:         vulnerability.Reference{ID: id, Namespace: namespace},
			PackageName:       nodejs,
			Constraint:        grypeversion.MustGetConstraint(constraint, grypeversion.RpmFormat),
			PackageQualifiers: []qualifier.Qualifier{rpmmodularity.New(stream)},
			Unaffected:        unaffected,
		}
		if id != cve {
			v.RelatedVulnerabilities = []vulnerability.Reference{{ID: cve, Namespace: "nvd:cpe"}}
		}
		return v
	}
	const rhel, alma = "redhat:distro:redhat:8", "almalinux:distro:almalinux:8"
	provider := mock.VulnerabilityProvider(
		record(cve, rhel, "< 1:18.20.2-1.module_el8.9.0", "nodejs:18", false),
		record(cve, rhel, "< 1:20.11.2-1.module_el8.9.0", "nodejs:20", false),
		record("ALSA-2024:0018", alma, ">= 1:18.20.2-1.module_el8.9.0", "nodejs:18", true),
		record("ALSA-2024:0020", alma, ">= 1:20.11.1-1.module_el8.9.0", "nodejs:20", true),
	)

	for name, tc := range map[string]struct {
		version string
		want    []string
	}{
		// The fix of nodejs:18 doesn't apply to an RPM of nodejs:20.
		"below the fix of its stream": {version: "20.10.0-1.module_el8.9.0", want: []string{cve}},
		// AlmaLinux's fix of nodejs:20 applies to it.
		"at the fix of its stream": {version: "20.11.1-1.module_el8.9.0", want: []string{}},
	} {
		t.Run(name, func(t *testing.T) {
			sbom := evidence.SBOM{
				Distro: &evidence.Distro{ID: "almalinux", Version: "8.9", IDLike: []string{"rhel", "centos", "fedora"}},
				Packages: []evidence.SBOMPackage{{
					ID: pkg1, Name: nodejs, Version: "1:" + tc.version, Type: typeRPM,
					PURL: "pkg:rpm/almalinux/nodejs@" + tc.version + "?arch=x86_64&distro=almalinux-8.9&epoch=1" +
						"&upstream=nodejs-" + tc.version + ".src.rpm",
					ModularityLabel: new("nodejs:20:8090020240101000000:a1b2c3d4"),
				}},
				Producer: evidence.Producer{Name: syft, Version: syftVersion},
			}
			pkgs, _ := grypeOf(t, documentOf(t, sbom))

			matches, _, err := rpm.NewRpmMatcher(rpm.MatcherConfig{}).Match(provider, pkgs[pkg1])

			require.NoError(t, err)
			found := make([]string, 0, len(matches))
			for _, m := range matches {
				found = append(found, m.Vulnerability.ID)
			}
			require.Equal(t, tc.want, found)
		})
	}
}
