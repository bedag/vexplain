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

package match

import (
	"strings"
	"testing"

	grypeversion "github.com/anchore/grype/grype/version"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/grype"
	"github.com/bedag/vexplain/sdk/evidence"
)

const (
	deb124      = "1.2-4"
	goInstalled = "v1.2.3"
	goFixed     = "v1.2.5"
	lodashFixed = "4.17.21"
	pep1        = "1.0"
	typeNPM     = "npm"
	cve1        = "CVE-2026-1"
	ghsaA       = "GHSA-aaaa"
)

func TestFixTargetIsTheLowestFixedVersionAboveTheInstalledOne(t *testing.T) {
	for name, tc := range map[string]struct {
		format    grypeversion.Format
		installed string
		fixed     []string
		want      string
	}{
		"plain deb":         {grypeversion.DebFormat, "1.2-3", []string{"1.3-1", deb124}, deb124},
		"deb with a tilde":  {grypeversion.DebFormat, "3.0.11-1~deb12u1", []string{"3.0.11-1~deb12u2", "3.0.12-1"}, "3.0.11-1~deb12u2"},
		"deb epoch":         {grypeversion.DebFormat, "1.9-1", []string{"1:1.0-1", "2.0-1"}, "2.0-1"},
		"apk with releases": {grypeversion.ApkFormat, "1.1.24-r8", []string{"1.1.24-r10", "1.1.24-r9"}, "1.1.24-r9"},
		"rpm with el":       {grypeversion.RpmFormat, "1.2.3-4.el9", []string{"1.2.3-10.el9", "1.2.3-5.el9"}, "1.2.3-5.el9"},
		"go":                {grypeversion.GolangFormat, goInstalled, []string{"v1.3.0", goFixed}, goFixed},
		"go ten after nine": {grypeversion.GolangFormat, goInstalled, []string{"v1.2.10", "v1.2.9"}, "v1.2.9"},
		"semver":            {grypeversion.SemanticFormat, "4.17.20", []string{lodashFixed, "5.0.0"}, lodashFixed},
		"python":            {grypeversion.PythonFormat, "2.0.0rc1", []string{"2.0.0", "2.0.1"}, "2.0.0"},
		"python post":       {grypeversion.PythonFormat, pep1, []string{"1.0.post1", "1.1"}, "1.0.post1"},
		"maven":             {grypeversion.MavenFormat, "2.14.0", []string{"2.15.0", "2.17.1"}, "2.15.0"},
		"maven qualifier":   {grypeversion.MavenFormat, "1.0-beta1", []string{pep1, "1.1"}, pep1},

		"an unparsable fixed version is skipped": {grypeversion.GolangFormat, goInstalled, []string{"not a version", goFixed}, goFixed},
		"only unparsable fixed versions":         {grypeversion.GolangFormat, goInstalled, []string{"latest", "next"}, ""},
		"an unparsable installed version":        {grypeversion.GolangFormat, "unreleased", []string{goFixed}, ""},
		"no installed version":                   {grypeversion.DebFormat, "", []string{deb124}, ""},
		"no format":                              {grypeversion.UnknownFormat, "1.2.3", []string{"1.2.5"}, ""},
		"no fix above the installed version":     {grypeversion.DebFormat, deb124, []string{"1.2-3", deb124}, ""},
		"no fixed versions":                      {grypeversion.DebFormat, deb124, nil, ""},
		"a target that is too long": {
			grypeversion.SemanticFormat, "1.0.0", []string{"1.0.1-" + strings.Repeat("a", 130)}, "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, fixTarget(tc.format, tc.installed, tc.fixed))
		})
	}
}

func TestFixTargetOfEqualVersionsIsTheSameWhateverTheOrder(t *testing.T) {
	// 1.02 and 1.2 compare equal in semantic order, and the lower text is the target.
	a := fixTarget(grypeversion.SemanticFormat, "1.0.0", []string{"1.2.0", "1.02.0"})
	b := fixTarget(grypeversion.SemanticFormat, "1.0.0", []string{"1.02.0", "1.2.0"})
	require.Equal(t, a, b)
}

func TestFormatOfPrefersTheSchemeGrypeMatchedWith(t *testing.T) {
	semver := []grypeversion.Format{grypeversion.SemanticFormat}
	for name, tc := range map[string]struct {
		match grype.Match
		want  grypeversion.Format
	}{
		"npm names a scheme that the type doesn't": {
			grype.Match{PackageType: typeNPM, ConstraintFormats: semver}, grypeversion.SemanticFormat,
		},
		"the constraint wins over the type": {
			grype.Match{PackageType: typeDeb, ConstraintFormats: []grypeversion.Format{grypeversion.DebFormat}}, grypeversion.DebFormat,
		},
		"no constraint scheme: the type's": {
			grype.Match{PackageType: "go-module"}, grypeversion.GolangFormat,
		},
		"java is maven":     {grype.Match{PackageType: "java-archive"}, grypeversion.MavenFormat},
		"a type nobody has": {grype.Match{PackageType: typeNPM}, grypeversion.UnknownFormat},
		"two schemes, none is certain": {
			grype.Match{PackageType: typeDeb, ConstraintFormats: []grypeversion.Format{grypeversion.DebFormat, grypeversion.SemanticFormat}},
			grypeversion.UnknownFormat,
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, formatOf(tc.match))
		})
	}
}

func TestMatchOfCarriesTheEnvelopeTheAliasesAndTheTarget(t *testing.T) {
	m, format := matchOf(grype.Match{
		VulnerabilityID: cve1, PackageID: "p1", PackageName: "lodash", PackageVersion: "4.17.20", PackageType: typeNPM,
		FixedVersions: []string{lodashFixed}, ConstraintFormats: []grypeversion.Format{grypeversion.SemanticFormat},
		Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
	})
	require.Equal(t, grypeversion.SemanticFormat, format)
	require.Equal(t, "CVE-2026-1/p1", m.ID)
	require.Equal(t, "CVE-2026-1 in lodash 4.17.20", m.Title)
	require.Equal(t, lodashFixed, m.FixTarget)
	require.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, m.Aliases)
}

func TestMatchOfLeavesNoTargetForATypeNoSchemeIsKnownFor(t *testing.T) {
	m, format := matchOf(grype.Match{
		VulnerabilityID: cve1, PackageID: "p1", PackageName: "left-pad", PackageVersion: "1.0.0", PackageType: typeNPM,
		FixedVersions: []string{"1.0.1"},
	})
	require.Equal(t, grypeversion.UnknownFormat, format)
	require.Empty(t, m.FixTarget)
}

func TestAliasesAreUniqueSortedBoundedAndNeverTheMatchesOwnID(t *testing.T) {
	many := make([]string, 0, 12)
	for _, c := range "abcdefghijkl" {
		many = append(many, "GHSA-"+strings.Repeat(string(c), 4))
	}
	m, _ := matchOf(grype.Match{
		VulnerabilityID: cve1, PackageID: "p1", PackageName: "n", PackageType: typeDeb,
		Aliases: append([]string{cve1, "", strings.Repeat("x", 65), ghsaA, ghsaA}, many...),
	})
	require.Equal(t, []string{
		ghsaA, "GHSA-bbbb", "GHSA-cccc", "GHSA-dddd", "GHSA-eeee", "GHSA-ffff", "GHSA-gggg", "GHSA-hhhh",
	}, m.Aliases, "the first 8 of the sorted list, without the match's own ID, an empty alias or one that is too long")
}

func TestTheEnvelopeIsLeftOutWhereItWouldNeedCutting(t *testing.T) {
	long := strings.Repeat("v", 300)
	m, _ := matchOf(grype.Match{VulnerabilityID: long, PackageID: "p", PackageName: "n", PackageVersion: "1", PackageType: typeDeb})
	require.Empty(t, m.ID, "an ID that is cut names another finding")
	require.LessOrEqual(t, len([]rune(m.Title)), maxTitleLength, "a title that is cut still reads")
	require.NotEmpty(t, m.Title)
}

func TestSetUpdateTargetsGivesEveryMatchOfAPackageTheHighestTarget(t *testing.T) {
	sem := grypeversion.SemanticFormat
	matches := []evidence.Match{
		{PackageID: "p1", FixTarget: "1.2.5"},
		{PackageID: "p1", FixTarget: "1.2.7"},
		{PackageID: "p1"},
		{PackageID: "p2", FixTarget: "9.0.0"},
		{PackageID: "p3"},
	}
	setUpdateTargets(matches, []grypeversion.Format{sem, sem, sem, sem, sem})
	require.Equal(t, "1.2.7", matches[0].UpdateTarget)
	require.Equal(t, "1.2.7", matches[1].UpdateTarget)
	require.Equal(t, "1.2.7", matches[2].UpdateTarget, "the package's, whatever the match's own")
	require.Equal(t, "9.0.0", matches[3].UpdateTarget)
	require.Empty(t, matches[4].UpdateTarget, "a package without a target has none")
}

func TestSetUpdateTargetsComparesNumbersAndNotText(t *testing.T) {
	matches := []evidence.Match{{PackageID: "p", FixTarget: "1.2.9"}, {PackageID: "p", FixTarget: "1.2.10"}}
	setUpdateTargets(matches, []grypeversion.Format{grypeversion.GolangFormat, grypeversion.GolangFormat})
	require.Equal(t, "1.2.10", matches[0].UpdateTarget)
}

func TestSetUpdateTargetsNamesNoneWhereTargetsAreOfAnotherScheme(t *testing.T) {
	matches := []evidence.Match{{PackageID: "p", FixTarget: "1.2.9"}, {PackageID: "p", FixTarget: "1.2.10"}}
	setUpdateTargets(matches, []grypeversion.Format{grypeversion.SemanticFormat, grypeversion.DebFormat})
	require.Empty(t, matches[0].UpdateTarget, "two schemes have no order")
	require.Empty(t, matches[1].UpdateTarget)
}
