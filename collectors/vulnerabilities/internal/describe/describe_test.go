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

package describe_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/describe"
	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/grype"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
)

// These tests run describe on what Grype v0.121.0 printed for its searches, kept in testdata (parse.go says how), and
// served by a fake Grype. One test runs it through the wrapper of the real CLI, on a script that stands for Grype.

const (
	// debianCVE is a vulnerability of Brotli that Debian 12 fixed in a release of its own, and debianFixed that release.
	debianCVE   = "CVE-2026-111497"
	debianFixed = "1.0.9-2+deb12u1"
	// ghsa is a GitHub advisory of a Go module, Gin, and ghsaCVE its CVE.
	ghsa    = "GHSA-2c4m-59x9-fr2g"
	ghsaCVE = "CVE-2023-29401"
	gin     = "github.com/gin-gonic/gin"
	// unknownID is in no database.
	unknownID = "CVE-2099-0001"
	// goVuln is a Go vulnerability of the Go vulnerability database, which lists Go's standard library and a module,
	// and goCVE its CVE, which the Go database's record names as an alias. The database holds no record under the CVE
	// itself, so the alias search returns the same rows.
	goVuln = "GO-2026-6612"
	goCVE  = "CVE-2026-78663"
	govuln = "govulndb:language:go"

	// busyboxCVE is a vulnerability of BusyBox, which NVD lists by CPE alone.
	busyboxCVE = "CVE-2022-48174"
	ghsaAlias  = "ghsa-alias"

	libbrotli1 = "libbrotli1"
	brotli     = "brotli"
	typeDeb    = "deb"
	typeGo     = "go-module"
	debian12   = "debian:distro:debian:12"
	debian13   = "debian:distro:debian:13"
	githubGo   = "github:language:go"
	nvdCPE     = "nvd:cpe"
	source     = "/hub/collectors/vulnerabilities"
)

// fixtures maps the IDs of a search, as describe asks for them, to the files in testdata that hold what Grype printed:
// <name>-records.json and <name>-packages.json.
var fixtures = map[string]string{
	debianCVE:            "debian",
	ghsa:                 "ghsa",
	ghsa + " " + ghsaCVE: ghsaAlias,
	unknownID:            "unknown",
	goVuln:               "go",
	goVuln + " " + goCVE: "go-alias",
	goCVE + " " + goVuln: "go-alias",
	busyboxCVE:           "busybox",
}

// fakeGrype answers searches from testdata, from files instead of fixtures where it is set, or with rows, the
// packages of a search, beside a record of each provider of the rows. It records the IDs of each search.
type fakeGrype struct {
	files    map[string]string
	rows     string
	mu       sync.Mutex
	searches [][]string
}

func (f *fakeGrype) Search(_ context.Context, ids ...string) ([]byte, []byte, error) {
	f.mu.Lock()
	f.searches = append(f.searches, ids)
	f.mu.Unlock()
	if f.rows != "" {
		var listings []struct {
			Vulnerability json.RawMessage `json:"vulnerability"`
		}
		if err := json.Unmarshal([]byte(f.rows), &listings); err != nil {
			return nil, nil, err
		}
		records := make([]json.RawMessage, 0, len(listings))
		for _, l := range listings {
			records = append(records, l.Vulnerability)
		}
		recordsJSON, err := json.Marshal(records)
		return recordsJSON, []byte(f.rows), err
	}
	files := fixtures
	if f.files != nil {
		files = f.files
	}
	name, ok := files[strings.Join(ids, " ")]
	if !ok {
		return nil, nil, errors.New("no fixture for the search")
	}
	records, err := os.ReadFile(filepath.Join("testdata", name+"-records.json"))
	if err != nil {
		return nil, nil, err
	}
	packages, err := os.ReadFile(filepath.Join("testdata", name+"-packages.json"))
	return records, packages, err
}

func (*fakeGrype) Match(context.Context, string) ([]grype.Match, error) {
	return nil, errors.New("no match here")
}
func (*fakeGrype) Update(context.Context) error { return errors.New("no update here") }
func (*fakeGrype) Status(context.Context) (grype.Database, error) {
	return grype.Database{}, errors.New("no status here")
}

// invoke runs describe with the parameters.
func invoke(t *testing.T, g grype.Grype, parameters string) ([]evidenceEvent, *collector.Failure) {
	t.Helper()
	events, failure, err := describe.Invoke(t.Context(), g, collector.InvokeRequest{
		Operation: describe.Name, Subject: "vulnerability/any", Parameters: json.RawMessage(parameters),
		Role: collector.RoleHub,
	}, evidence.WithSource(source))
	require.NoError(t, err)
	out := make([]evidenceEvent, 0, len(events))
	for _, e := range events {
		require.NoError(t, evidence.Validate(e))
		var d evidence.Description
		decoder := json.NewDecoder(strings.NewReader(string(e.Data())))
		decoder.DisallowUnknownFields()
		require.NoError(t, decoder.Decode(&d))
		out = append(out, evidenceEvent{eventType: e.Type(), subject: e.Subject(), source: e.Source(), data: d})
	}
	return out, failure
}

type evidenceEvent struct {
	eventType, subject, source string
	data                       evidence.Description
}

// described runs describe, and returns the one description that it answers with.
func described(t *testing.T, g grype.Grype, parameters string) evidence.Description {
	t.Helper()
	events, failure := invoke(t, g, parameters)
	require.Nil(t, failure)
	require.Len(t, events, 1)
	return events[0].data
}

// entry returns the answer of a provider for the package that it names in the namespace.
func entry(t *testing.T, d evidence.Description, provider, namespace, pkg string) evidence.ProviderFix {
	t.Helper()
	i := slices.IndexFunc(d.Providers, func(p evidence.ProviderFix) bool {
		return p.Provider == provider && p.Namespace == namespace && p.Package == pkg
	})
	require.NotEqual(t, -1, i, "no answer of %s for %s in %s", provider, pkg, namespace)
	return d.Providers[i]
}

// packagesOf returns the names of the packages that the listed entries are for.
func packagesOf(d evidence.Description) []string {
	names := make([]string, 0, len(d.Providers))
	for _, p := range d.Providers {
		names = append(names, p.Package)
	}
	return names
}

// counted returns how many entries of the provider the answer leaves out.
func counted(d evidence.Description, provider string) int32 {
	for _, c := range d.OtherProviders {
		if c.Provider == provider {
			return c.Entries
		}
	}
	return 0
}

// answer returns what an entry says of the package of the name and version.
func answer(t *testing.T, p evidence.ProviderFix, name, version string) string {
	t.Helper()
	i := slices.IndexFunc(p.Packages, func(f evidence.PackageFix) bool { return f.Name == name && f.Version == version })
	require.NotEqual(t, -1, i, "%s says nothing of %s %s", p.Namespace, name, version)
	return p.Packages[i].FixedForInstalled
}

// TestDescribeNamesEveryProvider: the description, the references and the scores come from the records, and every
// provider is named with what it says of a fix.
func TestDescribeNamesEveryProvider(t *testing.T) {
	events, failure := invoke(t, &fakeGrype{}, `{"vulnerabilityID": "`+debianCVE+`"}`)
	require.Nil(t, failure)
	require.Len(t, events, 1)
	e := events[0]
	require.Equal(t, evidence.TypeDescription, e.eventType)
	// The answer is about the vulnerability, whatever subject describe ran for.
	require.Equal(t, "vulnerability/"+debianCVE, e.subject)
	require.Equal(t, source, e.source)

	d := e.data
	require.Equal(t, debianCVE, d.VulnerabilityID)
	require.True(t, strings.HasPrefix(d.Description, "A buffer overflow vulnerability in the Brotli decoder"),
		"NVD's description of the CVE: %q", d.Description)
	require.Contains(t, d.References, "https://nvd.nist.gov/vuln/detail/"+debianCVE)
	require.Contains(t, d.References, "https://security-tracker.debian.org/tracker/"+debianCVE)
	require.Contains(t, d.References, "https://ubuntu.com/security/"+debianCVE)
	require.Equal(t, len(d.References), len(slices.Compact(slices.Sorted(slices.Values(d.References)))),
		"each reference once")
	require.True(t, d.KnownExploited)
	require.Equal(t, int32(826), *d.EPSSPermille)
	require.Equal(t, "2026-11-05", d.EPSSDate)
	require.Equal(t, []evidence.CVSS{
		{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/" +
			"MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X"},
	}, d.CVSS)
	require.Empty(t, d.Aliases)

	// Asked about no package, describe lists no entry, and counts them all.
	require.Empty(t, d.Providers)
	require.Equal(t, []evidence.ProviderCount{{Provider: "debian", Entries: 11}, {Provider: "nvd", Entries: 7},
		{Provider: "ubuntu", Entries: 19}}, d.OtherProviders)
}

// TestTheInstalledVersionIsComparedByTheDistributionsRules: a Debian package is fixed when its source package, which
// Debian tracks, is at the release that Debian fixed it in or later, compared as dpkg orders versions. Only the
// provider of the package's own release can say so.
func TestTheInstalledVersionIsComparedByTheDistributionsRules(t *testing.T) {
	d := described(t, &fakeGrype{}, `{"vulnerabilityID": "`+debianCVE+`", "packages": [
		{"name": "libbrotli1", "version": "1.0.9-2+deb12u1", "type": "deb",
		 "purl": "pkg:deb/debian/libbrotli1@1.0.9-2%2Bdeb12u1?arch=amd64&distro=debian-12&upstream=brotli"},
		{"name": "libbrotli1", "version": "1.0.9-2", "type": "deb",
		 "purl": "pkg:deb/debian/libbrotli1@1.0.9-2?arch=amd64&distro=debian-12&upstream=brotli"},
		{"name": "libbrotli1", "version": "1.0.9-2+b6", "type": "deb",
		 "purl": "pkg:deb/debian/libbrotli1@1.0.9-2%2Bb6?arch=amd64&distro=debian-12&upstream=brotli%401.0.9-2"},
		{"name": "libbrotli1", "version": "1.0.9-2+deb12u1", "type": "deb", "distro": "debian-12"},
		{"name": "brotli", "version": "1.0.9-2+deb12u1", "type": "binary", "distro": "debian-12"}
	]}`)
	fixed := entry(t, d, "debian", debian12, brotli)
	// The release that Debian fixed it in.
	require.Equal(t, evidence.FixedForInstalledYes, answer(t, fixed, libbrotli1, debianFixed))
	// The release before it.
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, fixed, libbrotli1, "1.0.9-2"))
	// A rebuild of the release before, which the purl names as the source package's release: Debian's fix is for the
	// source package, so its version counts, and not the rebuild's.
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, fixed, libbrotli1, "1.0.9-2+b6"))
	// Debian names the source package, brotli, which a package without a purl doesn't name: there is nothing to
	// compare, whatever the versions say. Nor does Debian speak for a library of that name that Syft found in a binary
	// of the image, which wasn't built by Debian.
	require.Equal(t, evidence.FixedForInstalledUnknown, answer(t, fixed, brotli, "1.0.9-2+deb12u1"))
	require.Len(t, d.Packages, 5)
	require.Equal(t, evidence.DescribedPackage{Name: libbrotli1, Version: debianFixed, Type: typeDeb, Distro: "debian-12"},
		d.Packages[3])

	unknownFor := func(p evidence.ProviderFix) {
		t.Helper()
		require.Len(t, p.Packages, 5, "%s %s answers for each package", p.Provider, p.Namespace)
		for _, f := range p.Packages {
			require.Equal(t, evidence.FixedForInstalledUnknown, f.FixedForInstalled, "%s %s", p.Namespace, p.Package)
		}
	}
	// Another release of Debian, another distribution and NVD's CPEs don't say what Debian 12 has fixed.
	unknownFor(entry(t, d, "debian", debian13, brotli))
	unknownFor(entry(t, d, "ubuntu", "ubuntu:distro:ubuntu:16.04", brotli))
	unknownFor(entry(t, d, "nvd", nvdCPE, "cpe:2.3:a:google:brotli:*:*:*:*:*:*:*:*"))
	// Debian 12's entry for another package is about that package, and no asked package names it.
	require.NotContains(t, packagesOf(d), "nodejs")

	// The entries that answer for a package of the case come first, so that a reader that is cut short sees them.
	require.Equal(t, debian12, d.Providers[0].Namespace)
	require.Equal(t, brotli, d.Providers[0].Package)
}

// TestAnAliasFindsTheVulnerability: a GitHub advisory finds its CVE, and what each provider says of the CVE. The
// advisory's Go module is compared as Go orders its versions.
func TestAnAliasFindsTheVulnerability(t *testing.T) {
	g := &fakeGrype{}
	d := described(t, g, `{"vulnerabilityID": "`+ghsa+`", "packages": [
		{"name": "`+gin+`", "version": "v1.9.1", "type": "go-module", "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1"},
		{"name": "`+gin+`", "version": "v1.9.0", "type": "go-module"},
		{"name": "`+gin+`", "version": "v1.3.0", "type": "go-module"}
	]}`)

	require.Equal(t, [][]string{{ghsa}, {ghsa, ghsaCVE}}, g.searches, "the second search adds the CVE")
	require.Equal(t, ghsa, d.VulnerabilityID)
	require.Equal(t, []string{ghsaCVE}, d.Aliases)
	require.Equal(t, "Gin Web Framework does not properly sanitize filename parameter of Context.FileAttachment function",
		d.Description, "the advisory's own description comes first")
	require.Contains(t, d.References, "https://nvd.nist.gov/vuln/detail/"+ghsaCVE)
	require.False(t, d.KnownExploited)
	require.Equal(t, int32(4), *d.EPSSPermille, "the CVE's score, which the advisory names")

	module := entry(t, d, "github", githubGo, gin)
	require.Equal(t, ghsa, module.VulnerabilityID, "GitHub lists it under the advisory")
	require.Equal(t, []string{"1.9.1"}, module.FixedVersions)
	require.Equal(t, evidence.FixedForInstalledYes, answer(t, module, gin, "v1.9.1"))
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, module, gin, "v1.9.0"))
	// Older than the vulnerable range, and older than the fix: GitHub doesn't say it is fixed.
	require.Equal(t, evidence.FixedForInstalledUnknown, answer(t, module, gin, "v1.3.0"))
	// The CVE's own providers say Unknown for a Go module, so they are counted and not listed.
	require.Positive(t, counted(d, "debian"))
	require.Positive(t, counted(d, "nvd"))
	require.Equal(t, []string{gin}, packagesOf(d))
}

// TestGosStandardLibraryIsAskedAsSyftWritesIt: Syft writes the standard library as stdlib, with the version go1.27.1 and
// the purl version 1.27.1. It is answered under the version that was asked, which Grype compares without the "go".
func TestGosStandardLibraryIsAskedAsSyftWritesIt(t *testing.T) {
	d := described(t, &fakeGrype{}, `{"vulnerabilityID": "`+goVuln+`", "packages": [
		{"name": "stdlib", "version": "go1.27.1", "type": "go-module", "purl": "pkg:golang/stdlib@1.27.1"},
		{"name": "stdlib", "version": "go1.26.5", "type": "go-module", "purl": "pkg:golang/stdlib@1.26.5"},
		{"name": "stdlib", "version": "go1.27.2", "type": "go-module", "purl": "pkg:golang/stdlib@1.27.2"},
		{"name": "golang.org/x/net", "version": "v0.57.0", "type": "go-module", "purl": "pkg:golang/golang.org/x/net@v0.57.0"}
	]}`)
	stdlib := entry(t, d, "govulndb", govuln, "stdlib")
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, stdlib, "stdlib", "go1.27.1"), ">=1.27.0-0,<1.27.2")
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, stdlib, "stdlib", "go1.26.5"), "<1.26.9")
	require.Equal(t, evidence.FixedForInstalledYes, answer(t, stdlib, "stdlib", "go1.27.2"))
	module := entry(t, d, "govulndb", govuln, "golang.org/x/net")
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, module, "golang.org/x/net", "v0.57.0"), "<0.60.0")
}

// TestAnUnknownIDIsAFailureNotAnEmptyAnswer: an empty answer would read as a vulnerability that no provider tracks.
func TestAnUnknownIDIsAFailureNotAnEmptyAnswer(t *testing.T) {
	events, failure := invoke(t, &fakeGrype{}, `{"vulnerabilityID": "`+unknownID+`"}`)
	require.Empty(t, events)
	require.NotNil(t, failure)
	require.Equal(t, "NotFound", failure.Reason)
	require.NotContains(t, failure.Message, unknownID)
}

// TestDescribeNeedsNoNetwork runs describe through the wrapper of the CLI, on a script that stands for Grype: it
// answers a search from testdata, and fails as a Grype that needs the network would, for any other command or when
// Grype may update its database or look for a newer Grype. The process's own environment allows both, and has a
// proxy that refuses every connection: the wrapper's settings win. The searches of the testdata ran with Docker's
// network off (parse.go).
func TestDescribeNeedsNoNetwork(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("GRYPE_DB_AUTO_UPDATE", "true")
	t.Setenv("GRYPE_CHECK_FOR_APP_UPDATE", "true")
	testdata, err := filepath.Abs("testdata")
	require.NoError(t, err)
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$GRYPE_DB_AUTO_UPDATE" != false ] || [ "$GRYPE_CHECK_FOR_APP_UPDATE" != false ]; then
  echo "this Grype would reach the network" >&2; exit 1
fi
case "$1 $2 $3" in
  "db search vuln") cat '` + testdata + `/debian-records.json' ;;
  "db search -o") cat '` + testdata + `/debian-packages.json' ;;
  *) echo "this command would reach the network" >&2; exit 1 ;;
esac
`
	binary := filepath.Join(dir, "grype")
	require.NoError(t, os.WriteFile(binary, []byte(script), 0o755))

	d := described(t, grype.NewGrype(binary, t.TempDir()), `{"vulnerabilityID": "`+debianCVE+`", "packages": [
		{"name": "libbrotli1", "version": "1.0.9-2+deb12u1", "type": "deb",
		 "purl": "pkg:deb/debian/libbrotli1@1.0.9-2%2Bdeb12u1?arch=amd64&distro=debian-12&upstream=brotli"}]}`)

	require.Equal(t, []string{debianFixed}, entry(t, d, "debian", debian12, brotli).FixedVersions)
}

// TestInputThatGrypeCouldMisreadIsRefused: the parameters come from a model. An ID that Grype could take for a flag,
// a purl of another package than the one named, and a release that the purl contradicts are refused, and Grype
// doesn't run.
func TestInputThatGrypeCouldMisreadIsRefused(t *testing.T) {
	for name, parameters := range map[string]string{
		"an ID that starts like a flag": `{"vulnerabilityID": "--help"}`,
		"an ID with a space":            `{"vulnerabilityID": "CVE-2026-0001 CVE-2026-0002"}`,
		"a purl of another package": `{"vulnerabilityID": "` + debianCVE + `", "packages": [{"name": "libbrotli1",
			"version": "1.0.9-2", "type": "deb", "purl": "pkg:deb/debian/libbrotli-dev@1.0.9-2?distro=debian-12"}]}`,
		"a purl of another version": `{"vulnerabilityID": "` + debianCVE + `", "packages": [{"name": "libbrotli1",
			"version": "1.0.9-2+deb12u1", "type": "deb", "purl": "pkg:deb/debian/libbrotli1@1.0.9-2?distro=debian-12"}]}`,
		"a release that the purl contradicts": `{"vulnerabilityID": "` + debianCVE + `", "packages": [{"name": "libbrotli1",
			"version": "1.0.9-2", "type": "deb", "distro": "ubuntu-22.04",
			"purl": "pkg:deb/debian/libbrotli1@1.0.9-2?distro=debian-12&upstream=brotli"}]}`,
		"a standard library of another purl version": `{"vulnerabilityID": "` + goVuln + `", "packages": [
			{"name": "stdlib", "version": "go1.27.1", "type": "go-module", "purl": "pkg:golang/stdlib@1.27.2"}]}`,
		"a module other than the standard library with a go prefix": `{"vulnerabilityID": "` + goVuln + `", "packages": [
			{"name": "golang.org/x/net", "version": "go0.57.0", "type": "go-module", "purl": "pkg:golang/golang.org/x/net@0.57.0"}]}`,
		"an unknown field": `{"vulnerabilityID": "` + debianCVE + `", "fixed": true}`,
		"seventeen packages": `{"vulnerabilityID": "` + debianCVE + `", "packages": [` +
			strings.Repeat(`{"name": "a", "type": "deb"},`, 16) + `{"name": "a", "type": "deb"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			g := &fakeGrype{}
			events, failure := invoke(t, g, parameters)
			require.Empty(t, events)
			require.NotNil(t, failure)
			require.Equal(t, "InvalidInput", failure.Reason)
			require.Empty(t, g.searches)
		})
	}
}

// TestTheMostCautiousRowOfAProviderWins: Red Hat lists the fix of an extended update stream under the namespace of
// its release, beside the fix of the release. A package that has the first fix but not the second isn't fixed: every
// row of the provider that names the package must leave it outside its range. The testdata holds the two rows of Red
// Hat 9 for Brotli.
func TestTheMostCautiousRowOfAProviderWins(t *testing.T) {
	d := described(t, &fakeGrype{files: map[string]string{debianCVE: "rhel"}}, `{"vulnerabilityID": "`+debianCVE+`", "packages": [
		{"name": "brotli", "version": "1.0.9-7.el9_6.3", "type": "rpm", "purl": "pkg:rpm/redhat/brotli@1.0.9-7.el9_6.3?distro=rhel-9.6"},
		{"name": "brotli", "version": "1.0.9-10.el9_8.1", "type": "rpm", "purl": "pkg:rpm/redhat/brotli@1.0.9-10.el9_8.1?distro=rhel-9.6"}
	]}`)
	rhel := entry(t, d, "rhel", "redhat:distro:redhat:9", brotli)
	require.Equal(t, []string{"0:1.0.9-7.el9_6.3", "0:1.0.9-10.el9_8.1"}, rhel.FixedVersions)
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, rhel, brotli, "1.0.9-7.el9_6.3"))
	require.Equal(t, evidence.FixedForInstalledYes, answer(t, rhel, brotli, "1.0.9-10.el9_8.1"))
}

// synthetic is the output of a search for made-up rows of a provider: each row is a namespace, a package and its
// ranges, as Grype prints them.
func synthetic(provider string, rows ...string) string {
	return "[" + listing("CVE-2026-0003", provider, rows...) + "]"
}

// listing is a provider's record of the vulnerability id that lists the rows.
func listing(id, provider string, rows ...string) string {
	return `{"vulnerability": {"id": "` + id + `", "provider": "` + provider + `"}, "packages": [` +
		strings.Join(rows, ",") + `]}`
}

// syntheticRow is a row of a namespace for the package foo, with its ranges.
func syntheticRow(namespace, ranges string) string {
	return `{"namespace": "` + namespace + `", "package": {"name": "foo"}, "detail": {"ranges": [` + ranges + `]}}`
}

// TestADebianVersionWithoutAnEpochHasEpochZero: dpkg reads a version without an epoch as epoch 0, and so does
// Grype's dpkg matcher by default. A fix of epoch 1 is above every version of epoch 0, so 2.4-1 isn't fixed by
// 1:2.3-1, whatever the rest of the versions say, and a caller that drops an epoch gets no Yes for it.
func TestADebianVersionWithoutAnEpochHasEpochZero(t *testing.T) {
	g := &fakeGrype{rows: synthetic("debian", syntheticRow(debian12,
		`{"version": {"type": "dpkg", "constraint": "< 1:2.3-1"}, "fix": {"version": "1:2.3-1", "state": "fixed"}}`))}
	d := described(t, g, `{"vulnerabilityID": "CVE-2026-0003", "packages": [
		{"name": "foo", "version": "2.4-1", "type": "deb", "purl": "pkg:deb/debian/foo@2.4-1?distro=debian-12"},
		{"name": "foo", "version": "1:2.3-1", "type": "deb", "purl": "pkg:deb/debian/foo@1:2.3-1?distro=debian-12"}
	]}`)
	foo := entry(t, d, "debian", debian12, "foo")
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, foo, "foo", "2.4-1"))
	require.Equal(t, evidence.FixedForInstalledYes, answer(t, foo, "foo", "1:2.3-1"))
}

// TestEveryNamespaceOfAProviderThatSpeaksForTheReleaseIsJudgedTogether: SUSE lists a vulnerability for the general
// release of SLES 15 and for its service pack 15.5, and both namespaces speak for a package of 15.5. A package that
// the general release's row calls fixed, but the service pack's row holds, isn't fixed: no entry of the provider says
// Yes for it.
func TestEveryNamespaceOfAProviderThatSpeaksForTheReleaseIsJudgedTogether(t *testing.T) {
	const general, servicePack = "sles:distro:sles:15", "sles:distro:sles:15.5"
	g := &fakeGrype{rows: synthetic("sles",
		syntheticRow(general,
			`{"version": {"type": "rpm", "constraint": "< 0:1.0-1"}, "fix": {"version": "0:1.0-1", "state": "fixed"}}`),
		syntheticRow(servicePack,
			`{"version": {"type": "rpm", "constraint": "< 0:1.2-150500.1"}, "fix": {"version": "0:1.2-150500.1", "state": "fixed"}}`))}
	d := described(t, g, `{"vulnerabilityID": "CVE-2026-0003", "packages": [
		{"name": "foo", "version": "1.1-150500.1", "type": "rpm", "purl": "pkg:rpm/suse/foo@1.1-150500.1?distro=sles-15.5"},
		{"name": "foo", "version": "1.2-150500.1", "type": "rpm", "purl": "pkg:rpm/suse/foo@1.2-150500.1?distro=sles-15.5"}
	]}`)
	for _, ns := range []string{general, servicePack} {
		p := entry(t, d, "sles", ns, "foo")
		require.Equal(t, evidence.FixedForInstalledNo, answer(t, p, "foo", "1.1-150500.1"), ns)
		require.Equal(t, evidence.FixedForInstalledYes, answer(t, p, "foo", "1.2-150500.1"), ns)
	}
}

// TestARangeWithoutAConstraintThatIsntFixedHoldsEveryVersion: a row that says "won't fix" for every version beside a
// range that a release fixed doesn't call that release fixed. Grype leaves the first range out when it joins the
// constraints; describe takes it as holding every version.
func TestARangeWithoutAConstraintThatIsntFixedHoldsEveryVersion(t *testing.T) {
	g := &fakeGrype{rows: synthetic("debian", syntheticRow(debian12,
		`{"version": {"type": "dpkg"}, "fix": {"state": "wont-fix"}},
		 {"version": {"type": "dpkg", "constraint": "< 2.3-1"}, "fix": {"version": "2.3-1", "state": "fixed"}}`))}
	d := described(t, g, `{"vulnerabilityID": "CVE-2026-0003", "packages": [
		{"name": "foo", "version": "2.4-1", "type": "deb", "purl": "pkg:deb/debian/foo@2.4-1?distro=debian-12"}
	]}`)
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, entry(t, d, "debian", debian12, "foo"), "foo", "2.4-1"))
}

// TestARangeWithoutAConstraintThatNamesAFixLeavesTheRowUnknown: Grype leaves a range without a constraint out when it
// joins the constraints of a row, though one that names a fix holds the versions below its fix. 1.5 is outside "< 1.0"
// and above its fix, but below 2.3-1, so the row says nothing sure of it.
func TestARangeWithoutAConstraintThatNamesAFixLeavesTheRowUnknown(t *testing.T) {
	g := &fakeGrype{rows: synthetic("debian", syntheticRow(debian12,
		`{"version": {"type": "dpkg"}, "fix": {"version": "2.3-1", "state": "fixed"}},
		 {"version": {"type": "dpkg", "constraint": "< 1.0"}, "fix": {"version": "1.0", "state": "fixed"}}`))}
	d := described(t, g, `{"vulnerabilityID": "CVE-2026-0003", "packages": [
		{"name": "foo", "version": "1.5", "type": "deb", "purl": "pkg:deb/debian/foo@1.5?distro=debian-12"}
	]}`)
	require.Equal(t, evidence.FixedForInstalledUnknown, answer(t, entry(t, d, "debian", debian12, "foo"), "foo", "1.5"))
}

// TestARowWithoutAnyConstraintThatNamesAFixAnswersNo: with no constraint in the row at all, Grype matches every
// version, so a No stays a No, which blocks a Yes of another provider; only a row that mixes constrained ranges with
// an unconstrained one that names a fix is unclear.
func TestARowWithoutAnyConstraintThatNamesAFixAnswersNo(t *testing.T) {
	g := &fakeGrype{rows: synthetic("debian", syntheticRow(debian12,
		`{"version": {"type": "dpkg"}, "fix": {"version": "2.3-1", "state": "fixed"}}`))}
	d := described(t, g, `{"vulnerabilityID": "CVE-2026-0003", "packages": [
		{"name": "foo", "version": "1.5", "type": "deb", "purl": "pkg:deb/debian/foo@1.5?distro=debian-12"}
	]}`)
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, entry(t, d, "debian", debian12, "foo"), "foo", "1.5"))
}

// TestEachAnswerRestsOnTheRecordsOfOneVulnerability: describe finds the records of the ID and of the IDs that they
// name, and a provider's answer rests on its records of one of them, which it names. A fix of another vulnerability
// says nothing of this one, and a provider that lists the package only under another vulnerability answers under that
// one.
func TestEachAnswerRestsOnTheRecordsOfOneVulnerability(t *testing.T) {
	const asked, other = "CVE-2026-0003", "CVE-2026-0004"
	fixedIn := func(v string) string {
		return syntheticRow(debian12,
			`{"version": {"type": "dpkg", "constraint": "< `+v+`"}, "fix": {"version": "`+v+`", "state": "fixed"}}`)
	}
	g := &fakeGrype{rows: "[" + listing(asked, "debian", fixedIn("2.5-1")) + "," +
		listing(other, "debian", fixedIn("2.3-1")) + "," + listing(other, "secdb", fixedIn("2.3-1")) + "]"}
	d := described(t, g, `{"vulnerabilityID": "`+asked+`", "packages": [
		{"name": "foo", "version": "2.4-1", "type": "deb", "purl": "pkg:deb/debian/foo@2.4-1?distro=debian-12"}
	]}`)

	answers := map[string]string{}
	for _, p := range d.Providers {
		answers[p.Provider+" "+p.VulnerabilityID] = answer(t, p, "foo", "2.4-1")
	}
	require.Equal(t, map[string]string{
		"debian " + asked: evidence.FixedForInstalledNo,
		"debian " + other: evidence.FixedForInstalledYes,
		"secdb " + other:  evidence.FixedForInstalledYes,
	}, answers)
}

// brotliPackage is the Debian 12 package that the Debian entry for Brotli answers for.
const brotliPackage = `{"name": "libbrotli1", "version": "1.0.9-2+deb12u1", "type": "deb",
	"purl": "pkg:deb/debian/libbrotli1@1.0.9-2%2Bdeb12u1?arch=amd64&distro=debian-12&upstream=brotli"}`

// TestOnlyTheEntriesThatAnswerAreListed: of the many releases and providers that list the vulnerability, the answer
// holds the entry of the release that the package is of, and counts the rest by provider.
func TestOnlyTheEntriesThatAnswerAreListed(t *testing.T) {
	all := described(t, &fakeGrype{}, `{"vulnerabilityID": "`+debianCVE+`"}`)
	total := 0
	for _, c := range all.OtherProviders {
		total += int(c.Entries)
	}

	d := described(t, &fakeGrype{}, `{"vulnerabilityID": "`+debianCVE+`", "packages": [`+brotliPackage+`]}`)

	require.Len(t, d.Providers, 1)
	require.Equal(t, debian12, d.Providers[0].Namespace)
	require.Equal(t, brotli, d.Providers[0].Package)
	require.Equal(t, evidence.FixedForInstalledYes, d.Providers[0].Packages[0].FixedForInstalled)
	require.Equal(t, int32(10), counted(d, "debian"), "the other releases and packages of Debian")
	listed := len(d.Providers)
	for _, c := range d.OtherProviders {
		listed += int(c.Entries)
	}
	require.Equal(t, total, listed, "every entry is listed or counted")
	require.True(t, slices.IsSortedFunc(d.OtherProviders, func(a, b evidence.ProviderCount) int {
		return strings.Compare(a.Provider, b.Provider)
	}))
}

// TestAnUnansweredPackageListsTheEntriesThatNameIt: a binary that Syft recognizes has a generic purl, which no
// provider speaks for. NVD's CPE for it is listed, with Unknown, so that the agent sees what names the package.
func TestAnUnansweredPackageListsTheEntriesThatNameIt(t *testing.T) {
	d := described(t, &fakeGrype{}, `{"vulnerabilityID": "`+busyboxCVE+`", "packages": [
		{"name": "busybox", "version": "1.36.1", "type": "binary", "purl": "pkg:generic/busybox@1.36.1"}]}`)

	require.NotEmpty(t, d.Providers)
	require.LessOrEqual(t, len(d.Providers), 8)
	p := entry(t, d, "nvd", nvdCPE, "cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*")
	require.Equal(t, evidence.FixedForInstalledUnknown, answer(t, p, "busybox", "1.36.1"))
	require.Equal(t, evidence.DescribedPackage{Name: "busybox", Version: "1.36.1", Type: "binary",
		PURL: "pkg:generic/busybox@1.36.1"}, d.Packages[0])
	require.Equal(t, int32(1), counted(d, "nvd"), "the CPE of Debian 11 names another product")
}

// TestAGenericPurlMustMatchTheAskedPackage: a generic purl names no type, but its name and version are the package's.
func TestAGenericPurlMustMatchTheAskedPackage(t *testing.T) {
	for name, pkg := range map[string]string{
		"a version":                `{"name": "busybox", "version": "1.36.1", "type": "binary", "purl": "pkg:generic/busybox@1.36.0"}`,
		"a name":                   `{"name": "busybox", "version": "1.36.1", "type": "binary", "purl": "pkg:generic/toybox@1.36.1"}`,
		"no version":               `{"name": "busybox", "type": "binary", "purl": "pkg:generic/busybox@1.36.1"}`,
		"a purl without a version": `{"name": "busybox", "version": "1.36.1", "type": "binary", "purl": "pkg:generic/busybox"}`,
	} {
		t.Run(name, func(t *testing.T) {
			events, failure := invoke(t, &fakeGrype{}, `{"vulnerabilityID": "`+busyboxCVE+`", "packages": [`+pkg+`]}`)
			require.Empty(t, events)
			require.NotNil(t, failure)
			require.Equal(t, "InvalidInput", failure.Reason)
		})
	}
}

// TestAGenericPurlSpeaksForNoDistribution: a package of a distribution's type that a generic purl names isn't that
// distribution's package, so no entry of the distribution says Yes for it.
func TestAGenericPurlSpeaksForNoDistribution(t *testing.T) {
	d := described(t, &fakeGrype{}, `{"vulnerabilityID": "`+debianCVE+`", "packages": [
		{"name": "brotli", "version": "1.0.9-2+deb12u1", "type": "deb", "distro": "debian-12",
		 "purl": "pkg:generic/brotli@1.0.9-2%2Bdeb12u1"}]}`)
	for _, p := range d.Providers {
		require.Equal(t, evidence.FixedForInstalledUnknown, p.Packages[0].FixedForInstalled, "%s", p.Namespace)
	}
}

// TestTheAliasesAreSearchedInTheSameCall: the alias that the caller gives is searched with the ID, so the first search
// finds the ecosystem's own record, which the records of the ID don't name.
func TestTheAliasesAreSearchedInTheSameCall(t *testing.T) {
	g := &fakeGrype{}
	d := described(t, g, `{"vulnerabilityID": "`+goCVE+`", "aliases": ["`+goVuln+`", "`+goCVE+`"], "packages": [
		{"name": "stdlib", "version": "go1.27.1", "type": "go-module", "purl": "pkg:golang/stdlib@1.27.1"}]}`)

	require.Equal(t, [][]string{{goCVE, goVuln}}, g.searches, "one search, with each ID once")
	require.Equal(t, evidence.FixedForInstalledNo, answer(t, entry(t, d, "govulndb", govuln, "stdlib"), "stdlib", "go1.27.1"))
}

// TestAliasesAreBounded: at most 8 aliases, each an ID that Grype can't take for a flag.
func TestAliasesAreBounded(t *testing.T) {
	nine := `["A-1", "A-2", "A-3", "A-4", "A-5", "A-6", "A-7", "A-8", "A-9"]`
	for name, aliases := range map[string]string{
		"nine aliases":          nine,
		"an alias like a flag":  `["--help"]`,
		"an alias with a space": `["CVE-2026-0001 CVE-2026-0002"]`,
	} {
		t.Run(name, func(t *testing.T) {
			g := &fakeGrype{}
			events, failure := invoke(t, g, `{"vulnerabilityID": "`+goVuln+`", "aliases": `+aliases+`}`)
			require.Empty(t, events)
			require.NotNil(t, failure)
			require.Equal(t, "InvalidInput", failure.Reason)
			require.Empty(t, g.searches)
		})
	}
}

// TestTheAnswerStaysSmall: the entries of providers that answer for no asked package are counted, however many
// there are, so a vulnerability that thousands of rows list gives a short answer.
func TestTheAnswerStaysSmall(t *testing.T) {
	listings := make([]string, 0, 20)
	for p := range 20 {
		rows := make([]string, 0, 500)
		for i := range 500 {
			rows = append(rows, `{"namespace": "debian:distro:debian:12", "package": {"name": "foo-`+strconv.Itoa(i)+
				`"}, "detail": {"ranges": []}}`)
		}
		listings = append(listings, listing("CVE-2026-0003", "provider-"+strconv.Itoa(p), rows...))
	}
	d := described(t, &fakeGrype{rows: "[" + strings.Join(listings, ",") + "]"},
		`{"vulnerabilityID": "CVE-2026-0003", "packages": [{"name": "bar", "version": "1.0", "type": "deb",
		 "distro": "debian-12"}]}`)

	require.Empty(t, d.Providers)
	require.Len(t, d.OtherProviders, 20)
	require.Equal(t, int32(500), d.OtherProviders[0].Entries)
	raw, err := json.Marshal(d)
	require.NoError(t, err)
	require.Less(t, len(raw), 4096)
}

// TestTheDescriptionIsTheAnsweringProvidersFirst: asked by the CVE, with a Go module that GitHub answers for, the
// description is GitHub's advisory, and not NVD's, which comes first where no entry answers.
func TestTheDescriptionIsTheAnsweringProvidersFirst(t *testing.T) {
	files := map[string]string{ghsaCVE: ghsaAlias, ghsaCVE + " " + ghsa: ghsaAlias}
	gin := `{"name": "` + gin + `", "version": "v1.9.1", "type": "go-module", "purl": "pkg:golang/` + gin + `@v1.9.1"}`

	none := described(t, &fakeGrype{files: files}, `{"vulnerabilityID": "`+ghsaCVE+`"}`)
	asked := described(t, &fakeGrype{files: files}, `{"vulnerabilityID": "`+ghsaCVE+`", "packages": [`+gin+`]}`)

	const github = "Gin Web Framework does not properly sanitize filename parameter of Context.FileAttachment function"
	require.NotEqual(t, github, none.Description, "NVD's description comes first where no entry answers")
	require.Equal(t, github, asked.Description)
	require.Contains(t, asked.References, "https://nvd.nist.gov/vuln/detail/"+ghsaCVE, "the asked ID's own records")
}

// TestTheNamedEntriesOfAnUnansweredPackageAreCapped: no entry answers for a binary, and more than 8 entries name
// Brotli, so 8 are listed and the rest counted.
func TestTheNamedEntriesOfAnUnansweredPackageAreCapped(t *testing.T) {
	all := described(t, &fakeGrype{}, `{"vulnerabilityID": "`+debianCVE+`"}`)
	total := 0
	for _, c := range all.OtherProviders {
		total += int(c.Entries)
	}

	d := described(t, &fakeGrype{}, `{"vulnerabilityID": "`+debianCVE+`", "packages": [
		{"name": "brotli", "version": "1.0.9", "type": "binary", "distro": "debian-12"}]}`)

	require.Len(t, d.Providers, 8)
	for _, p := range d.Providers {
		require.Equal(t, evidence.FixedForInstalledUnknown, p.Packages[0].FixedForInstalled)
	}
	listed := len(d.Providers)
	for _, c := range d.OtherProviders {
		listed += int(c.Entries)
	}
	require.Equal(t, total, listed, "every entry is listed or counted")
}

// TestTheFixStatesOfTheListedEntriesAreKept: an entry that is listed carries its provider's fix state and fixed
// versions, whether the provider fixed the package, has not, or won't.
func TestTheFixStatesOfTheListedEntriesAreKept(t *testing.T) {
	d := described(t, &fakeGrype{}, `{"vulnerabilityID": "`+debianCVE+`", "packages": [`+brotliPackage+`,
		{"name": "nodejs", "version": "18.0.0-1", "type": "deb", "distro": "debian-12"},
		{"name": "libbrotli1", "version": "1.0.9-2", "type": "deb",
		 "purl": "pkg:deb/ubuntu/libbrotli1@1.0.9-2?distro=ubuntu-20.04&upstream=brotli"}]}`)

	fixed := entry(t, d, "debian", debian12, brotli)
	require.Equal(t, "fixed", fixed.FixState)
	require.Equal(t, []string{debianFixed}, fixed.FixedVersions)
	notFixed := entry(t, d, "debian", debian12, "nodejs")
	require.Equal(t, "not-fixed", notFixed.FixState)
	require.Empty(t, notFixed.FixedVersions)
	require.Equal(t, "wont-fix", entry(t, d, "ubuntu", "ubuntu:distro:ubuntu:20.04", brotli).FixState)
}
