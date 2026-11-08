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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/evidence"
)

// These tests hold the document that the vulnerabilities collector hands Grype for an SBOM to Syft's JSON, which the
// SBOM was made of, through Grype's own reading of both: the package provider of Grype v0.121.0, the version of the
// CLI that the collector runs. Grype matches the packages that it reads, with their source packages and their
// distribution, so a document that gives it the same packages gets the same matches, and the tests need no
// vulnerability database to tell.
//
// Phase 2b handed Grype Syft's JSON. The sbom type keeps of each package its ID, name, version, type, purl and CPEs
// (decision 0044), and Grype reads more of Syft's JSON than that:
//   - an OS package's source package, from its metadata: the document carries it, from the purl's qualifier upstream;
//   - the distribution, from Syft's: the document carries the SBOM's;
//   - more metadata, which the document doesn't carry, and whose absence can only make Grype more lenient, as lenient
//     says.

// scannerTestdata holds the roots of the scanner's fixtures: Syft's JSON of each in syft-<root>.json, real output of
// Syft v1.55.0, and the sbom evidence that the scanner makes of it in sbom-<root>.json, which the scanner's own tests
// hold to its analysis. This module can't import the scanner's, so the tests read the files by their paths.
var scannerTestdata = filepath.Join("..", "..", "..", "scanner", "internal", "analyze", "testdata")

// The roots of the scanner's fixtures.
const (
	rootAPK  = "apk"
	rootDpkg = "dpkg"
	rootRPM  = "rpm"
)

// brotli is the source package of the Brotli libraries of every root.
const brotli = "brotli"

// grypeOf returns the packages that Grype reads from the SBOM document at path, by ID, and the distribution of the
// document, as the collector's Grype reads them: from sbom:<path>, with the default fix channels and no CPEs of its
// own making.
func grypeOf(t *testing.T, path string) (map[string]pkg.Package, *distro.Distro) {
	t.Helper()
	pkgs, ctx, _, err := pkg.Provide("sbom:"+path, pkg.ProviderConfig{SynthesisConfig: pkg.SynthesisConfig{
		Distro: pkg.DistroConfig{FixChannels: distro.DefaultFixChannels()},
	}})
	require.NoError(t, err)
	byID := make(map[string]pkg.Package, len(pkgs))
	for _, p := range pkgs {
		byID[string(p.ID)] = p
	}
	require.Len(t, byID, len(pkgs), "each package has an ID of its own")
	return byID, ctx.Distro
}

// identity is what Grype matches a package by, but for its metadata.
type identity struct {
	Name, Version, Type, Language, PURL string
	// CPEs are the package's CPEs, as Grype searches by them.
	CPEs []string
	// Upstreams are the source packages that Grype matches the package as, too.
	Upstreams []pkg.UpstreamPackage
	// Distro is the distribution whose advisories Grype reads for the package.
	Distro *distro.Distro
}

func identityOf(p pkg.Package) identity {
	id := identity{Name: p.Name, Version: p.Version, Type: string(p.Type), Language: string(p.Language), PURL: p.PURL,
		Upstreams: p.Upstreams, Distro: p.Distro}
	for _, c := range p.CPEs {
		id.CPEs = append(id.CPEs, c.Attributes.BindToFmtString())
	}
	return id
}

// lenient returns the metadata that Grype reads from Syft's JSON, without what the document doesn't carry. Each part
// left out can only make Grype more lenient, or doesn't matter to a match:
//   - an rpm's epoch: the version holds it, as Syft writes it, and Grype reads the metadata's only for a version that
//     has none;
//   - an rpm's modularity label: Grype takes a package that has none for the package of any module's advisory, where
//     an empty label holds a package to the advisories without a module;
//   - an apk's file list: without the files that a package owns, Grype drops no other package that one of them holds;
//   - a Go binary's build information: without the main module, Grype matches the main module as any other module;
//     without symbols it matches by module, not by function; the build settings, the Go version, the architecture and
//     the digest of a module are no part of a match;
//   - a Java archive's path, which is no part of a match, and its digests, which Grype reads only to search Maven by
//     SHA-1 for an archive without a group or artifact ID, which the collector's Grype never does: it has its external
//     sources off.
//
// A Java archive's manifest name stays: Grype searches the advisories by the group and that name as well, so a
// fixture whose archive had one would fail here.
func lenient(metadata any) any {
	switch m := metadata.(type) {
	case pkg.RpmMetadata:
		m.Epoch, m.ModularityLabel = nil, nil
		return m
	case pkg.ApkMetadata:
		m.Files = []pkg.ApkFileRecord{}
		return m
	case pkg.GolangBinMetadata:
		return nil
	case pkg.JavaMetadata:
		m.VirtualPath, m.ArchiveDigests = "", nil
		return m
	}
	return metadata
}

// requireSamePackages requires that Grype reads the same packages from the document at path as from Syft's JSON at
// syftPath: each under the same ID, with the same identity, and with the metadata of Syft's JSON but for what lenient
// leaves out. It returns the packages.
func requireSamePackages(t *testing.T, syftPath, path string) map[string]pkg.Package {
	t.Helper()
	before, beforeDistro := grypeOf(t, syftPath)
	after, afterDistro := grypeOf(t, path)

	require.NotEmpty(t, before)
	require.Equal(t, beforeDistro, afterDistro, "the distribution of the document")
	require.ElementsMatch(t, keysOf(before), keysOf(after), "the packages, by ID, which the matches name")
	for id, p := range before {
		require.Equal(t, identityOf(p), identityOf(after[id]), "package %s (%s)", id, p.Name)
		require.Equal(t, lenient(p.Metadata), after[id].Metadata, "the metadata of package %s (%s)", id, p.Name)
	}
	return after
}

func keysOf(pkgs map[string]pkg.Package) []string {
	keys := make([]string, 0, len(pkgs))
	for id := range pkgs {
		keys = append(keys, id)
	}
	return keys
}

// documentOf returns the path of a file that holds the document that the vulnerabilities collector hands Grype, through
// its operation match, for the sbom evidence whose data is sbom.
func documentOf(t *testing.T, sbom any) string {
	t.Helper()
	g := newGrype(&dbOne)
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))

	_, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, sbom)))

	require.NoError(t, err)
	require.Nil(t, failure)
	documents, _ := g.matched()
	require.Len(t, documents, 1)
	path := filepath.Join(t.TempDir(), "document.json")
	require.NoError(t, os.WriteFile(path, documents[0], 0o600))
	return path
}

// The scanner's fixtures hold what Grype reads besides a package's name and version (see their gen.sh): an apk built
// from an origin of another name, and one from itself; a deb of a source package of another name, and a rebuild of
// one of its own name in another version; an rpm of a source rpm, with an epoch; Go modules of a Go program; and a
// Java archive. From the scanner's sbom evidence of each root, the document gives Grype the packages of Syft's JSON.
func TestTheDocumentOfTheScannersSBOMGivesGrypeThePackagesOfSyftsJSON(t *testing.T) {
	for _, root := range []string{rootAPK, rootDpkg, rootRPM} {
		t.Run(root, func(t *testing.T) {
			sbom, err := os.ReadFile(filepath.Join(scannerTestdata, "sbom-"+root+".json"))
			require.NoError(t, err)

			requireSamePackages(t, filepath.Join(scannerTestdata, "syft-"+root+".json"),
				documentOf(t, json.RawMessage(sbom)))
		})
	}
}

// What the fixtures prove: the source packages that Debian, RPM-based and Alpine distributions track vulnerabilities
// by reach Grype, and so does the distribution, codename included.
func TestTheDocumentCarriesTheSourcePackagesAndTheDistribution(t *testing.T) {
	upstreams := map[string]map[string][]pkg.UpstreamPackage{
		rootAPK:  {"brotli-libs": {{Name: brotli}}, "app-tools": {{Name: "app-tools"}}},
		rootDpkg: {"libbrotli1": {{Name: brotli, Version: "1.0.9-2"}}, "bash": {{Name: "bash", Version: "5.2.15-2"}}},
		rootRPM:  {"libbrotli": {{Name: brotli, Version: "1.0.9-1"}}},
	}
	distros := map[string]string{rootAPK: "alpine 3.22.2", rootDpkg: "debian 12", rootRPM: "fedora 43"}
	for root, want := range upstreams {
		t.Run(root, func(t *testing.T) {
			sbom, err := os.ReadFile(filepath.Join(scannerTestdata, "sbom-"+root+".json"))
			require.NoError(t, err)

			pkgs := requireSamePackages(t, filepath.Join(scannerTestdata, "syft-"+root+".json"),
				documentOf(t, json.RawMessage(sbom)))

			for _, p := range pkgs {
				if upstream, ok := want[p.Name]; ok {
					require.Equal(t, upstream, p.Upstreams, p.Name)
				}
				require.NotNil(t, p.Distro, p.Name)
				require.Equal(t, distros[root], p.Distro.String(), p.Name)
			}
			if root == rootDpkg {
				require.Equal(t, "bookworm", pkgs["feec52b81c8e068a"].Distro.Codename)
			}
		})
	}
}

// Grype picks the advisories of a distribution by more of os-release than its ID and version, and so does the document:
// a distribution whose ID Grype doesn't know is the one that its ID_LIKE names, as Pop!_OS is Ubuntu, and a release
// without a version is its codename, as Debian's testing is. Without them Grype would read no advisories of the
// distribution, and find nothing in its packages.
func TestTheDocumentGivesGrypeTheDistributionOfTheSBOM(t *testing.T) {
	for name, tc := range map[string]struct {
		distro evidence.Distro
		want   string
	}{
		"a derivative of a distribution that Grype knows": {
			distro: evidence.Distro{ID: "pop", Version: "22.04", Codename: "jammy", IDLike: []string{"ubuntu", "debian"}},
			want:   "ubuntu 22.04",
		},
		"a release that has a codename and no version": {
			distro: evidence.Distro{ID: "debian", Codename: "trixie"},
			want:   "debian trixie",
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := tc.distro
			sbom := evidence.SBOM{
				Distro: &d,
				Packages: []evidence.SBOMPackage{{
					ID: "pkg-1", Name: "libssl3", Version: "3.0.2-0ubuntu1.15", Type: "deb",
					PURL: "pkg:deb/" + d.ID + "/libssl3@3.0.2-0ubuntu1.15?arch=amd64&upstream=openssl",
				}},
				Producer: evidence.Producer{Name: syft, Version: "1.55.0"},
			}

			pkgs, got := grypeOf(t, documentOf(t, sbom))

			require.NotNil(t, got)
			require.Equal(t, tc.want, got.String())
			require.Equal(t, tc.want, pkgs["pkg-1"].Distro.String())
			require.Equal(t, []pkg.UpstreamPackage{{Name: "openssl"}}, pkgs["pkg-1"].Upstreams)
		})
	}
}

// The Grype wrapper's golden output is what Grype v0.121.0 found, on 2026-10-30, in the SBOM that phase 2b's image
// contents carried for two packages of Alpine 3.12 (internal/grype/testdata). The sbom evidence of the same packages
// gets a document from which Grype reads the same packages, with the same IDs, so it gets the same matches, and each
// match names a package of the SBOM.
func TestAnSBOMGetsTheMatchesThatPhase2bsInputGot(t *testing.T) {
	old := filepath.Join("..", "grype", "testdata", "sbom.json")
	sbom := sbomOfSyftJSON(t, old)

	requireSamePackages(t, old, documentOf(t, sbom))

	raw, err := os.ReadFile(filepath.Join("..", "grype", "testdata", "grype-output.json"))
	require.NoError(t, err)
	var golden struct {
		Matches []struct {
			Artifact struct {
				ID string `json:"id"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	require.NoError(t, json.Unmarshal(raw, &golden))
	require.NotEmpty(t, golden.Matches)
	ids := map[string]bool{}
	for _, p := range sbom.Packages {
		ids[p.ID] = true
	}
	for _, m := range golden.Matches {
		require.True(t, ids[m.Artifact.ID], "a golden match names package %s of the SBOM", m.Artifact.ID)
	}
}

// sbomOfSyftJSON returns the sbom evidence of Syft's JSON at path, as the scanner makes it: each package with its ID,
// name, version, type, purl and CPEs as Syft wrote them, the distribution, and Syft as the producer. The scanner's
// tests hold its analysis to the same, for its own fixtures.
func sbomOfSyftJSON(t *testing.T, path string) evidence.SBOM {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc struct {
		Artifacts []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			PURL    string `json:"purl"`
			CPEs    []struct {
				CPE string `json:"cpe"`
			} `json:"cpes"`
		} `json:"artifacts"`
		Distro struct {
			ID              string   `json:"id"`
			VersionID       string   `json:"versionID"`
			VersionCodename string   `json:"versionCodename"`
			IDLike          []string `json:"idLike"`
		} `json:"distro"`
		Descriptor struct {
			Version string `json:"version"`
		} `json:"descriptor"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	sbom := evidence.SBOM{
		Distro: &evidence.Distro{ID: doc.Distro.ID, Version: doc.Distro.VersionID, Codename: doc.Distro.VersionCodename,
			IDLike: doc.Distro.IDLike},
		Producer: evidence.Producer{Name: syft, Version: doc.Descriptor.Version},
	}
	for _, a := range doc.Artifacts {
		p := evidence.SBOMPackage{ID: a.ID, Name: a.Name, Version: a.Version, Type: a.Type, PURL: a.PURL}
		for _, c := range a.CPEs {
			p.CPEs = append(p.CPEs, c.CPE)
		}
		sbom.Packages = append(sbom.Packages, p)
	}
	return sbom
}
