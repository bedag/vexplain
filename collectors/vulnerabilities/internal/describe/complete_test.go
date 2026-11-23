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

package describe

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/evidence"
)

// TestNoAnswerIsLeftOut: an entry that the answer leaves out says Unknown for every asked package, so each Yes and No
// of the full answer, which holds every entry, is in the listed entries. It runs on each fixture, for the packages
// that the tests ask about.
const (
	typeBinary   = "binary"
	typeGoModule = "go-module"
	brotliName   = "brotli"
)

func TestNoAnswerIsLeftOut(t *testing.T) {
	deb := func(name, version, distro, upstream string) evidence.DescribedPackage {
		return evidence.DescribedPackage{Name: name, Version: version, Type: "deb", Distro: distro,
			PURL: "pkg:deb/debian/" + name + "@" + version + "?distro=" + distro + "&upstream=" + upstream}
	}
	stdlib := func(v string) evidence.DescribedPackage {
		return evidence.DescribedPackage{Name: "stdlib", Version: "go" + v, Type: typeGoModule, PURL: "pkg:golang/stdlib@" + v}
	}
	gin := func(v string) evidence.DescribedPackage {
		return evidence.DescribedPackage{Name: "github.com/gin-gonic/gin", Version: v, Type: typeGoModule}
	}
	for fixture, packages := range map[string][]evidence.DescribedPackage{
		"debian": {deb("libbrotli1", "1.0.9-2+deb12u1", "debian-12", "brotli"), deb("libbrotli1", "1.0.9-2", "debian-12", "brotli"),
			{Name: brotliName, Version: "1.0.9", Type: typeBinary, PURL: "pkg:generic/brotli@1.0.9"},
			{Name: brotliName, Version: "1.0.9-2+deb12u1", Type: typeBinary, Distro: "debian-12"}},
		"ghsa":       {gin("v1.9.1"), gin("v1.9.0"), gin("v1.3.0")},
		"ghsa-alias": {gin("v1.9.1"), gin("v1.9.0")},
		"go":         {stdlib("1.27.1"), stdlib("1.27.2"), {Name: "golang.org/x/net", Version: "v0.57.0", Type: typeGoModule}},
		"go-alias":   {stdlib("1.26.5")},
		"rhel": {{Name: brotliName, Version: "1.0.9-7.el9_6.3", Type: "rpm",
			PURL: "pkg:rpm/redhat/brotli@1.0.9-7.el9_6.3?distro=rhel-9.6"}},
		"busybox": {{Name: "busybox", Version: "1.36.1", Type: typeBinary, PURL: "pkg:generic/busybox@1.36.1"}},
		"unknown": {gin("v1.9.1")},
	} {
		t.Run(fixture, func(t *testing.T) {
			recordsJSON, err := os.ReadFile(filepath.Join("testdata", fixture+"-records.json"))
			require.NoError(t, err)
			packagesJSON, err := os.ReadFile(filepath.Join("testdata", fixture+"-packages.json"))
			require.NoError(t, err)
			_, rows, err := parse(recordsJSON, packagesJSON)
			require.NoError(t, err)
			asked := make([]installed, 0, len(packages))
			for _, p := range packages {
				in, ok := installedOf(p)
				require.True(t, ok, "%s %s", p.Name, p.Version)
				asked = append(asked, in)
			}

			listed, others := providersOf(asked, rows)

			full := entriesOf(asked, rows)
			counted := int32(len(listed))
			for _, c := range others {
				counted += c.Entries
			}
			require.Equal(t, int32(len(full)), counted, "every entry is listed or counted")
			for _, e := range full {
				for _, p := range e.fix.Packages {
					if p.FixedForInstalled != evidence.FixedForInstalledUnknown {
						require.Contains(t, listed, e.fix, "%s %s says %s", e.fix.Namespace, e.fix.Package, p.FixedForInstalled)
					}
				}
			}
		})
	}
}
