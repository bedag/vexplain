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

package worker_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/casefile"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/worker"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

const debian = "debian"

func TestThePackagesOfACaseNameTheirPurlAndDistroFromTheSBOM(t *testing.T) {
	finding := func(id, typ string) inventoryv1alpha1.Finding {
		return inventoryv1alpha1.Finding{VulnerabilityID: "CVE-2026-0001",
			Package: inventoryv1alpha1.PackageReference{ID: id, Name: id, Type: typ}}
	}
	c := cases.Case{Findings: []inventoryv1alpha1.Finding{finding(examplePackage, "deb"), finding(otherPackage, "go-module"),
		finding(appPackage, "deb")}}
	sbom := &sdkevidence.SBOM{
		Distro: &sdkevidence.Distro{ID: debian, Version: "12"},
		Packages: []sdkevidence.SBOMPackage{
			{ID: examplePackage, PURL: "pkg:deb/debian/libbrotli1@1.0.9-2"},
			{ID: otherPackage, PURL: "pkg:golang/stdlib@1.22.0"},
			{ID: appPackage, PURL: "pkg:deb/ubuntu/curl@8.0?distro=ubuntu-22.04"},
		},
	}

	require.Equal(t, map[string]casefile.Package{
		examplePackage: {PURL: "pkg:deb/debian/libbrotli1@1.0.9-2", Distro: "debian-12"},
		otherPackage:   {PURL: "pkg:golang/stdlib@1.22.0"},
		appPackage:     {PURL: "pkg:deb/ubuntu/curl@8.0?distro=ubuntu-22.04", Distro: "ubuntu-22.04"},
	}, worker.Packages(c, sbom), "an OS package takes the SBOM's distribution unless its purl names one; a Go module has none")
	require.Equal(t, map[string]casefile.Package{examplePackage: {}, otherPackage: {}, appPackage: {}}, worker.Packages(c, nil))
}
