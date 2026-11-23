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
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/bedag/vexplain/internal/agent/cases"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// The fixtures of the judge's tests, as the hub's tests have them: the judge runs on the sheets and the evidence that
// the hub writes.
const (
	operatorNamespace = "vexplain-system"
	// scanner delivers the evidence of the images, and sbomName is the name under which the playbook supplies its
	// SBOM.
	scanner  = "scanner"
	sbomName = "sbom"
	// repository is where the images of the tests come from, and localCluster the cluster of the hub.
	repository   = "artifacts.example/team-a/app"
	localCluster = "cluster-a"
	// v1 and v2 are versions of the database of the findings collector, from two daily builds.
	v1 = "v6.1.10+2026-10-29T06:23:28Z"
	v2 = "v6.1.10+2026-10-30T06:23:28Z"
	// linuxAMD64 is the platform of the manifests of the tests.
	linuxAMD64 = "linux/amd64"
	// examplePackage, otherPackage and gonePackage are the IDs of the packages of three libraries of the SBOM, with
	// their names and versions, and deb their type.
	examplePackage = "pkg-1"
	exampleName    = "libexample1"
	exampleVersion = "1.0-1"
	otherPackage   = "pkg-2"
	otherName      = "libother2"
	otherVersion   = "2.0-1"
	gonePackage    = "pkg-4"
	goneName       = "libgone4"
	goneVersion    = "4.0-1"
	deb            = "deb"
	// appPackage is the ID of the package of a program, and appName its name, which also names the workload that
	// runs the image.
	appPackage = "pkg-3"
	appName    = "app"
	// deployment is the kind of the workload.
	deployment = "Deployment"
	// clusterLabel is the label of the series that holds the name of a cluster, and valueKey the key of a series'
	// value among its labels.
	clusterLabel = "cluster"
	valueKey     = "value"
)

// sbomOf returns the SBOM of a manifest of the tests: four packages of Debian, of which libexample1 is built from a
// source package of another name, as its purl says.
func sbomOf() sdkevidence.SBOM {
	return sdkevidence.SBOM{
		Distro: &sdkevidence.Distro{ID: debian, Version: "12", Codename: "bookworm"},
		Packages: []sdkevidence.SBOMPackage{
			{ID: examplePackage, Name: exampleName, Version: exampleVersion, Type: deb,
				PURL: "pkg:deb/debian/libexample1@1.0-1?arch=amd64&distro=debian-12&upstream=example"},
			{ID: otherPackage, Name: otherName, Version: otherVersion, Type: deb},
			{ID: appPackage, Name: appName, Version: "3.0", Type: deb},
			{ID: gonePackage, Name: goneName, Version: goneVersion, Type: deb},
		},
		Producer: sdkevidence.Producer{Name: "syft", Version: "1.55.0"},
	}
}

// gatherGauges returns the series of each gauge that c sends, as their labels and their value under "value".
func gatherGauges(t *testing.T, c prometheus.Collector) map[string][]map[string]string {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	families, err := reg.Gather()
	require.NoError(t, err)
	out := map[string][]map[string]string{}
	for _, family := range families {
		for _, m := range family.Metric {
			series := map[string]string{valueKey: strconv.FormatFloat(m.GetGauge().GetValue(), 'f', -1, 64)}
			for _, l := range m.Label {
				series[l.GetName()] = l.GetValue()
			}
			out[family.GetName()] = append(out[family.GetName()], series)
		}
	}
	return out
}

// idleQueue is a queue that takes every case, and has none pending, as an agent that is idle.
type idleQueue struct{}

func (idleQueue) Add(cases.Case, cases.Request) bool                 { return true }
func (idleQueue) Keep(types.NamespacedName, []string)                {}
func (idleQueue) Pending(types.NamespacedName, types.UID) (int, int) { return 0, 0 }
