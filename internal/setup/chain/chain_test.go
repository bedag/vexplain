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

package chain_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	"github.com/bedag/vexplain/sdk/collector"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

const (
	// v1 and v2 are versions of the vulnerabilities collector's database.
	v1 = "v6.1.10+2026-10-29T06:23:28Z"
	v2 = "v6.1.10+2026-10-30T06:23:28Z"
	// packageID is the ID of the package that the scanner stand-in finds in every image.
	packageID = "pkg-1"
)

// libraryMatch is the match of the database for the package that the scanner stand-in finds in every image.
var libraryMatch = sdkevidence.Match{
	VulnerabilityID: "CVE-2026-111497", PackageID: packageID, PackageName: "libexample1", PackageVersion: "1.0-1",
	PackageType: "deb", Severity: "High", FixState: "not-fixed",
	CVSS: []sdkevidence.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
}

// sheetOf returns a function that reads the sheet of the manifest, or nil while it has none.
func sheetOf(manifest string) func() *inventoryv1alpha1.ImageVerdictsStatus {
	return func() *inventoryv1alpha1.ImageVerdictsStatus {
		var sheet inventoryv1alpha1.ImageVerdicts
		err := k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(manifest)}, &sheet)
		if err != nil {
			// A sheet that doesn't exist yet, or that can't be read now: the spec waits for it.
			return nil
		}
		return &sheet.Status
	}
}

var _ = Describe("The hub, with the production wiring", func() {
	It("takes an image from its presence to its SBOM and its image contents, findings and a sheet, and matches every "+
		"manifest again when the database changes", func() {
		images := []string{digestOf(1), digestOf(2)}
		manifests := map[string]string{images[0]: digestOf(101), images[1]: digestOf(102)}
		scanner := newScannerStandIn(GinkgoT(), func(image string) string { return manifests[image] })
		vulnerabilities := newVulnerabilitiesStandIn(GinkgoT(), v1, libraryMatch)
		awaitForgotten(images...)

		By("installing the scanner and the vulnerabilities collector, and then the workloads collector that reports the images")
		install("scanner", scanner)
		install("vulnerabilities", vulnerabilities)
		install("workloads", newWorkloadsStandIn(images...))
		install("network-reach", newNetworkReachStandIn(GinkgoT(), map[string]sdkevidence.Exposure{
			"web-0": {External: sdkevidence.ExternalExposure{Exposed: true}, InternalReach: "Cluster"},
			"web-1": {InternalReach: "Namespace"},
		}))

		By("writing the exposure of each workload into the presence entry of its image")
		for image, want := range map[string]inventoryv1alpha1.SSVCExposure{
			images[0]: inventoryv1alpha1.SSVCExposureOpen, images[1]: inventoryv1alpha1.SSVCExposureSmall,
		} {
			Eventually(func() *inventoryv1alpha1.SSVCExposure {
				var obj inventoryv1alpha1.ImageInventory
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(image)}, &obj); err != nil ||
					len(obj.Status.Clusters) == 0 {
					return nil
				}
				return obj.Status.Clusters[0].Exposure
			}, startup, poll).Should(HaveValue(Equal(want)))
		}

		By("having the spoke's executor invoke scan for each image, with the repositories and the pods of its presence")
		Eventually(func() []string {
			scans := scanner.scanned()
			subjectsScanned := make([]string, 0, len(scans))
			for _, call := range scans {
				subjectsScanned = append(subjectsScanned, call.Subject)
			}
			return subjectsScanned
		}, startup, poll).Should(ConsistOf(subjects.Image(images[0]), subjects.Image(images[1])))
		for _, call := range scanner.scanned() {
			Expect(call.Role).To(Equal(collector.RoleSpoke))
			Expect(call.Repositories).To(Equal([]string{repository}))
			Expect(call.Pods).To(HaveLen(1))
			Expect(call.Pods[0]).To(HavePrefix("team-a/web-"))
		}

		By("storing both events of each answer of the scanner, the SBOM of the manifest, which the hub asked for, and its " +
			"contents, and the facts that name both")
		store := evidence.NewCRDStore(k8sClient, nil, func() string { return "cluster-a" })
		for image, manifest := range manifests {
			for _, eventType := range []string{sdkevidence.TypeSBOM, imagecontents.Type} {
				Eventually(func() (*evidence.Record, error) {
					return store.Get(ctx, evidence.Key{Subject: subjects.Manifest(manifest), Type: eventType, Source: "scanner"})
				}, startup, poll).ShouldNot(BeNil(), eventType)
			}
			Eventually(func() []inventoryv1alpha1.EvidenceFact {
				var obj inventoryv1alpha1.ImageInventory
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(image)}, &obj); err != nil ||
					obj.Status.Facts == nil {
					return nil
				}
				return obj.Status.Facts.Evidence
			}, startup, poll).Should(ConsistOf(
				HaveField("Type", sdkevidence.TypeSBOM), HaveField("Type", imagecontents.Type)))
		}

		By("writing the sheet of each manifest from the findings that the vulnerabilities collector gave for its SBOM, with " +
			"the rules over its contents and its SBOM")
		for _, manifest := range manifests {
			Eventually(sheetOf(manifest), startup, poll).Should(And(
				Not(BeNil()),
				HaveField("FindingsVersion", HaveValue(Equal(v1))),
				HaveField("Playbook", HaveValue(Equal("container-cves"))),
				HaveField("Findings", HaveLen(1)),
				HaveField("Evidence", ConsistOf(
					And(HaveField("Name", "contents"), HaveField("Type", imagecontents.Type), HaveField("Version", Not(BeNil()))),
					And(HaveField("Name", "sbom"), HaveField("Type", sdkevidence.TypeSBOM), HaveField("Version", Not(BeNil()))),
				)),
			))
			Expect((*sheetOf(manifest)()).Findings[0].VulnerabilityID).To(Equal(libraryMatch.VulnerabilityID))
		}
		Expect(vulnerabilities.matched()).To(HaveLen(2))
		for _, call := range vulnerabilities.matched() {
			Expect(call.Role).To(Equal(collector.RoleHub))
			Expect(call.Inputs).To(Equal([]string{sdkevidence.TypeSBOM}))
			Expect(call.Platform).To(Equal(platform))
			Expect([]string{subjects.Manifest(manifests[images[0]]), subjects.Manifest(manifests[images[1]])}).To(ContainElement(call.Subject))
		}

		By("matching every manifest again when the vulnerabilities collector says that its database changed")
		exploited := libraryMatch
		exploited.KnownExploited = true
		vulnerabilities.setDatabase(v2, exploited)
		for _, manifest := range manifests {
			Eventually(sheetOf(manifest), startup, poll).Should(And(
				Not(BeNil()),
				HaveField("FindingsVersion", HaveValue(Equal(v2))),
				HaveField("Findings", ConsistOf(HaveField("KnownExploited", inventoryv1alpha1.KnownExploitedListed))),
			))
		}
		Expect(vulnerabilities.matched()).To(HaveLen(4), "each manifest was matched once more")
	})
})
