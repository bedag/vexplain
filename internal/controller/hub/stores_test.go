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

package hub_test

import (
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/utils/ptr"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

var _ = Describe("The inventory stores, as the hub uses them", func() {
	It("find the digests whose facts name a manifest through the index of the manager's cache, and keep its evidence while one of them runs", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		namespace, shared, unnamed := newNamespace(), newDigest(), newDigest()
		first, second := newDigest(), newDigest()

		By("scanning two images that share a platform manifest, such as two indexes of one image")
		firstApp := runAndScan(namespace, "app-0", first, evidenceOf(shared))
		secondApp := runAndScan(namespace, "app-1", second, evidenceOf(shared))

		// The janitor's store: the manager's client, which reads from the manager's cache, with the
		// cache's informers. setup.Register gives the cache the index.
		store := inventory.NewCRDStore(k8sManager.GetClient(), k8sManager.GetCache(), cluster)
		referencesOf := func(manifest string) func(g Gomega) []string {
			return func(g Gomega) []string {
				digests, err := store.ManifestReferences(ctx, manifest)
				g.Expect(err).NotTo(HaveOccurred())
				return digests
			}
		}
		Eventually(referencesOf(shared), reaction, poll).Should(ConsistOf(first, second))
		Expect(referencesOf(unnamed)(Default)).To(BeEmpty())
		Eventually(statusOf(shared), reaction, poll).ShouldNot(BeNil())

		By("keeping the evidence and the sheet of the manifest while one of the images still runs")
		stopWorkload(firstApp)
		Eventually(referencesOf(shared), reaction, poll).Should(ConsistOf(second))
		// Longer than the janitor's grace and a round.
		Consistently(heldOf(shared), 2*janitorGrace, poll).Should(Equal(scanTypes))
		Expect(statusOf(shared)(Default)).NotTo(BeNil())

		By("deleting both once neither runs")
		stopWorkload(secondApp)
		Eventually(heldOf(shared), reaction, poll).Should(BeEmpty())
		Eventually(statusOf(shared), reaction, poll).Should(BeNil())
	})

	// The engine cuts each finding to the limits of the schema, and Sheet a sheet to 2048 findings and
	// 1 MiB. They copy those limits by hand: only the API server can tell whether they are the schema's.
	It("have the API server accept the sheets of worst-case findings", func() {
		verdicts := inventory.NewCRDVerdictsStore(k8sClient, cluster)
		steps := make([]*engine.Compiled, 0, 4)
		for _, rule := range defaultRules() {
			compiled, err := engine.Compile(rule)
			Expect(err).NotTo(HaveOccurred())
			steps = append(steps, compiled)
		}
		write := func(manifest string, evidence scan, matches []sdkevidence.Match) *inventoryv1alpha1.ImageVerdictsStatus {
			GinkgoHelper()
			found := engine.Evaluate(steps, inputsOf(evidence), matches).Findings
			kept, omitted, counts, summary := rules.Sheet(rules.Findings(found))
			Expect(verdicts.Put(ctx, manifest, inventoryv1alpha1.ImageVerdictsStatus{
				Playbook:        ptr.To(playbookName),
				FindingsVersion: ptr.To(v1),
				Findings:        kept,
				OmittedFindings: ptr.To(omitted),
				Counts:          &counts,
				Summary:         &summary,
			})).To(Succeed())
			DeferCleanup(verdicts.Delete, ctx, manifest)
			stored := statusOf(manifest)(Default)
			Expect(stored).NotTo(BeNil())
			Expect(stored.Findings).To(HaveLen(len(kept)))
			return stored
		}

		By("cutting every string to its limit, and the sheet to 1 MiB")
		manifest := newDigest()
		evidence, matches := worstCase(manifest, 600)
		stored := write(manifest, evidence, matches)
		Expect(*stored.OmittedFindings).To(BeNumerically(">", 0), "the findings pass 1 MiB")
		Expect(stored.Findings[0].VulnerabilityID).To(Equal("unknown"), "the match that names nothing")
		Expect(stored.Findings[1].StatusNotes).To(HaveLen(1), "the note of the load check, cut to its limit")

		By("cutting the sheet to 2048 findings")
		manifest = newDigest()
		matches = make([]sdkevidence.Match, 0, 2100)
		for i := range 2100 {
			m := goneMatch
			m.VulnerabilityID = fmt.Sprintf("CVE-2026-%05d", i)
			matches = append(matches, m)
		}
		stored = write(manifest, evidenceOf(manifest), matches)
		Expect(stored.Findings).To(HaveLen(2048))
		Expect(stored.OmittedFindings).To(HaveValue(Equal(int32(52))))
		Expect(stored.Counts.NotAffected).To(HaveValue(Equal(int32(2100))), "every finding is settled")
	})
})

// inputsOf returns the scanner's evidence s as the default playbook supplies it to the rules: the contents and the
// SBOM, under their names.
func inputsOf(s scan) map[string]engine.Input {
	GinkgoHelper()
	inputs := map[string]engine.Input{}
	for name, data := range map[string]any{contents: s.contents, sbomName: s.sbom} {
		raw, err := json.Marshal(data)
		Expect(err).NotTo(HaveOccurred())
		var decoded any
		Expect(json.Unmarshal(raw, &decoded)).To(Succeed())
		inputs[name] = engine.Input{Present: true, Data: decoded, Coverage: ptr.To(s.contents.Completeness()),
			Source: "/clusters/cluster-a/collectors/scanner"}
	}
	return inputs
}

// worstCase returns evidence and matches whose findings pass every limit of the schema before the
// engine cuts them: IDs, names, versions and types past their maximum lengths, more fixed versions
// and scores than a finding holds and each too long, a note past 256 characters, an unprintable
// character, and a match that names nothing. The finding that names nothing and the one with the
// note come first on the sheet. Then come n settled findings in a package that a later layer
// removed, which the sheet keeps while they fit in 1 MiB.
func worstCase(manifest string, n int) (scan, []sdkevidence.Match) {
	GinkgoHelper()
	reachedID, removedID := "pkg-reached-"+strings.Repeat("r", 100), "pkg-removed-"+strings.Repeat("x", 100)
	pkg := func(id string) sdkevidence.SBOMPackage {
		return sdkevidence.SBOMPackage{
			ID: id, Name: strings.Repeat("ñ", 300), Version: "1.0\x1b[31m" + strings.Repeat("9", 200), Type: strings.Repeat("t", 50),
		}
	}
	contents := imagecontents.Manifest{
		Platform: linuxAMD64,
		Digest:   manifest,
		Packages: []imagecontents.PackageFacts{
			{ID: reachedID, FilesListed: 1, FilesPresent: 1, SharedLibraries: 1},
			{ID: removedID, FilesListed: 1},
		},
		ELF: imagecontents.ELFSummary{Total: 1, Owned: 1},
		Libraries: []imagecontents.Library{
			{Path: "/usr/lib/libreached.so.1", Soname: "libreached.so.1", PackageID: reachedID,
				ReachedBy: []string{"/usr/bin/" + strings.Repeat("ß", 300)}, ReachedCount: 1},
		},
	}

	fixedVersions := make([]string, 10)
	for i := range fixedVersions {
		fixedVersions[i] = fmt.Sprintf("%d.%s", i, strings.Repeat("0", 200))
	}
	scores := make([]sdkevidence.CVSS, 6)
	for i := range scores {
		scores[i] = sdkevidence.CVSS{Version: fmt.Sprintf("%d.%s", i, strings.Repeat("1", 30)), Vector: strings.Repeat("V", 300)}
	}
	match := func(id, packageID string) sdkevidence.Match {
		return sdkevidence.Match{VulnerabilityID: id, PackageID: packageID, Severity: critical, FixState: fixedState,
			FixedVersions: fixedVersions, CVSS: scores, PackageName: strings.Repeat("n", 300), PackageType: deb,
			PackageVersion: strings.Repeat("9", 200)}
	}
	matches := make([]sdkevidence.Match, 0, n+2)
	matches = append(matches, sdkevidence.Match{KnownExploited: true}, match("CVE-2026-0001-"+strings.Repeat("v", 100), reachedID))
	for i := range n {
		matches = append(matches, match(fmt.Sprintf("CVE-2026-%06d-%s", i+2, strings.Repeat("v", 100)), removedID))
	}
	sbom := sdkevidence.SBOM{Packages: []sdkevidence.SBOMPackage{pkg(reachedID), pkg(removedID)},
		Producer: sdkevidence.Producer{Name: "syft"}}
	return scan{contents: contents, sbom: sbom}, matches
}
