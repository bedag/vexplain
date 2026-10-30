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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/scan/result"
)

var _ = Describe("The inventory stores, as the hub uses them", func() {
	It("find the digests whose facts name a manifest through the index of the manager's cache", func() {
		matcher.set(v1, exampleMatch, otherMatch)
		namespace, shared, unnamed := newNamespace(), newDigest(), newDigest()
		first, second := newDigest(), newDigest()

		By("scanning two images that share a platform manifest, such as two indexes of one image")
		firstPod := runAndScan(namespace, "app-0", first, evidenceOf(shared))
		secondPod := runAndScan(namespace, "app-1", second, evidenceOf(shared))

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

		By("keeping the evidence of the manifest while one of the images still runs")
		deletePod(firstPod)
		Eventually(referencesOf(shared), reaction, poll).Should(ConsistOf(second))
		// Longer than the janitor's grace and a round.
		Consistently(lookup(shared, &inventoryv1alpha1.ImagePackages{}), 2*janitorGrace, poll).Should(Succeed())

		By("deleting it once neither runs")
		deletePod(secondPod)
		Eventually(lookup(shared, &inventoryv1alpha1.ImagePackages{}), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
	})

	// The rules cut each finding to the limits of the schema, and a sheet to 2048 findings and 1 MiB.
	// They copy those limits by hand: only the API server can tell whether they are the schema's.
	It("have the API server accept the sheets of worst-case findings", func() {
		verdicts := inventory.NewCRDVerdictsStore(k8sClient, cluster)
		write := func(manifest string, findings []inventoryv1alpha1.Finding) *inventoryv1alpha1.ImageVerdictsStatus {
			GinkgoHelper()
			kept, omitted, counts := rules.Sheet(findings)
			Expect(verdicts.Put(ctx, manifest, inventoryv1alpha1.ImageVerdictsStatus{
				DatabaseVersion: ptr.To(v1),
				ScannerImage:    ptr.To(scannerImage),
				Findings:        kept,
				OmittedFindings: ptr.To(omitted),
				Counts:          &counts,
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
		stored := write(manifest, rules.Evaluate(evidence, matches, rules.Settings{MinCompletenessPercent: 90}))
		Expect(*stored.OmittedFindings).To(BeNumerically(">", 0), "the findings pass 1 MiB")
		Expect(stored.Findings[1].VulnerabilityID).To(Equal("unknown"), "the match that names nothing")

		By("cutting the sheet to 2048 findings")
		manifest = newDigest()
		matches = make([]matchapi.Match, 0, 2100)
		for i := range 2100 {
			m := exampleMatch
			m.VulnerabilityID = fmt.Sprintf("CVE-2026-%05d", i)
			matches = append(matches, m)
		}
		stored = write(manifest, rules.Evaluate(evidenceOf(manifest), matches, rules.Settings{MinCompletenessPercent: 90}))
		Expect(stored.Findings).To(HaveLen(2048))
		Expect(stored.OmittedFindings).To(HaveValue(Equal(int32(52))))
	})
})

// worstCase returns evidence and matches whose findings pass every limit of the schema before the
// rules cut them: IDs, names, versions and types past their maximum lengths, more fixed versions
// than a finding holds and each too long, a reason past 256 bytes, an unprintable character, and a
// match that names nothing. The finding with the reason and the one that names nothing come first
// on the sheet. Then come n findings in a library that nothing loads, which the sheet keeps while
// they fit in 1 MiB.
func worstCase(manifest string, n int) (result.Manifest, []matchapi.Match) {
	GinkgoHelper()
	reachedID, unusedID := "pkg-reached-"+strings.Repeat("r", 100), "pkg-unused-"+strings.Repeat("u", 100)
	artifact := func(id string) map[string]string {
		return map[string]string{
			"id":      id,
			"name":    strings.Repeat("ñ", 300),
			"version": "1.0\x1b[31m" + strings.Repeat("9", 200),
			"type":    strings.Repeat("t", 50),
		}
	}
	sbom, err := json.Marshal(map[string]any{"artifacts": []any{artifact(reachedID), artifact(unusedID)}})
	Expect(err).NotTo(HaveOccurred())
	evidence := result.Manifest{
		Platform: linuxAMD64,
		Digest:   manifest,
		SBOM:     sbom,
		Packages: []result.PackageFacts{
			{ID: reachedID, FilesListed: 1, FilesPresent: 1, SharedLibraries: 1},
			{ID: unusedID, FilesListed: 1, FilesPresent: 1, SharedLibraries: 1},
		},
		ELF: result.ELFSummary{Total: 2, Owned: 2},
		Libraries: []result.Library{
			{Path: "/usr/lib/libreached.so.1", Soname: "libreached.so.1", PackageID: reachedID,
				ReachedBy: []string{"/usr/bin/" + strings.Repeat("ß", 300)}, ReachedCount: 1},
			{Path: "/usr/lib/libunused.so.1", Soname: "libunused.so.1", PackageID: unusedID},
		},
	}

	fixedVersions := make([]string, 10)
	for i := range fixedVersions {
		fixedVersions[i] = fmt.Sprintf("%d.%s", i, strings.Repeat("0", 200))
	}
	match := func(id, packageID string) matchapi.Match {
		return matchapi.Match{VulnerabilityID: id, PackageID: packageID, Severity: "Critical", FixState: "fixed",
			FixedVersions: fixedVersions, PackageName: "unused", PackageType: deb}
	}
	matches := make([]matchapi.Match, 0, n+2)
	matches = append(matches, match("CVE-2026-0001-"+strings.Repeat("v", 100), reachedID), matchapi.Match{})
	for i := range n {
		matches = append(matches, match(fmt.Sprintf("CVE-2026-%06d-%s", i+2, strings.Repeat("v", 100)), unusedID))
	}
	return evidence, matches
}
