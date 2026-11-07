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

package inventory_test

import (
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

const (
	// maxFindings is the most findings that one sheet holds.
	maxFindings = 2048
	// justificationRule is the message of the rule that ties a justification to a finding that is not
	// affected.
	justificationRule = "justification is set exactly for a finding that is NotAffected"
	// The names of the rules and the playbook of the sheets that the specs write.
	knownExploited = "known-exploited"
	loadCheck      = "load-check"
	removedRule    = "removed-in-later-layer"
	playbookName   = "container-cves"
)

// newSheet returns the ImageVerdicts of the platform manifest with the digest, with no status. The
// status is a subresource, so the API server ignores one on create: a spec writes it in a second call.
func newSheet(manifestDigest string) *inventoryv1alpha1.ImageVerdicts {
	return &inventoryv1alpha1.ImageVerdicts{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(manifestDigest)},
		Spec:       inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifestDigest},
	}
}

// createSheet creates sheet, and deletes it after the spec.
func createSheet(sheet *inventoryv1alpha1.ImageVerdicts) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, sheet)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, sheet))).To(Succeed())
	})
}

// finding returns a finding that the schema accepts: one that a rule holds open, which has no
// justification.
func finding() inventoryv1alpha1.Finding {
	return inventoryv1alpha1.Finding{
		VulnerabilityID: "CVE-2026-0001",
		Package: inventoryv1alpha1.PackageReference{
			ID: "pkg-1", Name: "brotli-libs", Version: ptr.To("1.1.0-r2"), Type: "apk",
		},
		Status:         inventoryv1alpha1.VEXStatusUnderInvestigation,
		Severity:       inventoryv1alpha1.SeverityHigh,
		FixState:       inventoryv1alpha1.FixStateFixed,
		KnownExploited: inventoryv1alpha1.KnownExploitedNotListed,
	}
}

// contents returns the evidence that a sheet rested on: the scanner's, as the default playbook names
// it.
func contents() inventoryv1alpha1.SheetEvidence {
	return inventoryv1alpha1.SheetEvidence{
		Name:    "contents",
		Source:  "scanner",
		Type:    imageContentsType,
		Version: ptr.To(scannerImage),
		// The API keeps a time in the local zone of whoever reads it, as metav1.Time decodes it.
		Time:     ptr.To(metav1.NewTime(time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC).Local())),
		Coverage: ptr.To(int32(95)),
	}
}

// ofFinding changes the one finding of the status that the rejection specs start from.
func ofFinding(change func(*inventoryv1alpha1.Finding)) func(*inventoryv1alpha1.ImageVerdictsStatus) {
	return func(status *inventoryv1alpha1.ImageVerdictsStatus) { change(&status.Findings[0]) }
}

// ofEvidence changes the one piece of evidence of the status that the rejection specs start from.
func ofEvidence(change func(*inventoryv1alpha1.SheetEvidence)) func(*inventoryv1alpha1.ImageVerdictsStatus) {
	return func(status *inventoryv1alpha1.ImageVerdictsStatus) { change(&status.Evidence[0]) }
}

// counts returns the counts of a sheet with as many findings of each status.
func counts(affected, underInvestigation, notAffected, fixed int32) *inventoryv1alpha1.FindingCounts {
	return &inventoryv1alpha1.FindingCounts{
		Affected: ptr.To(affected), UnderInvestigation: ptr.To(underInvestigation),
		NotAffected: ptr.To(notAffected), Fixed: ptr.To(fixed),
	}
}

// These specs write the sheets by hand, and check the rules of the schema against the real API server.
// The findings live in the status, so every spec of them goes through the status subresource.
var _ = Describe("ImageVerdicts API", func() {
	It("takes the status through the status subresource, with a finding of each status", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		notAffected := finding()
		notAffected.Status = inventoryv1alpha1.VEXStatusNotAffected
		notAffected.Rule = ptr.To(removedRule)
		notAffected.Justification = ptr.To(inventoryv1alpha1.VEXJustificationComponentNotPresent)
		notAffected.Conditions = []inventoryv1alpha1.FindingCondition{inventoryv1alpha1.FindingConditionNoPreloadEnvironment}
		held := finding()
		held.Rule = ptr.To(knownExploited)
		held.Reason = ptr.To("known exploited")
		held.KnownExploited = inventoryv1alpha1.KnownExploitedListed
		held.FixedVersions = []string{"1.1.0-r3", "1.2.0-r0"}
		held.CVSS = []inventoryv1alpha1.CVSS{{Version: ptr.To("3.1"), Vector: ptr.To("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")}}
		held.StatusNotes = []inventoryv1alpha1.StatusNote{{Rule: loadCheck, Text: "reached by /usr/bin/curl"}}
		affected := finding()
		affected.Status = inventoryv1alpha1.VEXStatusAffected
		affected.Rule = ptr.To("reached-and-exploitable")
		fixed := finding()
		fixed.Status = inventoryv1alpha1.VEXStatusFixed
		fixed.Rule = ptr.To("backported-fix")
		status := inventoryv1alpha1.ImageVerdictsStatus{
			Playbook:        ptr.To(playbookName),
			FindingsVersion: ptr.To("db-2026-10-30"),
			Evidence:        []inventoryv1alpha1.SheetEvidence{contents()},
			Findings:        []inventoryv1alpha1.Finding{affected, held, fixed, notAffected},
			OmittedFindings: ptr.To[int32](0),
			Counts:          counts(1, 1, 1, 1),
		}
		sheet.Status = status

		Expect(k8sClient.Status().Update(ctx, sheet)).To(Succeed())

		var got inventoryv1alpha1.ImageVerdicts
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sheet), &got)).To(Succeed())
		Expect(got.Status).To(Equal(status))
	})

	// The enums are open: a later version may add values, and this one refuses the values it doesn't
	// know. The names are the contract, so the spec spells each of them out.
	It("accepts every value of the enums", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		var findings []inventoryv1alpha1.Finding
		with := func(change func(*inventoryv1alpha1.Finding)) {
			f := finding()
			change(&f)
			findings = append(findings, f)
		}
		for _, status := range []inventoryv1alpha1.VEXStatus{"Affected", "UnderInvestigation", "Fixed"} {
			with(func(f *inventoryv1alpha1.Finding) { f.Status = status })
		}
		for _, justification := range []inventoryv1alpha1.VEXJustification{
			"ComponentNotPresent", "VulnerableCodeNotPresent", "VulnerableCodeNotInExecutePath",
			"VulnerableCodeCannotBeControlledByAdversary", "InlineMitigationsAlreadyExist",
		} {
			with(func(f *inventoryv1alpha1.Finding) {
				f.Status = "NotAffected"
				f.Justification = ptr.To(justification)
			})
		}
		with(func(f *inventoryv1alpha1.Finding) {
			f.Conditions = []inventoryv1alpha1.FindingCondition{"NoPreloadEnvironment"}
		})
		for _, severity := range []inventoryv1alpha1.Severity{
			"Critical", "High", "Medium", "Low", "Negligible", "Unknown",
		} {
			with(func(f *inventoryv1alpha1.Finding) { f.Severity = severity })
		}
		for _, fixState := range []inventoryv1alpha1.FixState{"Fixed", "NotFixed", "WontFix", "Unknown"} {
			with(func(f *inventoryv1alpha1.Finding) { f.FixState = fixState })
		}
		for _, exploited := range []inventoryv1alpha1.KnownExploited{"Listed", "NotListed"} {
			with(func(f *inventoryv1alpha1.Finding) { f.KnownExploited = exploited })
		}
		sheet.Status.Findings = findings

		Expect(k8sClient.Status().Update(ctx, sheet)).To(Succeed())
	})

	// A package can lack a version, and a finding for it is still a finding. Only the version may be
	// absent: the ID, the name and the type of a package are always known. A score whose source gave no
	// version or no vector has an empty one.
	It("accepts a finding whose package has no version, and a score with an empty version or vector", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		noVersion := finding()
		noVersion.Package.Version = nil
		noVersion.CVSS = []inventoryv1alpha1.CVSS{
			{Version: ptr.To(""), Vector: ptr.To("AV:N/AC:L/Au:N/C:P/I:P/A:P")}, {Version: ptr.To("4.0"), Vector: ptr.To("")},
		}
		sheet.Status.Findings = []inventoryv1alpha1.Finding{noVersion}

		Expect(k8sClient.Status().Update(ctx, sheet)).To(Succeed())

		var got inventoryv1alpha1.ImageVerdicts
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sheet), &got)).To(Succeed())
		Expect(got.Status.Findings).To(Equal([]inventoryv1alpha1.Finding{noVersion}))
	})

	// Evidence that was missing when the sheet was made has a name, a source and a type, and nothing of
	// what a collector delivers.
	It("accepts evidence that was missing", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		missing := inventoryv1alpha1.SheetEvidence{Name: "contents", Source: "scanner", Type: imageContentsType}
		sheet.Status.Evidence = []inventoryv1alpha1.SheetEvidence{missing}

		Expect(k8sClient.Status().Update(ctx, sheet)).To(Succeed())
	})

	It("holds every field of a finding, and of the status, at its limit", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		largest := finding()
		largest.VulnerabilityID = chars(64)
		largest.Package = inventoryv1alpha1.PackageReference{
			ID: chars(64), Name: chars(253), Version: ptr.To(chars(128)), Type: chars(32),
		}
		largest.Status = inventoryv1alpha1.VEXStatusNotAffected
		largest.Rule = ptr.To(chars(63))
		largest.Justification = ptr.To(inventoryv1alpha1.VEXJustificationComponentNotPresent)
		largest.Conditions = []inventoryv1alpha1.FindingCondition{inventoryv1alpha1.FindingConditionNoPreloadEnvironment}
		largest.Reason = ptr.To(chars(256))
		largest.StatusNotes = slices.Repeat([]inventoryv1alpha1.StatusNote{{Rule: chars(63), Text: chars(256)}}, 4)
		largest.FixedVersions = slices.Repeat([]string{chars(128)}, 8)
		largest.CVSS = slices.Repeat([]inventoryv1alpha1.CVSS{{Version: ptr.To(chars(16)), Vector: ptr.To(chars(256))}}, 4)
		evidence := make([]inventoryv1alpha1.SheetEvidence, 0, 16)
		for i := range 16 {
			e := contents()
			e.Name = "e" + chars(62)[:61] + string(rune('a'+i))
			e.Source = chars(63)
			e.Type = "ch.bedag.vexplain." + chars(226) + ".v1"
			e.Version = ptr.To(chars(128))
			e.Coverage = ptr.To(int32(100))
			evidence = append(evidence, e)
		}
		sheet.Status = inventoryv1alpha1.ImageVerdictsStatus{
			Playbook:        ptr.To(chars(253)),
			FindingsVersion: ptr.To(chars(128)),
			Evidence:        evidence,
			Findings:        []inventoryv1alpha1.Finding{largest},
		}

		Expect(k8sClient.Status().Update(ctx, sheet)).To(Succeed())
	})

	It("holds 2048 findings, and refuses one more", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		sheet.Status.Findings = slices.Repeat([]inventoryv1alpha1.Finding{finding()}, maxFindings+1)

		err := k8sClient.Status().Update(ctx, sheet)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("status.findings: Too many")))

		sheet.Status.Findings = sheet.Status.Findings[:maxFindings]
		Expect(k8sClient.Status().Update(ctx, sheet)).To(Succeed())
	})

	DescribeTable("rejects a status that breaks the schema",
		func(mutate func(*inventoryv1alpha1.ImageVerdictsStatus), message string) {
			sheet := newSheet(newManifestDigest())
			createSheet(sheet)
			sheet.Status.Findings = []inventoryv1alpha1.Finding{finding()}
			sheet.Status.Evidence = []inventoryv1alpha1.SheetEvidence{contents()}
			mutate(&sheet.Status)

			err := k8sClient.Status().Update(ctx, sheet)

			Expect(err).To(Satisfy(apierrors.IsInvalid))
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		// A finding is NotAffected with a justification, and with nothing else.
		Entry("a finding that is NotAffected without a justification",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Status = inventoryv1alpha1.VEXStatusNotAffected }),
			justificationRule),
		Entry("a finding that is UnderInvestigation, with a justification",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.Justification = ptr.To(inventoryv1alpha1.VEXJustificationComponentNotPresent)
			}),
			justificationRule),
		Entry("a finding that is Fixed, with a justification",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.Status = inventoryv1alpha1.VEXStatusFixed
				f.Justification = ptr.To(inventoryv1alpha1.VEXJustificationComponentNotPresent)
			}),
			justificationRule),

		// Values that no enum has.
		Entry("a status that no version knows",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Status = "Suppressed" }),
			`findings[0].status: Unsupported value: "Suppressed"`),
		Entry("a justification that no version knows",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.Status = inventoryv1alpha1.VEXStatusNotAffected
				f.Justification = ptr.To(inventoryv1alpha1.VEXJustification(unknownValue))
			}),
			`findings[0].justification: Unsupported value: "`+unknownValue+`"`),
		Entry("a condition that no version knows",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.Conditions = []inventoryv1alpha1.FindingCondition{unknownValue}
			}),
			`findings[0].conditions[0]: Unsupported value: "`+unknownValue+`"`),
		Entry("a severity that no version knows",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Severity = unknownValue }),
			`findings[0].severity: Unsupported value: "`+unknownValue+`"`),
		Entry("a fix state that no version knows",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.FixState = unknownValue }),
			`findings[0].fixState: Unsupported value: "`+unknownValue+`"`),
		Entry("a known exploitation that no version knows",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.KnownExploited = unknownValue }),
			`findings[0].knownExploited: Unsupported value: "`+unknownValue+`"`),

		// A rule is named as a Rule is: with a DNS-1123 label.
		Entry("a rule that is no DNS-1123 label",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Rule = ptr.To("KnownExploited") }),
			"findings[0].rule: Invalid value"),
		Entry("a note of a rule that is no DNS-1123 label",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.StatusNotes = []inventoryv1alpha1.StatusNote{{Rule: "load_check", Text: "reached"}}
			}),
			"findings[0].statusNotes[0].rule: Invalid value"),

		// What a finding must have.
		Entry("a finding without a vulnerability ID",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.VulnerabilityID = "" }),
			"findings[0].vulnerabilityID: Required value"),
		Entry("a finding without a package",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package = inventoryv1alpha1.PackageReference{} }),
			"findings[0].package: Required value"),
		Entry("a package without an ID",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.ID = "" }),
			"findings[0].package.id: Required value"),
		Entry("a package without a name",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.Name = "" }),
			"findings[0].package.name: Required value"),
		Entry("a package without a type",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.Type = "" }),
			"findings[0].package.type: Required value"),
		Entry("a finding without a status",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Status = "" }),
			"findings[0].status: Required value"),
		Entry("a finding without a severity",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Severity = "" }),
			"findings[0].severity: Required value"),
		Entry("a finding without a fix state",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.FixState = "" }),
			"findings[0].fixState: Required value"),
		Entry("a finding that doesn't say whether it is known to be exploited",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.KnownExploited = "" }),
			"findings[0].knownExploited: Required value"),
		Entry("a note without a text",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.StatusNotes = []inventoryv1alpha1.StatusNote{{Rule: loadCheck}}
			}),
			"findings[0].statusNotes[0].text: Required value"),
		Entry("the same condition twice",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				condition := inventoryv1alpha1.FindingConditionNoPreloadEnvironment
				f.Conditions = []inventoryv1alpha1.FindingCondition{condition, condition}
			}),
			"findings[0].conditions[1]: Duplicate value"),
		Entry("evidence without a name",
			ofEvidence(func(e *inventoryv1alpha1.SheetEvidence) { e.Name = "" }),
			"evidence[0].name: Required value"),
		Entry("the same evidence twice",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) {
				s.Evidence = append(s.Evidence, contents())
			},
			"status.evidence[1]: Duplicate value"),
		Entry("evidence whose name is no CEL identifier",
			ofEvidence(func(e *inventoryv1alpha1.SheetEvidence) { e.Name = "1contents" }),
			"evidence[0].name: Invalid value"),
		Entry("evidence whose type isn't a type",
			ofEvidence(func(e *inventoryv1alpha1.SheetEvidence) { e.Type = "image-contents" }),
			"evidence[0].type: Invalid value"),
		Entry("evidence whose coverage is above 100",
			ofEvidence(func(e *inventoryv1alpha1.SheetEvidence) { e.Coverage = ptr.To(int32(101)) }),
			"evidence[0].coverage: Invalid value"),

		// One beyond each limit.
		Entry("a vulnerability ID of 65 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.VulnerabilityID = chars(65) }),
			"findings[0].vulnerabilityID: Too long"),
		Entry("a package ID of 65 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.ID = chars(65) }),
			"findings[0].package.id: Too long"),
		Entry("a package name of 254 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.Name = chars(254) }),
			"findings[0].package.name: Too long"),
		Entry("a package version of 129 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.Version = ptr.To(chars(129)) }),
			"findings[0].package.version: Too long"),
		Entry("a package type of 33 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.Type = chars(33) }),
			"findings[0].package.type: Too long"),
		Entry("a rule of 64 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Rule = ptr.To(chars(64)) }),
			"findings[0].rule: Too long"),
		Entry("a reason of 257 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Reason = ptr.To(chars(257)) }),
			"findings[0].reason: Too long"),
		Entry("5 status notes",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.StatusNotes = slices.Repeat([]inventoryv1alpha1.StatusNote{{Rule: loadCheck, Text: "reached"}}, 5)
			}),
			"findings[0].statusNotes: Too many"),
		Entry("a note of 257 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.StatusNotes = []inventoryv1alpha1.StatusNote{{Rule: loadCheck, Text: chars(257)}}
			}),
			"findings[0].statusNotes[0].text: Too long"),
		Entry("9 fixed versions",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.FixedVersions = slices.Repeat([]string{"1.0"}, 9) }),
			"findings[0].fixedVersions: Too many"),
		Entry("a fixed version of 129 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.FixedVersions = []string{chars(129)} }),
			"findings[0].fixedVersions[0]: Too long"),
		Entry("5 CVSS scores",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.CVSS = slices.Repeat([]inventoryv1alpha1.CVSS{{Version: ptr.To("3.1"), Vector: ptr.To("AV:N")}}, 5)
			}),
			"findings[0].cvss: Too many"),
		Entry("a CVSS score without its version",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.CVSS = []inventoryv1alpha1.CVSS{{Vector: ptr.To("AV:N")}} }),
			"findings[0].cvss[0].version: Required value"),
		Entry("a CVSS version of 17 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.CVSS = []inventoryv1alpha1.CVSS{{Version: ptr.To(chars(17)), Vector: ptr.To("AV:N")}}
			}),
			"findings[0].cvss[0].version: Too long"),
		Entry("a CVSS vector of 257 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.CVSS = []inventoryv1alpha1.CVSS{{Version: ptr.To("3.1"), Vector: ptr.To(chars(257))}}
			}),
			"findings[0].cvss[0].vector: Too long"),
		Entry("17 pieces of evidence",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) {
				s.Evidence = nil
				for i := range 17 {
					e := contents()
					e.Name = "contents" + string(rune('a'+i))
					s.Evidence = append(s.Evidence, e)
				}
			},
			"status.evidence: Too many"),
		Entry("a collector version of 129 characters",
			ofEvidence(func(e *inventoryv1alpha1.SheetEvidence) { e.Version = ptr.To(chars(129)) }),
			"evidence[0].version: Too long"),
		Entry("a findings version of 129 characters",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.FindingsVersion = ptr.To(chars(129)) },
			"status.findingsVersion: Too long"),
		Entry("a playbook of 254 characters",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Playbook = ptr.To(chars(254)) },
			"status.playbook: Too long"),
		Entry("a negative number of omitted findings",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.OmittedFindings = ptr.To[int32](-1) },
			"status.omittedFindings: Invalid value"),
		Entry("a negative count of findings that are not affected",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Counts = counts(0, 0, -1, 0) },
			"status.counts.notAffected: Invalid value"),
		Entry("counts without the number of fixed findings",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) {
				s.Counts = counts(0, 0, 0, 0)
				s.Counts.Fixed = nil
			},
			"status.counts.fixed: Required value"),
	)

	It("rejects a change of the manifest digest", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)

		// A merge patch carries no resourceVersion, so the API server validates it against the object
		// as it is.
		patch := client.MergeFrom(sheet.DeepCopy())
		sheet.Spec.ManifestDigest = newManifestDigest()
		err := k8sClient.Patch(ctx, sheet, patch)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("manifestDigest is immutable")))
	})

	It("rejects an object whose name is not its manifest digest", func() {
		sheet := newSheet(newManifestDigest())
		sheet.Name = inventory.NameForDigest(newManifestDigest())

		err := k8sClient.Create(ctx, sheet)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("name must be the manifest digest with ':' replaced by '-'")))
	})

	It("rejects a manifest digest that is not a sha256 digest", func() {
		sheet := newSheet("sha256:abc")

		err := k8sClient.Create(ctx, sheet)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("spec.manifestDigest")))
	})
})

// agreeingSheet returns a status whose summary counts what its counts count (decision 0039): of 3 open findings, 2
// that an update fixes and 1 that a rule holds; 4 settled findings; and 3 findings that findings leaves out.
func agreeingSheet() inventoryv1alpha1.ImageVerdictsStatus {
	held := finding()
	held.Rule = ptr.To(knownExploited)
	held.KnownExploited = inventoryv1alpha1.KnownExploitedListed
	return inventoryv1alpha1.ImageVerdictsStatus{
		Playbook:        ptr.To(playbookName),
		FindingsVersion: ptr.To("db-2026-10-30"),
		Evidence:        []inventoryv1alpha1.SheetEvidence{contents()},
		Findings:        []inventoryv1alpha1.Finding{held, finding(), finding()},
		OmittedFindings: ptr.To[int32](3),
		Counts:          counts(1, 2, 3, 1),
		Summary: &inventoryv1alpha1.SheetSummary{
			Open: ptr.To[int32](3), Fixable: ptr.To[int32](2), Held: ptr.To[int32](1), Settled: ptr.To[int32](4),
			Omitted: ptr.To[int32](3),
		},
	}
}

// The summary of a sheet feeds its columns. The hub writes it with the sheet, from the same findings as the counts,
// and the schema holds the two to each other.
var _ = Describe("ImageVerdicts summary", func() {
	It("takes a summary that counts what the counts count", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		status := agreeingSheet()
		sheet.Status = status

		Expect(k8sClient.Status().Update(ctx, sheet)).To(Succeed())

		Expect(sheet.Status).To(Equal(status))
	})

	It("takes a sheet without a summary, which has no verdict yet", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		sheet.Status = inventoryv1alpha1.ImageVerdictsStatus{Playbook: ptr.To(playbookName)}

		Expect(k8sClient.Status().Update(ctx, sheet)).To(Succeed())
	})

	DescribeTable("rejects a summary that breaks the schema",
		func(mutate func(*inventoryv1alpha1.ImageVerdictsStatus), message string) {
			sheet := newSheet(newManifestDigest())
			createSheet(sheet)
			sheet.Status = agreeingSheet()
			mutate(&sheet.Status)

			err := k8sClient.Status().Update(ctx, sheet)

			Expect(err).To(Satisfy(apierrors.IsInvalid))
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		Entry("more fixable findings than open ones",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Summary.Fixable = ptr.To[int32](4) },
			"fixable counts no more findings than open"),
		Entry("more held findings than open ones",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Summary.Held = ptr.To[int32](4) },
			"held counts no more findings than open"),
		Entry("a negative count",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Summary.Settled = ptr.To[int32](-1) },
			"status.summary.settled: Invalid value"),
		Entry("a count left out",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Summary.Held = nil },
			"status.summary.held: Required value"),
		Entry("open findings that the counts don't count",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Summary.Open = ptr.To[int32](4) },
			"the summary counts what counts counts"),
		Entry("settled findings that the counts don't count",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Summary.Settled = ptr.To[int32](3) },
			"the summary counts what counts counts"),
		Entry("a summary without counts",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Counts = nil },
			"the summary counts what counts counts"),
		Entry("findings left out that omittedFindings doesn't count",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.Summary.Omitted = ptr.To[int32](2) },
			"summary.omitted is omittedFindings"),
		Entry("findings left out without omittedFindings",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.OmittedFindings = nil },
			"summary.omitted is omittedFindings"),
	)
})
