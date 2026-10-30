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
	// justificationRule is the message of the rule that ties a justification to a suppressed finding.
	justificationRule = "justification is set exactly for a suppressed finding"
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

// finding returns a finding that the schema accepts: a tracked one, which has no justification.
func finding() inventoryv1alpha1.Finding {
	return inventoryv1alpha1.Finding{
		VulnerabilityID: "CVE-2026-0001",
		Package: inventoryv1alpha1.PackageReference{
			ID: "pkg-1", Name: "brotli-libs", Version: "1.1.0-r2", Type: "apk",
		},
		Outcome:  inventoryv1alpha1.OutcomeTracked,
		Severity: inventoryv1alpha1.SeverityHigh,
		FixState: inventoryv1alpha1.FixStateFixed,
	}
}

// ofFinding changes the one finding of the status that the rejection specs start from.
func ofFinding(change func(*inventoryv1alpha1.Finding)) func(*inventoryv1alpha1.ImageVerdictsStatus) {
	return func(status *inventoryv1alpha1.ImageVerdictsStatus) { change(&status.Findings[0]) }
}

// Nothing in the operator writes an ImageVerdicts yet, so these specs write the sheets by hand, and
// check the rules of the schema against the real API server. The findings live in the status, so
// every spec of them goes through the status subresource.
var _ = Describe("ImageVerdicts API", func() {
	It("takes the status through the status subresource, with a finding of each outcome", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		suppressed := finding()
		suppressed.Outcome = inventoryv1alpha1.OutcomeSuppressed
		suppressed.Rule = ptr.To(inventoryv1alpha1.RuleLoadCheck)
		suppressed.Justification = ptr.To(inventoryv1alpha1.JustificationVulnerableCodeNotInExecutePath)
		suppressed.Conditions = []inventoryv1alpha1.FindingCondition{inventoryv1alpha1.FindingConditionNoPreloadEnvironment}
		tracked := finding()
		tracked.Rule = ptr.To(inventoryv1alpha1.RuleKnownExploited)
		tracked.FixedVersions = []string{"1.1.0-r3", "1.2.0-r0"}
		needsAssessment := finding()
		needsAssessment.Outcome = inventoryv1alpha1.OutcomeNeedsAssessment
		needsAssessment.Rule = ptr.To(inventoryv1alpha1.RuleLoadCheck)
		needsAssessment.Reason = ptr.To("reached by /usr/bin/curl")
		status := inventoryv1alpha1.ImageVerdictsStatus{
			DatabaseVersion: ptr.To("db-2026-10-30"),
			ScannerImage:    ptr.To(scannerImage),
			Findings:        []inventoryv1alpha1.Finding{suppressed, tracked, needsAssessment},
			OmittedFindings: ptr.To[int32](0),
			Counts: &inventoryv1alpha1.FindingCounts{
				Suppressed:      ptr.To[int32](1),
				Tracked:         ptr.To[int32](1),
				NeedsAssessment: ptr.To[int32](1),
			},
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
		for _, outcome := range []inventoryv1alpha1.Outcome{"Tracked", "NeedsAssessment"} {
			with(func(f *inventoryv1alpha1.Finding) { f.Outcome = outcome })
		}
		for _, rule := range []inventoryv1alpha1.Rule{
			"KnownExploited", "CompletenessGuard", "RemovedInLaterLayer", "LoadCheck",
		} {
			with(func(f *inventoryv1alpha1.Finding) { f.Rule = ptr.To(rule) })
		}
		for _, justification := range []inventoryv1alpha1.Justification{
			"ComponentNotPresent", "VulnerableCodeNotInExecutePath",
		} {
			with(func(f *inventoryv1alpha1.Finding) {
				f.Outcome = "Suppressed"
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
		sheet.Status.Findings = findings

		Expect(k8sClient.Status().Update(ctx, sheet)).To(Succeed())
	})

	It("holds every field of a finding, and of the status, at its limit", func() {
		sheet := newSheet(newManifestDigest())
		createSheet(sheet)
		largest := finding()
		largest.VulnerabilityID = chars(64)
		largest.Package = inventoryv1alpha1.PackageReference{
			ID: chars(64), Name: chars(253), Version: chars(128), Type: chars(32),
		}
		largest.Outcome = inventoryv1alpha1.OutcomeSuppressed
		largest.Rule = ptr.To(inventoryv1alpha1.RuleLoadCheck)
		largest.Justification = ptr.To(inventoryv1alpha1.JustificationComponentNotPresent)
		largest.Conditions = []inventoryv1alpha1.FindingCondition{inventoryv1alpha1.FindingConditionNoPreloadEnvironment}
		largest.Reason = ptr.To(chars(256))
		largest.FixedVersions = slices.Repeat([]string{chars(128)}, 8)
		sheet.Status = inventoryv1alpha1.ImageVerdictsStatus{
			DatabaseVersion: ptr.To(chars(128)),
			ScannerImage:    ptr.To(chars(512)),
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
			mutate(&sheet.Status)

			err := k8sClient.Status().Update(ctx, sheet)

			Expect(err).To(Satisfy(apierrors.IsInvalid))
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		// A finding is suppressed with a justification, and with nothing else.
		Entry("a suppressed finding without a justification",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Outcome = inventoryv1alpha1.OutcomeSuppressed }),
			justificationRule),
		Entry("a finding that needs assessment, with a justification",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.Outcome = inventoryv1alpha1.OutcomeNeedsAssessment
				f.Justification = ptr.To(inventoryv1alpha1.JustificationComponentNotPresent)
			}),
			justificationRule),
		Entry("a tracked finding with a justification",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.Justification = ptr.To(inventoryv1alpha1.JustificationComponentNotPresent)
			}),
			justificationRule),

		// Values that no enum has.
		Entry("an outcome that no version knows",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Outcome = "Settled" }),
			`findings[0].outcome: Unsupported value: "Settled"`),
		Entry("a rule that no version knows",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Rule = ptr.To(inventoryv1alpha1.Rule(unknownValue)) }),
			`findings[0].rule: Unsupported value: "`+unknownValue+`"`),
		Entry("a justification that no version knows",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				f.Outcome = inventoryv1alpha1.OutcomeSuppressed
				f.Justification = ptr.To(inventoryv1alpha1.Justification(unknownValue))
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

		// What a finding must have, and what a set holds once.
		Entry("a finding without a vulnerability ID",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.VulnerabilityID = "" }),
			"findings[0].vulnerabilityID: Required value"),
		Entry("a finding without a package",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package = inventoryv1alpha1.PackageReference{} }),
			"findings[0].package: Required value"),
		Entry("a package without a version",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.Version = "" }),
			"findings[0].package.version: Required value"),
		Entry("a finding without an outcome",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Outcome = "" }),
			"findings[0].outcome: Required value"),
		Entry("a finding without a severity",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Severity = "" }),
			"findings[0].severity: Required value"),
		Entry("a finding without a fix state",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.FixState = "" }),
			"findings[0].fixState: Required value"),
		Entry("the same condition twice",
			ofFinding(func(f *inventoryv1alpha1.Finding) {
				condition := inventoryv1alpha1.FindingConditionNoPreloadEnvironment
				f.Conditions = []inventoryv1alpha1.FindingCondition{condition, condition}
			}),
			"findings[0].conditions[1]: Duplicate value"),

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
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.Version = chars(129) }),
			"findings[0].package.version: Too long"),
		Entry("a package type of 33 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Package.Type = chars(33) }),
			"findings[0].package.type: Too long"),
		Entry("a reason of 257 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.Reason = ptr.To(chars(257)) }),
			"findings[0].reason: Too long"),
		Entry("9 fixed versions",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.FixedVersions = slices.Repeat([]string{"1.0"}, 9) }),
			"findings[0].fixedVersions: Too many"),
		Entry("a fixed version of 129 characters",
			ofFinding(func(f *inventoryv1alpha1.Finding) { f.FixedVersions = []string{chars(129)} }),
			"findings[0].fixedVersions[0]: Too long"),
		Entry("a database version of 129 characters",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.DatabaseVersion = ptr.To(chars(129)) },
			"status.databaseVersion: Too long"),
		Entry("a scanner image of 513 characters",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.ScannerImage = ptr.To(chars(513)) },
			"status.scannerImage: Too long"),
		Entry("a negative number of omitted findings",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) { s.OmittedFindings = ptr.To[int32](-1) },
			"status.omittedFindings: Invalid value"),
		Entry("a negative count of suppressed findings",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) {
				s.Counts = &inventoryv1alpha1.FindingCounts{
					Suppressed: ptr.To[int32](-1), Tracked: ptr.To[int32](0), NeedsAssessment: ptr.To[int32](0),
				}
			},
			"status.counts.suppressed: Invalid value"),
		Entry("counts without the number of tracked findings",
			func(s *inventoryv1alpha1.ImageVerdictsStatus) {
				s.Counts = &inventoryv1alpha1.FindingCounts{
					Suppressed: ptr.To[int32](0), NeedsAssessment: ptr.To[int32](0),
				}
			},
			"status.counts.tracked: Required value"),
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
