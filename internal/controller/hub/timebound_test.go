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
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These tests cover an evaluation in which a run of a rule passed a bound on time, as in a process that is stalled
// or starved: what the rules conclude then fails closed, so the sheet is written, but it isn't what the evidence
// gives, so the sheet is evaluated again from its findings, without a new match, until an evaluation is complete. The
// bounds of the tests are 0, which every run passes, and the engine's again.

// pastBound returns f as an evaluation makes it in which every run passed its bound of 0: the completeness guard,
// whose name sorts before that of every other rule that holds, holds it open, nothing settles it, and no hint notes
// it.
func pastBound(f inventoryv1alpha1.Finding) inventoryv1alpha1.Finding {
	f.Status = inventoryv1alpha1.VEXStatusUnderInvestigation
	f.Rule = ptr.To(guardRule)
	f.Reason = ptr.To("could not be evaluated: took longer than " + time.Duration(0).String())
	f.Justification = nil
	f.StatusNotes = nil
	return f
}

// evaluatedOf reconciles the Rule of the name on the fake client of f, as the rule controller does with the counts
// of the assessor's evaluations, and returns its Evaluated condition.
func (f *assessorFixture) evaluatedOf(t *testing.T, rule string) *metav1.Condition {
	t.Helper()
	reconciler := &hub.RuleReconciler{Client: f.client, Rules: f.assessor.Rules, Evaluations: f.assessor.Evaluations}
	_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rule}})
	require.NoError(t, err)
	var r configv1alpha1.Rule
	require.NoError(t, f.client.Get(t.Context(), client.ObjectKey{Name: rule}, &r))
	return meta.FindStatusCondition(r.Status.Conditions, configv1alpha1.ConditionEvaluated)
}

// scannedRecordOf reads the scanner's record about manifest from the evidence store of f.
func (f *assessorFixture) scannedRecordOf(t *testing.T, manifest string) *evidence.Record {
	t.Helper()
	record, err := f.evidence.Get(t.Context(), evidence.Key{Subject: subjects.Manifest(manifest), Type: imagecontents.Type, Source: scanner})
	require.NoError(t, err)
	require.NotNil(t, record)
	return record
}

func TestTheAssessorEvaluatesASheetAgainWhenARunPassedABoundOnTime(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, manifest := digestOf(1), digestOf(101)
	f.scanned(t, digest, manifest, evidenceOf(manifest))
	restore := engine.SetBounds(0, time.Hour)
	t.Cleanup(restore)
	evaluations := 0
	hub.WatchBudget(f.assessor, func(_ string, holds bool) {
		if holds {
			evaluations++
		}
	})

	res, err := hub.Assess(f.assessor, t.Context(), manifestRequest(manifest))

	require.ErrorIs(t, err, hub.ErrPassedABound, "the controller reconciles the manifest again, with its back-off")
	require.Equal(t, ctrl.Result{}, res)
	contents := sheetEvidenceOf(f.scannedRecordOf(t, manifest))
	require.Equal(t, sheet(v1, contents, counted{underInvestigation: 3},
		pastBound(otherReached), pastBound(exampleUnreached), pastBound(goneSettled)), &f.sheetOf(t, manifest).Status,
		"the sheet holds what the rules failed closed to: no note, and nothing settled")
	require.Equal(t, metav1.ConditionFalse, f.evaluatedOf(t, loadCheckRule).Status)

	restore()
	res, err = hub.Assess(f.assessor, t.Context(), manifestRequest(manifest))

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res, "a complete evaluation asks for no requeue")
	require.Equal(t, sheet(v1, contents, counted{underInvestigation: 2, notAffected: 1},
		otherReached, exampleUnreached, goneSettled), &f.sheetOf(t, manifest).Status,
		"the notes are back, with the version of the findings of the first match")
	require.Equal(t, 1, f.findings.found(manifest), "the sheet's findings were evaluated again, without a new match")
	require.Equal(t, metav1.ConditionTrue, f.evaluatedOf(t, loadCheckRule).Status)

	res, err = hub.Assess(f.assessor, t.Context(), manifestRequest(manifest))

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	require.Equal(t, 2, evaluations, "a complete evaluation is remembered, and stands until what it rests on changes")
}

var _ = Describe("The assessor, when a run of a rule passes a bound on time", func() {
	It("writes the sheet that the rules failed closed to, and evaluates it again from its findings until the runs keep within their bounds", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		digest, manifest := newDigest(), newDigest()

		By("evaluating the manifest while every run passes its bound, as in a stalled process")
		restore := engine.SetBounds(0, time.Hour)
		DeferCleanup(restore)
		runAndScan(newNamespace(), "app-0", digest, evidenceOf(manifest))
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(sheet(v1, contentsOf(manifest), counted{underInvestigation: 3},
			pastBound(otherReached), pastBound(exampleUnreached), pastBound(goneSettled))))
		evaluated := expectCondition(loadCheckRule, configv1alpha1.ConditionEvaluated, metav1.ConditionFalse,
			configv1alpha1.ReasonEvaluationErrors)
		Expect(evaluated.Message).To(MatchRegexp(`^\d+ findings? couldn't be evaluated in the last evaluations\.$`),
			"a hint that couldn't be evaluated leaves no trace in the sheet, so the message doesn't send the reader there")
		found := findings.found(manifest)

		By("letting the runs keep within their bounds again")
		restore()

		Eventually(statusOf(manifest), reaction, poll).Should(Equal(sheet(v1, contentsOf(manifest),
			counted{underInvestigation: 2, notAffected: 1}, otherReached, exampleUnreached, goneSettled)))
		Expect(findings.found(manifest)).To(Equal(found), "the findings were not asked for again")
		expectCondition(loadCheckRule, configv1alpha1.ConditionEvaluated, metav1.ConditionTrue, configv1alpha1.ReasonNoEvaluationErrors)
	})
})
