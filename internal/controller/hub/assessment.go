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

package hub

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/conditions"
)

// The agent's verdicts in the sheets, and their statements: the agent workers judge the cases (internal/agent/worker),
// and the hub brings their outcomes into the sheets.

// The reason and the action of the event of a verdict that the hub proposes as a VexStatement.
const (
	reasonVerdictProposed = "VerdictProposed"
	eventActionPropose    = "Propose"
)

// The assessor reads the cases of a manifest, marks an Assessment whose inputs changed stale, proposes a statement for
// each verdict that would silence a case, and says whether each statement stands. It deletes no statement.
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments,verbs=get;list;watch
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments/status,verbs=update
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=vexstatements,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=vexstatements/status,verbs=update

// caseRecords is what the hub holds of the cases of a manifest: their Assessments, sorted by name, their VexStatements,
// by name, the names of the playbooks that can give their case files, and, by the Assessment's name, the hashes of its
// case file's evidence and whether its outcome rests on the case's current inputs. err is why a case file couldn't be
// read.
type caseRecords struct {
	assessments []triagev1alpha1.Assessment
	statements  map[string]*triagev1alpha1.VexStatement
	caseFiles   map[string]bool
	hashes      map[string]map[string][]string
	fresh       map[string]bool
	err         error
}

// casesNow returns the manifest's sheets as they are stored now, by playbook, and reads its cases, as casesOf does,
// against those sheets, each with the evidence that this reconcile read for its playbook, pieces, in place of the
// evidence that it recorded: so the cases rest on the case file's evidence as this reconcile writes it, a new
// producer's included. Evidence whose data isn't JSON, which a sheet records as missing, is hashed as it is, so that
// its verdict isn't fresh. Nor is the verdict of a case whose case file comes from a playbook whose evidence this
// reconcile couldn't read, by unread.
func (a *Assessor) casesNow(ctx context.Context, manifest string, pieces map[string][]piece,
	unread map[string]error) (map[string]*inventoryv1alpha1.ImageVerdicts, *caseRecords, error) {
	listed, err := a.Verdicts.List(ctx, manifest)
	if err != nil {
		return nil, nil, err
	}
	sheets := make(map[string]*inventoryv1alpha1.ImageVerdicts, len(listed))
	now := make(map[string]*inventoryv1alpha1.ImageVerdicts, len(listed))
	for i := range listed {
		sheet := &listed[i]
		sheets[sheet.Spec.Playbook] = sheet
		if read, ok := pieces[sheet.Spec.Playbook]; ok {
			sheet = ptr.To(*sheet) // the stored sheet keeps the evidence that it recorded
			sheet.Status.Evidence = make([]inventoryv1alpha1.SheetEvidence, 0, len(read))
			for _, p := range read {
				sheet.Status.Evidence = append(sheet.Status.Evidence, p.entry)
			}
		}
		now[sheet.Spec.Playbook] = sheet
	}
	records, err := a.casesOf(ctx, manifest, now, unread)
	return sheets, records, err
}

// digestOfCase returns the digest of the platform manifest that a case's subject names, and "" for another subject.
func digestOfCase(subject triagev1alpha1.AssessmentSubject) string {
	if subject.ContainerImage == nil {
		return ""
	}
	return subject.ContainerImage.Digest
}

// casesOf reads the Assessments and the VexStatements of the manifest's cases, by its digest label, and whether the
// outcome of each is fresh, from sheets, the manifest's sheets by playbook: once for the reconcile, so that every sheet
// of the manifest rests on it, also one that doesn't read the case file's evidence. A case file that can't be read
// leaves its outcome stale, which shows nowhere, and the reconcile fails, so that it is tried again. So does one whose
// playbook's evidence couldn't be read, by unread, whose sheet records evidence that may be gone.
func (a *Assessor) casesOf(ctx context.Context, manifest string, sheets map[string]*inventoryv1alpha1.ImageVerdicts,
	unread map[string]error) (*caseRecords, error) {
	label := client.MatchingLabels{cases.DigestLabel: cases.Labels("", manifest)[cases.DigestLabel]}
	var assessments triagev1alpha1.AssessmentList
	if err := a.Client.List(ctx, &assessments, label); err != nil {
		return nil, fmt.Errorf("list the Assessments of manifest %s: %w", manifest, err)
	}
	var statements triagev1alpha1.VexStatementList
	if err := a.Client.List(ctx, &statements, label); err != nil {
		return nil, fmt.Errorf("list the VexStatements of manifest %s: %w", manifest, err)
	}
	r := &caseRecords{statements: map[string]*triagev1alpha1.VexStatement{}, caseFiles: map[string]bool{},
		hashes: map[string]map[string][]string{}, fresh: map[string]bool{}}
	for _, as := range assessments.Items {
		if digestOfCase(as.Spec.Subject) == manifest {
			r.assessments = append(r.assessments, as)
		}
	}
	slices.SortFunc(r.assessments, func(x, y triagev1alpha1.Assessment) int { return strings.Compare(x.Name, y.Name) })
	for i := range statements.Items {
		if s := &statements.Items[i]; digestOfCase(s.Spec.Subject) == manifest {
			r.statements[s.Name] = s
		}
	}
	memo := map[string]map[string][]string{}
	var errs []error
	for i := range r.assessments {
		as := &r.assessments[i]
		for _, name := range append([]string{ptr.Deref(as.Status.CaseFilePlaybook, "")}, as.Status.Playbooks...) {
			if name != "" {
				r.caseFiles[name] = true
			}
		}
		if as.Status.InputHash == nil || as.Status.Verdict == nil && as.Status.NoVerdict == nil {
			continue
		}
		caseFile, hashes, err := a.caseFile(ctx, as, sheets, memo)
		if err != nil {
			errs = append(errs, fmt.Errorf("read the case file of the Assessment %q: %w", as.Name, err))
			continue
		}
		r.hashes[as.Name] = hashes
		r.fresh[as.Name] = caseFile != nil && unread[caseFile.Spec.Playbook] == nil &&
			cases.InputHash(ofVulnerability(caseFile.Status.Findings, as.Spec.VulnerabilityID), hashes) == *as.Status.InputHash
	}
	r.err = errors.Join(errs...)
	return r, nil
}

// basis says what of the cases a sheet rests on: each verdict, and whether it is fresh, and each statement, by its UID,
// with its review, so that a statement deleted and made again under its name shows too.
func (r *caseRecords) basis() string {
	var parts []string
	for i := range r.assessments {
		as := &r.assessments[i]
		if v := as.Status.Verdict; v != nil {
			parts = append(parts, fmt.Sprintf("%s=%s/%s@%s|%t", as.Name, v.Status, ptr.Deref(v.Justification, ""),
				ptr.Deref(as.Status.InputHash, ""), r.fresh[as.Name]))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(r.statements)) {
		s := r.statements[name]
		parts = append(parts, fmt.Sprintf("%s(%s)~%s", name, s.UID, reviewStateOf(s)))
	}
	return strings.Join(parts, ",")
}

// agentVerdicts returns, by vulnerability, the verdict of each case whose findings are among findings, the findings of
// the sheet that is written now, as rules.WithAgent takes them: only a fresh verdict, whose inputHash is that of the
// case's findings in its case file and of the case file's data, as this reconcile writes them, and that of the case's
// findings in this sheet with the same data too. So no sheet settles a finding with a verdict whose package or case
// file moved, not even for one write. A stale verdict, or one whose case file couldn't be read, shows nowhere.
func agentVerdicts(r *caseRecords, findings []inventoryv1alpha1.Finding) map[string]inventoryv1alpha1.AgentVerdict {
	if r == nil {
		return nil
	}
	out := map[string]inventoryv1alpha1.AgentVerdict{}
	for i := range r.assessments {
		as := &r.assessments[i]
		v, mine := as.Status.Verdict, ofVulnerability(findings, as.Spec.VulnerabilityID)
		// A not affected that names no justification is none that a sheet or a statement can hold.
		if v == nil || len(mine) == 0 || !r.fresh[as.Name] ||
			v.Status == triagev1alpha1.VEXStatusNotAffected && v.Justification == nil ||
			cases.InputHash(mine, r.hashes[as.Name]) != *as.Status.InputHash {
			continue
		}
		out[as.Spec.VulnerabilityID] = agentVerdictOf(as, r.statements)
	}
	return out
}

// ofVulnerability returns the findings of the vulnerability: those of its case.
func ofVulnerability(findings []inventoryv1alpha1.Finding, id string) []inventoryv1alpha1.Finding {
	var out []inventoryv1alpha1.Finding
	for _, f := range findings {
		if f.VulnerabilityID == id {
			out = append(out, f)
		}
	}
	return out
}

// caseFile returns the sheet whose evidence the case file of the Assessment's case holds, and the hashes of that
// evidence's data now, as an investigation computes them: the sheet of its case-file playbook, or, when that can't give
// the case file, of the first playbook that selected the case that can, as the agent picks it. It returns a nil sheet
// when no playbook can. memo keeps the hashes of each playbook's case file.
func (a *Assessor) caseFile(ctx context.Context, as *triagev1alpha1.Assessment,
	sheets map[string]*inventoryv1alpha1.ImageVerdicts, memo map[string]map[string][]string) (
	*inventoryv1alpha1.ImageVerdicts, map[string][]string, error) {
	for _, name := range append([]string{ptr.Deref(as.Status.CaseFilePlaybook, "")}, as.Status.Playbooks...) {
		sheet := sheets[name]
		if sheet == nil {
			continue
		}
		if hashes, seen := memo[name]; seen {
			return sheet, hashes, nil
		}
		var playbook configv1alpha1.Playbook
		if err := a.Client.Get(ctx, client.ObjectKey{Name: name}, &playbook); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, nil, err
		}
		if playbook.Spec.Agent == nil {
			continue
		}
		hashes, err := cases.EvidenceHashes(ctx, a.Evidence, sheet, playbook.Spec.Agent.Evidence)
		if err != nil {
			return nil, nil, err
		}
		memo[name] = hashes
		return sheet, hashes, nil
	}
	return nil, nil, nil
}

// agentVerdictOf returns the Assessment's verdict as a sheet names it: its status and justification, and, for a
// NotAffected or Fixed verdict, its statement and that statement's review, Proposed until it stands on the verdict.
func agentVerdictOf(as *triagev1alpha1.Assessment,
	statements map[string]*triagev1alpha1.VexStatement) inventoryv1alpha1.AgentVerdict {
	v := as.Status.Verdict
	out := inventoryv1alpha1.AgentVerdict{Assessment: as.Name, Status: inventoryv1alpha1.VEXStatus(v.Status)}
	if v.Status == triagev1alpha1.VEXStatusNotAffected {
		out.Justification = ptr.To(inventoryv1alpha1.VEXJustification(*v.Justification))
	}
	if cases.Silences(as) {
		name, review := cases.StatementNameOf(as), inventoryv1alpha1.ReviewStateProposed
		if s := statements[name]; standsOn(s, as) {
			review = inventoryv1alpha1.ReviewState(reviewStateOf(s))
		}
		out.Review, out.Statement = &review, &name
	}
	return out
}

// standsOn reports whether the statement states the Assessment's verdict, on the inputs that the verdict rests on.
func standsOn(s *triagev1alpha1.VexStatement, as *triagev1alpha1.Assessment) bool {
	v := as.Status.Verdict
	return s != nil && v != nil && as.Status.InputHash != nil && s.Spec.AssessmentRef.Name == as.Name &&
		s.Spec.Status == v.Status && ptr.Equal(s.Spec.Justification, v.Justification) &&
		s.Spec.InputHash == *as.Status.InputHash
}

// reviewStateOf returns the review state of the statement: Proposed until a person reviews it.
func reviewStateOf(s *triagev1alpha1.VexStatement) triagev1alpha1.ReviewState {
	if s.Spec.Review == nil {
		return triagev1alpha1.ReviewStateProposed
	}
	return ptr.Deref(s.Spec.Review.State, triagev1alpha1.ReviewStateProposed)
}

// reviewCases keeps the cases of the manifest in step with their inputs, once its sheets are written (design of the
// agent on image cases, 5.4 and 5.10):
//   - an Assessment whose outcome no longer rests on its case's current inputs is Stale, Ready=False, unless the queue
//     holds it, Queued or Judging: the next investigation that selects the case has it judged again. One whose inputs
//     are those of its outcome again is Judged again;
//   - a fresh NotAffected or Fixed verdict is proposed as a VexStatement of its own, in Proposed, with the event
//     VerdictProposed on the Assessment;
//   - every other statement of the manifest says whether it stands: it is Superseded once its case's inputs changed, or
//     its Assessment holds another verdict, or none. It stays, with its review: a labelled data point.
//
// It reads the sheets as they are now, and computes what each case rests on as an investigation does. The statements
// of a case whose case file can't be read keep their standing, which the retry decides.
func (a *Assessor) reviewCases(ctx context.Context, manifest string, r *caseRecords) error {
	if len(r.assessments) == 0 && len(r.statements) == 0 {
		return nil
	}
	listed, err := a.Verdicts.List(ctx, manifest)
	if err != nil {
		return err
	}
	sheets := make(map[string]*inventoryv1alpha1.ImageVerdicts, len(listed))
	for i := range listed {
		sheets[listed[i].Spec.Playbook] = &listed[i]
	}
	memo := map[string]map[string][]string{}
	standing, proposed, unread := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var errs []error
	for i := range r.assessments {
		as := &r.assessments[i]
		if as.Status.Verdict == nil && as.Status.NoVerdict == nil {
			continue
		}
		caseFile, hashes, err := a.caseFile(ctx, as, sheets, memo)
		if err != nil {
			errs, unread[as.Name] = append(errs, err), true
			continue
		}
		fresh := caseFile != nil && as.Status.InputHash != nil &&
			cases.InputHash(ofVulnerability(caseFile.Status.Findings, as.Spec.VulnerabilityID), hashes) == *as.Status.InputHash
		errs = append(errs, a.markStale(ctx, as.Name, !fresh))
		if !fresh || !cases.Silences(as) {
			continue
		}
		name := cases.StatementNameOf(as)
		if standsOn(r.statements[name], as) {
			standing[name] = true
		} else {
			proposed[name] = true
			errs = append(errs, a.propose(ctx, as, name))
		}
	}
	for name, s := range r.statements {
		if !proposed[name] && !unread[s.Spec.AssessmentRef.Name] {
			errs = append(errs, a.setStands(ctx, s, standing[name]))
		}
	}
	return errors.Join(errs...)
}

// markStale marks the Assessment of the name Stale, Ready=False, when its outcome is stale, and Judged again when it
// isn't and was marked so, unless the queue holds it, Queued or Judging: the agent's next write decides then. Its
// update carries the version that it read, so it never overwrites a newer condition.
func (a *Assessor) markStale(ctx context.Context, name string, stale bool) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var obj triagev1alpha1.Assessment
		if err := a.Client.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
			return err
		}
		ready := meta.FindStatusCondition(obj.Status.Conditions, configv1alpha1.ConditionReady)
		if isHeld(&obj) || stale == (ready != nil && ready.Reason == triagev1alpha1.ReasonStale) {
			return nil
		}
		condition := metav1.Condition{Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonStale,
			Message: "The case's findings or the data of its case file changed since its outcome: the next investigation " +
				"that selects it has it judged again.", ObservedGeneration: obj.Generation}
		if !stale {
			condition = metav1.Condition{Status: metav1.ConditionTrue, Reason: triagev1alpha1.ReasonJudged,
				Message: "The case's inputs are those of its outcome again.", ObservedGeneration: obj.Generation}
		}
		conditions.SetReady(&obj.Status.Conditions, condition, conditions.None)
		conditions.Observe(&obj.Status.ObservedGeneration, obj.Generation)
		return a.Client.Status().Update(ctx, &obj)
	})
	return client.IgnoreNotFound(err)
}

// propose proposes the Assessment's verdict as the VexStatement of the name, its own, in Proposed. An earlier verdict's
// statement stays, with its review.
func (a *Assessor) propose(ctx context.Context, as *triagev1alpha1.Assessment, name string) error {
	v := as.Status.Verdict
	s := &triagev1alpha1.VexStatement{
		ObjectMeta: metav1.ObjectMeta{Name: name,
			Labels: cases.Labels(as.Spec.VulnerabilityID, digestOfCase(as.Spec.Subject))},
		Spec: triagev1alpha1.VexStatementSpec{Subject: *as.Spec.Subject.DeepCopy(), VulnerabilityID: as.Spec.VulnerabilityID,
			Status: v.Status, Origin: triagev1alpha1.StatementOriginAgent,
			AssessmentRef: triagev1alpha1.AssessmentReference{Name: as.Name}, InputHash: *as.Status.InputHash,
			Review: &triagev1alpha1.VexStatementReview{State: ptr.To(triagev1alpha1.ReviewStateProposed)}},
	}
	if v.Status == triagev1alpha1.VEXStatusNotAffected {
		s.Spec.Justification = ptr.To(*v.Justification)
	}
	if err := a.Client.Create(ctx, s); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil // the cache didn't show it yet: its event brings the manifest back
		}
		return fmt.Errorf("propose the VexStatement %q: %w", s.Name, err)
	}
	a.Recorder.Eventf(as, nil, corev1.EventTypeNormal, reasonVerdictProposed, eventActionPropose,
		"The agent's verdict %s is proposed as the VexStatement %s, for a person to review: until one accepts it, it "+
			"settles nothing.", v.Status, s.Name)
	return nil
}

// setStands writes whether the statement stands: Superseded False and Ready True while it does, and else Superseded
// True and Ready False, with the reason Stale.
func (a *Assessor) setStands(ctx context.Context, s *triagev1alpha1.VexStatement, stands bool) error {
	obj := s.DeepCopy()
	superseded := metav1.Condition{Type: triagev1alpha1.ConditionSuperseded, Status: metav1.ConditionTrue,
		Reason: triagev1alpha1.ReasonStale, Message: "The case's inputs changed since the statement, or its Assessment " +
			"holds another verdict, or none: the statement settles nothing.", ObservedGeneration: obj.Generation}
	ready := metav1.Condition{Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonStale,
		Message: "The statement is superseded.", ObservedGeneration: obj.Generation}
	if stands {
		superseded.Status, superseded.Reason = metav1.ConditionFalse, triagev1alpha1.ReasonCurrent
		superseded.Message = "The statement stands on its case's current inputs and on its Assessment's verdict."
		ready.Status, ready.Reason = metav1.ConditionTrue, triagev1alpha1.ReasonCurrent
		ready.Message = "The statement stands."
	}
	changed := meta.SetStatusCondition(&obj.Status.Conditions, superseded)
	changed = conditions.SetReady(&obj.Status.Conditions, ready, conditions.None) || changed
	changed = conditions.Observe(&obj.Status.ObservedGeneration, obj.Generation) || changed
	if !changed {
		return nil
	}
	return client.IgnoreNotFound(a.Client.Status().Update(ctx, obj))
}
