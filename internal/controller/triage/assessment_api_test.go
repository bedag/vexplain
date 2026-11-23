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

package triage_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

// casePlaybook is the playbook of the cases' case files.
const casePlaybook = "container-cves"

// assessmentCount numbers the assessments that the specs create.
var assessmentCount int

// assessment returns an Assessment of an image's case that the schema accepts.
func assessment() *triagev1alpha1.Assessment {
	assessmentCount++
	return &triagev1alpha1.Assessment{
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("cve-2026-0001-%016x", assessmentCount)},
		Spec: triagev1alpha1.AssessmentSpec{
			Subject: triagev1alpha1.AssessmentSubject{
				Type:           triagev1alpha1.SubjectTypeContainerImage,
				ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: digestOf(assessmentCount)},
			},
			VulnerabilityID: cve1,
		},
	}
}

var _ = Describe("The Assessment schema", func() {
	It("refuses any change of the spec", func() {
		obj := assessment()
		Expect(create(obj)).To(Succeed())

		obj.Spec.VulnerabilityID = cve2
		Expect(k8sClient.Update(ctx, obj)).To(refusedWith("the case of an Assessment can't change"))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		obj.Spec.Subject.ContainerImage.Digest = digestOf(9999)
		Expect(k8sClient.Update(ctx, obj)).To(refusedWith("the case of an Assessment can't change"))
	})

	It("takes a subject by its type: a ContainerImage with its manifest's digest", func() {
		without := assessment()
		without.Spec.Subject.ContainerImage = nil
		Expect(create(without)).To(refusedWith("containerImage"))

		unknown := assessment()
		unknown.Spec.Subject.Type = guess
		Expect(create(unknown)).To(refusedWith("type"))

		bad := assessment()
		bad.Spec.Subject.ContainerImage.Digest = "sha256:abc"
		Expect(create(bad)).To(refusedWith("digest"))
	})

	It("holds a verdict or a no-verdict, never both, with a summary of at most 2048 characters", func() {
		obj := assessment()
		Expect(create(obj)).To(Succeed())
		obj.Status = triagev1alpha1.AssessmentStatus{
			Verdict:          &triagev1alpha1.AssessmentVerdict{Status: triagev1alpha1.VEXStatusAffected, Summary: chars(2048)},
			InputHash:        ptr.To("sha256:" + fmt.Sprintf("%064x", 1)),
			CaseFilePlaybook: ptr.To(casePlaybook),
			Playbooks:        []string{casePlaybook},
		}
		Expect(k8sClient.Status().Update(ctx, obj)).To(Succeed())

		obj.Status.NoVerdict = &triagev1alpha1.AssessmentNoVerdict{Summary: "The step limit came first."}
		Expect(k8sClient.Status().Update(ctx, obj)).To(refusedWith("verdict"))

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		obj.Status.Verdict.Summary = chars(2049)
		Expect(k8sClient.Status().Update(ctx, obj)).To(refusedWith("summary"))
	})

	It("holds a claim only with a queue, and no negative count", func() {
		obj := assessment()
		Expect(create(obj)).To(Succeed())
		now := metav1.Now()
		const uid = "4d5e6f70-1a2b-4c3d-8e9f-a0b1c2d3e4f5"
		ref := triagev1alpha1.InvestigationReference{Namespace: workloadNamespace, Name: "most-urgent", UID: uid}
		request := triagev1alpha1.QueueRequest{InvestigationRef: ref, Trigger: triagev1alpha1.InvestigationTriggerOnce}
		queue := &triagev1alpha1.AssessmentQueue{Playbook: casePlaybook, Requests: []triagev1alpha1.QueueRequest{request},
			Order: triagev1alpha1.QueueOrder{UrgencyRank: ptr.To(int32(1)), KnownExploited: triagev1alpha1.KnownExploitedListed,
				EPSSPermille: ptr.To(int32(950)), Resources: ptr.To(int32(13))},
			QueuedTime: &now, Failures: ptr.To(int32(0)), Misses: ptr.To(int32(0))}
		claim := &triagev1alpha1.QueueClaim{Worker: "vexplain-agent-7d9f4-x2k8q", LeaseEndTime: &now}

		obj.Status = triagev1alpha1.AssessmentStatus{Claim: claim}
		Expect(k8sClient.Status().Update(ctx, obj)).To(refusedWith("a claim needs a queue"))

		obj.Status = triagev1alpha1.AssessmentStatus{Queue: queue, Claim: claim,
			InvestigationRef: &ref}
		Expect(k8sClient.Status().Update(ctx, obj)).To(Succeed())

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		Expect(obj.Status.InvestigationRef).To(Equal(&ref), "the status takes the renamed field")
		Expect(obj.Status.Queue.Requests).To(Equal([]triagev1alpha1.QueueRequest{request}))
		nouid := ref
		nouid.UID = ""
		unreferenced := obj.DeepCopy()
		unreferenced.Status.InvestigationRef = &nouid
		Expect(k8sClient.Status().Update(ctx, unreferenced)).To(refusedWith("uid"), "a reference in the status needs a uid")
		unreferenced = obj.DeepCopy()
		unreferenced.Status.Queue.InvestigationRef = &nouid
		Expect(k8sClient.Status().Update(ctx, unreferenced)).To(refusedWith("uid"), "a reference in the queue needs a uid")
		unreferenced = obj.DeepCopy()
		unreferenced.Status.Queue.Requests = []triagev1alpha1.QueueRequest{{InvestigationRef: nouid,
			Trigger: triagev1alpha1.InvestigationTriggerOnce}}
		Expect(k8sClient.Status().Update(ctx, unreferenced)).To(refusedWith("uid"), "a request needs a uid")
		unreferenced = obj.DeepCopy()
		long := ref
		long.UID = types.UID(chars(37))
		unreferenced.Status.InvestigationRef = &long
		Expect(k8sClient.Status().Update(ctx, unreferenced)).To(refusedWith("uid"), "a uid is at most 36 characters")

		negative := obj.DeepCopy()
		negative.Status.Queue.Failures = ptr.To(int32(-1))
		Expect(k8sClient.Status().Update(ctx, negative)).To(refusedWith("failures"))
	})

	It("holds where a queued case runs: at most 16 groups, each with 8 rules, 8 missing inputs and 5 workloads", func() {
		obj := assessment()
		Expect(create(obj)).To(Succeed())
		now := metav1.Now()
		names := func(prefix string, n int) []string {
			list := make([]string, n)
			for i := range list {
				list[i] = fmt.Sprintf("%s%d", prefix, i)
			}
			return list
		}
		group := triagev1alpha1.ExposureGroup{Exposure: triagev1alpha1.SSVCExposureUnknown, Rules: names("rule-", 8),
			Missing: names("input", 8), Workloads: ptr.To(int32(9)),
			First: []string{"workload/cluster-a/team-a/Deployment.apps/" + chars(512-len("workload/cluster-a/team-a/Deployment.apps/")),
				"b", "c", "d", "e"}}
		runsIn := &triagev1alpha1.QueueRunsIn{HighestExposure: ptr.To(triagev1alpha1.SSVCExposureUnknown),
			HighestUrgency: ptr.To(triagev1alpha1.SSVCOutcomeImmediate), UrgentWorkloads: ptr.To(int32(144))}
		for range 16 {
			runsIn.Exposure = append(runsIn.Exposure, group)
		}
		obj.Status = triagev1alpha1.AssessmentStatus{Queue: &triagev1alpha1.AssessmentQueue{Playbook: casePlaybook,
			Order: triagev1alpha1.QueueOrder{UrgencyRank: ptr.To(int32(1)), KnownExploited: triagev1alpha1.KnownExploitedNotListed,
				Resources: ptr.To(int32(144))}, QueuedTime: &now, RunsIn: runsIn}}
		Expect(k8sClient.Status().Update(ctx, obj)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		Expect(obj.Status.Queue.RunsIn).To(Equal(runsIn))

		for field, change := range map[string]func(*triagev1alpha1.QueueRunsIn){
			"exposure":        func(r *triagev1alpha1.QueueRunsIn) { r.Exposure = append(r.Exposure, group) },
			"rules":           func(r *triagev1alpha1.QueueRunsIn) { r.Exposure[0].Rules = names("rule-", 9) },
			"missing":         func(r *triagev1alpha1.QueueRunsIn) { r.Exposure[0].Missing = names("input", 9) },
			"first":           func(r *triagev1alpha1.QueueRunsIn) { r.Exposure[0].First = names("w", 6) },
			"first[0]":        func(r *triagev1alpha1.QueueRunsIn) { r.Exposure[0].First[0] += "x" },
			"workloads":       func(r *triagev1alpha1.QueueRunsIn) { r.Exposure[0].Workloads = ptr.To(int32(-1)) },
			"urgentWorkloads": func(r *triagev1alpha1.QueueRunsIn) { r.UrgentWorkloads = ptr.To(int32(-1)) },
			"highestExposure": func(r *triagev1alpha1.QueueRunsIn) {
				r.HighestExposure = ptr.To(triagev1alpha1.SSVCExposure(guess))
			},
			"exposure[0].exposure": func(r *triagev1alpha1.QueueRunsIn) { r.Exposure[0].Exposure = guess },
		} {
			refused := obj.DeepCopy()
			change(refused.Status.Queue.RunsIn)
			Expect(k8sClient.Status().Update(ctx, refused)).To(refusedWith(field), field)
		}
	})
})
