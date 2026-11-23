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
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

// investigationCount numbers the investigations that the specs create.
var investigationCount int

// investigation returns an Investigation that the schema accepts, with the spec changed by change.
func investigation(change func(*triagev1alpha1.InvestigationSpec)) *triagev1alpha1.Investigation {
	investigationCount++
	obj := &triagev1alpha1.Investigation{
		ObjectMeta: metav1.ObjectMeta{Namespace: workloadNamespace, Name: fmt.Sprintf("cves-%03d", investigationCount)},
		Spec: triagev1alpha1.InvestigationSpec{
			PlaybookRef: triagev1alpha1.PlaybookReference{Name: "container-cves"},
			Agent:       triagev1alpha1.InvestigationAgent{MaxCases: 50},
		},
	}
	if change != nil {
		change(&obj.Spec)
	}
	return obj
}

// create creates the object, and deletes it after the spec.
func create(obj client.Object) error {
	err := k8sClient.Create(ctx, obj)
	if err == nil {
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed()) })
	}
	return err
}

var _ = Describe("The Investigation schema", func() {
	It("requires agent, and its maxCases, from 1 to 1000", func() {
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Agent = triagev1alpha1.InvestigationAgent{} }))).
			To(refusedWith("spec.agent"))
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) {
			s.Agent = triagev1alpha1.InvestigationAgent{Guidance: ptr.To("Check the module.")}
		}))).To(refusedWith("spec.agent.maxCases"))
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Agent.MaxCases = -1 }))).To(refusedWith("maxCases"))
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Agent.MaxCases = 1001 }))).To(refusedWith("maxCases"))
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Agent.MaxCases = 1 }))).To(Succeed())
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Agent.MaxCases = 1000 }))).To(Succeed())
	})

	It("takes at most 100 vulnerabilities and 16 conditions", func() {
		ids := func(n int) []string {
			out := make([]string, 0, n)
			for i := range n {
				out = append(out, fmt.Sprintf("CVE-2026-%04d", i))
			}
			return out
		}
		conds := func(n int) []triagev1alpha1.MatchCondition {
			out := make([]triagev1alpha1.MatchCondition, 0, n)
			for i := range n {
				out = append(out, triagev1alpha1.MatchCondition{Name: fmt.Sprintf("c-%d", i), Expression: "true"})
			}
			return out
		}
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Vulnerabilities = ids(100) }))).To(Succeed())
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Vulnerabilities = ids(101) }))).
			To(refusedWith("vulnerabilities"))
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.MatchConditions = conds(16) }))).To(Succeed())
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.MatchConditions = conds(17) }))).
			To(refusedWith("matchConditions"))
	})

	It("takes a schedule exactly for a Schedule trigger, of five fields", func() {
		trigger := func(t triagev1alpha1.InvestigationTriggerType, schedule *string) func(*triagev1alpha1.InvestigationSpec) {
			return func(s *triagev1alpha1.InvestigationSpec) {
				s.Trigger = &triagev1alpha1.InvestigationTrigger{Type: t, Schedule: schedule}
			}
		}
		Expect(create(investigation(trigger(triagev1alpha1.InvestigationTriggerSchedule, ptr.To("0 6 * * 1"))))).To(Succeed())
		Expect(create(investigation(trigger(triagev1alpha1.InvestigationTriggerSchedule, nil)))).To(refusedWith("schedule"))
		Expect(create(investigation(trigger(triagev1alpha1.InvestigationTriggerOnce, ptr.To("0 6 * * 1"))))).To(refusedWith("schedule"))
		Expect(create(investigation(trigger(triagev1alpha1.InvestigationTriggerSchedule, ptr.To("0 6 * *"))))).To(refusedWith("schedule"))
		Expect(create(investigation(trigger(triagev1alpha1.InvestigationTriggerSchedule, ptr.To("0 6 * * 1 2"))))).To(refusedWith("schedule"))
		Expect(create(investigation(trigger(triagev1alpha1.InvestigationTriggerContinuous, nil)))).To(Succeed())
		Expect(create(investigation(trigger("Sometimes", nil)))).To(refusedWith("type"))
	})

	It("defaults the trigger to Once and the state to Enabled", func() {
		obj := investigation(nil)
		Expect(create(obj)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		Expect(obj.Spec.State).To(HaveValue(Equal(triagev1alpha1.InvestigationStateEnabled)))
		Expect(obj.Spec.Trigger).To(HaveValue(HaveField("Type", triagev1alpha1.InvestigationTriggerOnce)))
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) {
			s.State = ptr.To(triagev1alpha1.InvestigationState(guess))
		}))).To(refusedWith("state"))
	})

	It("defaults judgePolicy to IfStale, and takes only the policies that it knows", func() {
		obj := investigation(nil)
		Expect(create(obj)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		Expect(obj.Spec.Agent.JudgePolicy).To(HaveValue(Equal(triagev1alpha1.InvestigationJudgeIfStale)))
		for _, policy := range []triagev1alpha1.InvestigationJudgePolicy{triagev1alpha1.InvestigationJudgeIfJudgedElsewhere,
			triagev1alpha1.InvestigationJudgeAlways} {
			Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Agent.JudgePolicy = ptr.To(policy) }))).
				To(Succeed())
		}
		Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) {
			s.Agent.JudgePolicy = ptr.To(triagev1alpha1.InvestigationJudgePolicy(guess))
		}))).To(refusedWith("judgePolicy"))
	})

	It("takes judgePolicy IfJudgedElsewhere or Always only with a trigger other than Continuous", func() {
		policy := func(trigger triagev1alpha1.InvestigationTriggerType, p *triagev1alpha1.InvestigationJudgePolicy) func(
			*triagev1alpha1.InvestigationSpec) {
			return func(s *triagev1alpha1.InvestigationSpec) {
				s.Trigger = &triagev1alpha1.InvestigationTrigger{Type: trigger}
				s.Agent.JudgePolicy = p
			}
		}
		for _, p := range []triagev1alpha1.InvestigationJudgePolicy{triagev1alpha1.InvestigationJudgeIfJudgedElsewhere,
			triagev1alpha1.InvestigationJudgeAlways} {
			Expect(create(investigation(policy(triagev1alpha1.InvestigationTriggerContinuous, ptr.To(p))))).
				To(refusedWith("a Continuous run never ends"))
			Expect(create(investigation(policy(triagev1alpha1.InvestigationTriggerOnce, ptr.To(p))))).To(Succeed())
			Expect(create(investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Agent.JudgePolicy = ptr.To(p) }))).
				To(Succeed(), "the trigger defaults to Once")
		}
		Expect(create(investigation(policy(triagev1alpha1.InvestigationTriggerContinuous,
			ptr.To(triagev1alpha1.InvestigationJudgeIfStale))))).To(Succeed())
		Expect(create(investigation(policy(triagev1alpha1.InvestigationTriggerContinuous, nil)))).
			To(Succeed(), "judgePolicy defaults to IfStale")
	})

	It("holds the guidance to 4096 bytes in UTF-8, not to 4096 characters", func() {
		guidance := func(text string) func(*triagev1alpha1.InvestigationSpec) {
			return func(s *triagev1alpha1.InvestigationSpec) { s.Agent.Guidance = ptr.To(text) }
		}
		Expect(create(investigation(guidance(strings.Repeat("a", 4096))))).To(Succeed())
		Expect(create(investigation(guidance(strings.Repeat("a", 4097))))).To(refusedWith("guidance"))
		Expect(create(investigation(guidance(strings.Repeat("ä", 2048))))).To(Succeed())
		Expect(create(investigation(guidance(strings.Repeat("ä", 2049))))).To(refusedWith("guidance is at most 4096 bytes in UTF-8"))
		Expect(create(investigation(guidance("")))).To(refusedWith("guidance"))
	})

	It("keeps the guidance as the investigation was created with it: an update can't change, add or remove it", func() {
		// update retries on a conflict: the manager of the suite writes the investigation's status meanwhile.
		update := func(obj *triagev1alpha1.Investigation, change func(*triagev1alpha1.InvestigationAgent)) error {
			return retry.RetryOnConflict(retry.DefaultRetry, func() error {
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
				change(&obj.Spec.Agent)
				return k8sClient.Update(ctx, obj)
			})
		}
		guide := func(text *string) func(*triagev1alpha1.InvestigationAgent) {
			return func(a *triagev1alpha1.InvestigationAgent) { a.Guidance = text }
		}
		raise := func(a *triagev1alpha1.InvestigationAgent) { a.MaxCases++ }

		with := investigation(func(s *triagev1alpha1.InvestigationSpec) { s.Agent.Guidance = ptr.To("Check the module.") })
		Expect(create(with)).To(Succeed())
		Expect(update(with, guide(ptr.To("Check another module.")))).To(refusedWith("guidance can't change"))
		Expect(update(with, guide(nil))).To(refusedWith("guidance can't change"))
		Expect(update(with, raise)).To(Succeed(), "the rest of spec.agent may change")

		without := investigation(nil)
		Expect(create(without)).To(Succeed())
		Expect(update(without, guide(ptr.To("Check the module.")))).To(refusedWith("guidance can't change"))
		Expect(update(without, raise)).To(Succeed())
	})

	It("prunes a status with skipped cases, and refuses a negative overTheCap", func() {
		obj := investigation(nil)
		Expect(create(obj)).To(Succeed())
		cases := func(overTheCap int64) map[string]any {
			counts := map[string]any{"skipped": int64(1), "overTheCap": overTheCap, "notSelected": int64(0)}
			for _, name := range []string{"total", "queued", "inProgress", "charged", "judged", "reused"} {
				counts[name] = int64(0)
			}
			return counts
		}
		// update retries on a conflict: the manager of the suite writes the investigation's status meanwhile.
		update := func(overTheCap int64) error {
			return retry.RetryOnConflict(retry.DefaultRetry, func() error {
				u := &unstructured.Unstructured{}
				u.SetGroupVersionKind(triagev1alpha1.SchemeGroupVersion.WithKind("Investigation"))
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), u)).To(Succeed())
				Expect(unstructured.SetNestedMap(u.Object, cases(overTheCap), "status", "cases")).To(Succeed())
				return k8sClient.Status().Update(ctx, u)
			})
		}
		Expect(update(-1)).To(refusedWith("overTheCap"))
		Expect(update(2)).To(Succeed())
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(triagev1alpha1.SchemeGroupVersion.WithKind("Investigation"))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), u)).To(Succeed())
		stored, _, err := unstructured.NestedMap(u.Object, "status", "cases")
		Expect(err).NotTo(HaveOccurred())
		Expect(stored).To(HaveKeyWithValue("overTheCap", BeEquivalentTo(2)))
		Expect(stored).NotTo(HaveKey("skipped"))
	})

	It("names each result's highest exposure, of the four that it knows", func() {
		obj := investigation(nil)
		Expect(create(obj)).To(Succeed())
		// update retries on a conflict: the manager of the suite writes the investigation's status meanwhile.
		update := func(exposure triagev1alpha1.SSVCExposure) error {
			return retry.RetryOnConflict(retry.DefaultRetry, func() error {
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
				obj.Status.Results = []triagev1alpha1.InvestigationResult{{Subject: "artifacts.example/team-a/app@" + digestOf(1),
					VulnerabilityID: cve1, Result: triagev1alpha1.InvestigationResultWarn, Severity: triagev1alpha1.SeverityHigh,
					Resources: ptr.To(int32(2)), Exposure: ptr.To(exposure)}}
				return k8sClient.Status().Update(ctx, obj)
			})
		}
		for _, exposure := range []triagev1alpha1.SSVCExposure{triagev1alpha1.SSVCExposureOpen, triagev1alpha1.SSVCExposureUnknown,
			triagev1alpha1.SSVCExposureControlled, triagev1alpha1.SSVCExposureSmall} {
			Expect(update(exposure)).To(Succeed(), string(exposure))
		}
		Expect(update(guess)).To(refusedWith("exposure"))
	})

	It("accepts the sample", func() {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples", "triage_v1alpha1_investigation.yaml"))
		Expect(err).NotTo(HaveOccurred())
		var sample triagev1alpha1.Investigation
		Expect(yaml.UnmarshalStrict(data, &sample)).To(Succeed())
		sample.Namespace = workloadNamespace
		Expect(create(&sample)).To(Succeed())
	})
})
