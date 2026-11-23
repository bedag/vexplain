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
	"encoding/json"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/ledger"
)

// fullLedger returns the ledger of a case at its bounds, as the core records it: 50 calls, the most that a profile's
// maxSteps allows, each with arguments and an output far over what an entry keeps, in characters of two bytes.
func fullLedger(name string) *inventoryv1alpha1.Ledger {
	GinkgoHelper()
	l := ledger.New(name, map[string]string{"vexplain.bedag.ch/vulnerability": "CVE-2026-0042"}, 16000)
	query, err := json.Marshal(map[string]string{"name": "sbom", "query": strings.Repeat("é", 5000)})
	Expect(err).NotTo(HaveOccurred())
	for range 50 {
		l.Add("vulnerabilities__describe", query, []byte(strings.Repeat("é", 50000)), ledger.External, time.Second)
	}
	return l.Object()
}

var _ = Describe("Ledger API", func() {
	It("takes the ledger of a case at its bounds", func() {
		l := fullLedger("ledger-api-full")
		Expect(k8sClient.Create(ctx, l)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, l))).To(Succeed()) })

		var read inventoryv1alpha1.Ledger
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(l), &read)).To(Succeed())
		Expect(read.Spec.Entries).To(HaveLen(50))
		Expect(read.Spec.Entries[49].ID).To(Equal("ev-50"))
	})

	DescribeTable("refuses",
		func(change func(*inventoryv1alpha1.LedgerEntry), message string) {
			l := fullLedger("ledger-api-refused")
			l.Spec.Entries = l.Spec.Entries[:1]
			change(&l.Spec.Entries[0])
			err := k8sClient.Create(ctx, l)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%v", err)
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		Entry("an ID that isn't ev- and a number", func(e *inventoryv1alpha1.LedgerEntry) { e.ID = "ev-01" }, "id"),
		Entry("a tool name that a model can't call", func(e *inventoryv1alpha1.LedgerEntry) { e.Tool = "vulnerabilities.describe" },
			"tool"),
		Entry("more shown than the output holds", func(e *inventoryv1alpha1.LedgerEntry) {
			e.ShownBytes = ptr.To(*e.OutputBytes + 1)
		}, "no more is shown than the output holds"),
		Entry("arguments over 4096 characters", func(e *inventoryv1alpha1.LedgerEntry) {
			e.Arguments = ptr.To(strings.Repeat("a", 4097))
		}, "arguments"),
	)
})
