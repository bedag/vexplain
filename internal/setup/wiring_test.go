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

package setup_test

import (
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/scan/result"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

var _ = Describe("A manager without a scanner image or a matcher", func() {
	It("asks for no scan, and writes no facts", func() {
		repoDigest, imageID := digestOf(1), digestOf(2)
		observeElsewhere(repoDigest, "artifacts.example/team-a/app")
		observeElsewhere(imageID)

		Consistently(func(g Gomega) {
			g.Expect(requests.taken()).To(BeEmpty())
			for _, digest := range []string{repoDigest, imageID} {
				var obj inventoryv1alpha1.ImageInventory
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)).To(Succeed())
				g.Expect(obj.Status.Facts).To(BeNil(), "even an image ID gets no facts")
			}
		}, quiet, poll).Should(Succeed())
	})

	// The install creates the Collector, and the manager creates none, so the spec stands in for the
	// install. The deployer runs every Collector from its package, and the health that phase 2a's scan
	// runner reports in the operator's process no longer shows: the deployer's own health check does.
	It("deploys the Collector named scanner from its package, whatever the scan runner reports", func() {
		scanner := &configv1alpha1.Collector{
			ObjectMeta: metav1.ObjectMeta{Name: "scanner"},
			Spec:       configv1alpha1.CollectorSpec{Package: "scanner.example/vexplain-scanner:1.0"},
		}
		Expect(k8sClient.Create(ctx, scanner)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, scanner))).To(Succeed()) })

		Eventually(func(g Gomega) {
			var d appsv1.Deployment
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: "vexplain-collector-scanner"},
				&d)).To(Succeed())
			g.Expect(d.Spec.Template.Spec.Containers).To(ContainElement(HaveField("Image", scanner.Spec.Package)))
			var got configv1alpha1.Collector
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "scanner"}, &got)).To(Succeed())
			ready := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionUnknown))
			g.Expect(ready.Reason).To(Equal(configv1alpha1.ReasonProgressing), "envtest makes no Deployment available")
		}, startup, poll).Should(Succeed())
	})

	It("writes no sheet, says once that it has no matcher, and runs nothing that could fail again and again", func() {
		manifest := digestOf(101)
		scanned, err := sdkevidence.New(result.EvidenceType, subjects.Manifest(manifest), result.Manifest{
			Platform: "linux/amd64",
			Digest:   manifest,
			SBOM:     json.RawMessage(`{"artifacts":[{"id":"pkg-1","name":"libexample1","version":"1.0-1","type":"deb"}]}`),
			Packages: []result.PackageFacts{{ID: "pkg-1", FilesListed: 1, FilesPresent: 1, SharedLibraries: 1}},
			ELF:      result.ELFSummary{Total: 1, Owned: 1},
		}, sdkevidence.WithPlatform("linux/amd64"), sdkevidence.WithCoverage(100),
			sdkevidence.WithSource("/clusters/local/collectors/scanner"))
		Expect(err).NotTo(HaveOccurred())
		store := evidence.NewCRDStore(k8sClient, nil, func() string { return "local" })
		Expect(store.Put(ctx, "scanner", "scanner.example/vexplain-scanner:1.0", scanned)).To(Succeed())

		Consistently(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(manifest)}, &inventoryv1alpha1.ImageVerdicts{})
		}, quiet, poll).Should(Satisfy(apierrors.IsNotFound))

		logged := suiteLog.String()
		Expect(strings.Count(logged, "No matcher is configured")).To(Equal(1))
		// Each controller logs as it starts. The spoke's presence and the controllers of the rules and
		// the playbooks are among them, and neither of the assessor's is.
		Expect(logged).To(ContainSubstring(`"controller": "spoke-presence"`))
		Expect(logged).To(ContainSubstring(`"controller": "hub-rules"`))
		Expect(logged).To(ContainSubstring(`"controller": "hub-playbooks"`))
		Expect(logged).NotTo(ContainSubstring(`"controller": "hub-assessor"`))
		Expect(logged).NotTo(ContainSubstring(`"controller": "hub-evidence-requests"`))
	})
})

// lookup returns a function that reads the ImageInventory of digest.
func lookup(digest string) func() error {
	return func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &inventoryv1alpha1.ImageInventory{})
	}
}
