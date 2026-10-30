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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/scan/result"
)

var _ = Describe("A manager without a scanner image or a matcher", func() {
	It("asks for no scan, and writes no facts", func() {
		ns := newNamespace("team-a")
		repoDigest, imageID := digestOf(1), digestOf(2)
		runPod(ns, "app-0", "artifacts.example/team-a/app@"+repoDigest)
		runPod(ns, "tool-0", imageID)
		for _, digest := range []string{repoDigest, imageID} {
			Eventually(lookup(digest), startup, poll).Should(Succeed())
		}

		Consistently(func(g Gomega) {
			g.Expect(requests.taken()).To(BeEmpty())
			for _, digest := range []string{repoDigest, imageID} {
				var obj inventoryv1alpha1.ImageInventory
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)).To(Succeed())
				g.Expect(obj.Status.Facts).To(BeNil(), "even an image ID gets no facts")
			}
		}, quiet, poll).Should(Succeed())
	})

	It("has the Scanner Collector report that no scanner image is configured", func() {
		Eventually(func(g Gomega) {
			var scanner configv1alpha1.Collector
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "scanner"}, &scanner)).To(Succeed())
			ready := meta.FindStatusCondition(scanner.Status.Conditions, configv1alpha1.ConditionReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(configv1alpha1.ReasonCollectorFailing))
			g.Expect(ready.Message).To(Equal("no scanner image is configured"))
		}, startup, poll).Should(Succeed())
	})

	It("writes no sheet, says once that it has no matcher, and runs nothing that could fail again and again", func() {
		manifest := digestOf(101)
		packages := inventory.NewCRDPackagesStore(k8sClient, nil, func() string { return "local" })
		Expect(packages.Put(ctx, "scanner.example/vexplain-scanner:1.0", time.Now(), result.Manifest{
			Platform: "linux/amd64",
			Digest:   manifest,
			SBOM:     json.RawMessage(`{"artifacts":[{"id":"pkg-1","name":"libexample1","version":"1.0-1","type":"deb"}]}`),
			Packages: []result.PackageFacts{{ID: "pkg-1", FilesListed: 1, FilesPresent: 1, SharedLibraries: 1}},
			ELF:      result.ELFSummary{Total: 1, Owned: 1},
		})).To(Succeed())

		Consistently(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(manifest)}, &inventoryv1alpha1.ImageVerdicts{})
		}, quiet, poll).Should(Satisfy(apierrors.IsNotFound))

		logged := suiteLog.String()
		Expect(strings.Count(logged, "No matcher is configured")).To(Equal(1))
		// Each controller logs as it starts. The pod inventory is among them, and neither of the hub's
		// controllers is.
		Expect(logged).To(ContainSubstring(`"controller": "podinventory"`))
		Expect(logged).NotTo(ContainSubstring(`"controller": "hub-verdicts"`))
		Expect(logged).NotTo(ContainSubstring(`"controller": "hub-scheduler"`))
	})
})

// lookup returns a function that reads the ImageInventory of digest.
func lookup(digest string) func() error {
	return func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &inventoryv1alpha1.ImageInventory{})
	}
}
