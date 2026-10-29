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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
)

// Ginkgo skips BeforeSuite when a suite has no specs. This spec makes the suite bootstrap its
// environment, so that a broken manager or CRD setup shows up here and not in the first
// controller test.
var _ = Describe("Test environment", func() {
	It("runs the manager with the production wiring and serves the ImageInventory API", func() {
		By("waiting until the manager has started its controllers")
		Eventually(k8sManager.Elected(), time.Minute).Should(BeClosed())

		By("listing ImageInventory objects")
		Expect(k8sClient.List(ctx, &inventoryv1alpha1.ImageInventoryList{})).To(Succeed())
	})
})
