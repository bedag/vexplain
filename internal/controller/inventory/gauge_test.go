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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// The manager counts the images that run in this cluster in vexplain_images_running, from the
// entries of this cluster's ID, under the name that the OperatorConfig gives the cluster, which it
// follows. The entries keep their former name until the spoke's presence writes them again.
var _ = Describe("The gauge of running images", func() {
	It("counts the images of this cluster's entries, under the cluster's name, and follows a rename", func() {
		observeHere(newDigest())
		Eventually(gaugeOnlyFor(localCluster), reaction, poll).Should(Succeed())

		configure(configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(renamedCluster)})

		Eventually(gaugeOnlyFor(renamedCluster), reaction, poll).Should(Succeed())
	})
})
