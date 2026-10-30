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
	"bytes"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// maxEvidenceBytes is the most evidence that the stores keep in one ImagePackages: 768 KiB. As
// base64 that is exactly 1 MiB, the length that the schema allows for spec.evidence.
const maxEvidenceBytes = 786432

// newPackages returns the ImagePackages of the platform manifest with the digest, as the store
// writes one. The API server checks the size of the evidence and nothing else about it: only the
// store decodes it.
func newPackages(manifestDigest string) *inventoryv1alpha1.ImagePackages {
	return &inventoryv1alpha1.ImagePackages{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(manifestDigest)},
		Spec: inventoryv1alpha1.ImagePackagesSpec{
			ManifestDigest:    manifestDigest,
			Platform:          "linux/amd64",
			ScannerImage:      scannerImage,
			ScannedTime:       ptr.To(metav1.NewTime(time.Now().Truncate(time.Second))),
			Encoding:          inventoryv1alpha1.EvidenceEncodingGzipJSON,
			Evidence:          []byte("evidence"),
			UncompressedBytes: ptr.To[int64](4096),
		},
	}
}

// createPackages creates obj, and deletes it after the spec.
func createPackages(obj *inventoryv1alpha1.ImagePackages) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, obj)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
	})
}

// Nothing in the operator writes an ImagePackages yet, so these specs write the objects by hand, and
// check the rules of the schema against the real API server.
var _ = Describe("ImagePackages API", func() {
	It("stores a package list as it was written", func() {
		obj := newPackages(newManifestDigest())
		createPackages(obj)

		var got inventoryv1alpha1.ImagePackages
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())

		Expect(got.Spec.ScannedTime.Time).To(BeTemporally("==", obj.Spec.ScannedTime.Time))
		got.Spec.ScannedTime, obj.Spec.ScannedTime = nil, nil
		Expect(got.Spec).To(Equal(obj.Spec), "the evidence and every other field come back as written")
	})

	It("is written once: the spec of an existing object can't change", func() {
		obj := newPackages(newManifestDigest())
		createPackages(obj)

		patch := client.MergeFrom(obj.DeepCopy())
		obj.Spec.ScannerImage = "scanner.example/vexplain-scanner:2.0"
		err := k8sClient.Patch(ctx, obj, patch)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring(
			"ImagePackages are written once; replace one by deleting and creating it")))
	})

	It("lets the metadata of an object change, so that only its spec is written once", func() {
		obj := newPackages(newManifestDigest())
		createPackages(obj)

		patch := client.MergeFrom(obj.DeepCopy())
		obj.Labels = map[string]string{"team": "team-a"}

		Expect(k8sClient.Patch(ctx, obj, patch)).To(Succeed())
	})

	It("rejects an object whose name is not its manifest digest", func() {
		obj := newPackages(newManifestDigest())
		obj.Name = inventory.NameForDigest(newManifestDigest())

		err := k8sClient.Create(ctx, obj)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("name must be the manifest digest with ':' replaced by '-'")))
	})

	// MaxEvidenceBytes of the store is 786432, so that the evidence as base64 fits in the 1 MiB that
	// the schema allows, which is below etcd's limit of 1.5 MiB for a request.
	It("holds evidence of 786432 bytes, and refuses one byte more", func() {
		obj := newPackages(newManifestDigest())
		obj.Spec.Evidence = bytes.Repeat([]byte{0xA5}, maxEvidenceBytes+1)

		err := k8sClient.Create(ctx, obj)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("spec.evidence")))

		obj.Spec.Evidence = obj.Spec.Evidence[:maxEvidenceBytes]
		createPackages(obj)
	})

	DescribeTable("rejects a spec that breaks the schema",
		func(mutate func(*inventoryv1alpha1.ImagePackagesSpec), field string) {
			obj := newPackages(newManifestDigest())
			mutate(&obj.Spec)

			err := k8sClient.Create(ctx, obj)

			Expect(err).To(Satisfy(apierrors.IsInvalid))
			Expect(err).To(MatchError(ContainSubstring(field)))
		},
		Entry("a manifest digest that is not a sha256 digest",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.ManifestDigest = "sha256:abc" },
			"spec.manifestDigest"),
		Entry("a manifest digest in upper case",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.ManifestDigest = "sha256:" + strings.Repeat("A", 64) },
			"spec.manifestDigest"),
		Entry("a platform without an architecture",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.Platform = "linux" },
			"spec.platform"),
		Entry("a platform in upper case",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.Platform = "Linux/amd64" },
			"spec.platform"),
		Entry("a platform with two variants",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.Platform = "linux/arm64/v8/v9" },
			"spec.platform"),
		Entry("no scanner image",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.ScannerImage = "" },
			"spec.scannerImage"),
		Entry("a scanner image of 513 characters",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.ScannerImage = chars(513) },
			"spec.scannerImage"),
		Entry("no time of the scan",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.ScannedTime = nil },
			"spec.scannedTime"),
		Entry("an encoding that no version knows",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.Encoding = "Zstd" },
			"spec.encoding"),
		Entry("no evidence",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.Evidence = nil },
			"spec.evidence"),
		Entry("a negative size of the unpacked evidence",
			func(s *inventoryv1alpha1.ImagePackagesSpec) { s.UncompressedBytes = ptr.To[int64](-1) },
			"spec.uncompressedBytes"),
	)
})
