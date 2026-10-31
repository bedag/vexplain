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
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/setup"
)

// scannedPackage is the ID in the SBOM of the one package of the evidence and the sheet.
const scannedPackage = "pkg-1"

// scannedManifest returns the evidence of a scan of the platform manifest.
func scannedManifest(manifestDigest string) result.Manifest {
	return result.Manifest{
		Platform: "linux/amd64",
		Digest:   manifestDigest,
		SBOM:     json.RawMessage(`{"artifacts":[{"id":"pkg-1","name":"libexample1","version":"1.2.3-1","type":"deb"}]}`),
		Packages: []result.PackageFacts{{ID: scannedPackage, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1}},
		ELF:      result.ELFSummary{Total: 1, Owned: 1},
	}
}

// resultSheet returns a sheet of one finding, which waits for an assessment.
func resultSheet() inventoryv1alpha1.ImageVerdictsStatus {
	return inventoryv1alpha1.ImageVerdictsStatus{
		DatabaseVersion: ptr.To("v6.1.0"),
		ScannerImage:    ptr.To(scannerImage),
		Findings: []inventoryv1alpha1.Finding{{
			VulnerabilityID: "CVE-2026-0001",
			Package:         inventoryv1alpha1.PackageReference{ID: scannedPackage, Name: "libexample1", Type: "deb"},
			Outcome:         inventoryv1alpha1.OutcomeNeedsAssessment,
			Severity:        inventoryv1alpha1.SeverityHigh,
			FixState:        inventoryv1alpha1.FixStateUnknown,
		}},
		Counts: &inventoryv1alpha1.FindingCounts{
			Suppressed: ptr.To(int32(0)), Tracked: ptr.To(int32(0)), NeedsAssessment: ptr.To(int32(1)),
		},
	}
}

// Evidence and sheets are bulky: up to about 1 MiB each. A cache would hold every one of them for
// as long as the operator runs, so the manager's client reads them from the API server, one at a
// time, and the stores watch the evidence through its metadata only.
var _ = Describe("The manager's client", func() {
	It("reads ImagePackages and ImageVerdicts from the API server, without an informer for them", func() {
		manifestDigest := newManifestDigest()
		cluster := func() string { return localCluster }
		// Written through the stores, so that the API server checks what they write against the schema.
		packages := inventory.NewCRDPackagesStore(k8sClient, nil, cluster)
		Expect(packages.Put(ctx, scannerImage, time.Now(), scannedManifest(manifestDigest))).To(Succeed())
		DeferCleanup(func() { Expect(packages.Delete(ctx, manifestDigest)).To(Succeed()) })
		verdicts := inventory.NewCRDVerdictsStore(k8sClient, cluster)
		Expect(verdicts.Put(ctx, manifestDigest, resultSheet())).To(Succeed())
		DeferCleanup(func() { Expect(verdicts.Delete(ctx, manifestDigest)).To(Succeed()) })

		By("building a manager as cmd/main.go does, whose cache refuses a read that would start an informer")
		cacheOptions := setup.CacheOptions(operatorNamespace)
		cacheOptions.ReaderFailOnMissingInformer = true
		mgr, err := ctrl.NewManager(k8sManager.GetConfig(), ctrl.Options{
			Scheme:  k8sManager.GetScheme(),
			Cache:   cacheOptions,
			Client:  setup.ClientOptions(),
			Metrics: metricsserver.Options{BindAddress: "0"},
		})
		Expect(err).NotTo(HaveOccurred())

		By("reading the evidence and the sheet through stores over its client and cache")
		managerPackages := inventory.NewCRDPackagesStore(mgr.GetClient(), mgr.GetCache(), cluster)
		manifest, info, err := managerPackages.Get(ctx, manifestDigest)
		Expect(err).NotTo(HaveOccurred())
		Expect(manifest).To(HaveValue(Equal(scannedManifest(manifestDigest))))
		Expect(info.ScannerImage).To(Equal(scannerImage))
		digests, err := managerPackages.Digests(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(digests).To(ContainElement(manifestDigest))
		sheet, err := inventory.NewCRDVerdictsStore(mgr.GetClient(), cluster).Get(ctx, manifestDigest)
		Expect(err).NotTo(HaveOccurred())
		Expect(sheet).NotTo(BeNil())
		Expect(sheet.Status.Findings).To(HaveLen(1))

		By("seeing that the kinds the cache serves still go through it")
		err = mgr.GetClient().Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(manifestDigest)},
			&inventoryv1alpha1.ImageInventory{})
		var notCached *cache.ErrResourceNotCached
		Expect(errors.As(err, &notCached)).To(BeTrue(), "an ImageInventory is read through the cache, got %v", err)
	})
})
