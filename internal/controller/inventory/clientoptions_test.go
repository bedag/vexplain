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

	cloudevents "github.com/cloudevents/sdk-go/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// scannedPackage is the ID of the one package of the evidence and the sheet.
const scannedPackage = "pkg-1"

// scannedEvent returns the scanner's evidence about the platform manifest, seen at a whole second, as
// an Evidence keeps a time.
func scannedEvent(manifestDigest string) cloudevents.Event {
	GinkgoHelper()
	e, err := sdkevidence.New(imagecontents.Type, subjects.Manifest(manifestDigest), imagecontents.Manifest{
		Platform: "linux/amd64",
		Digest:   manifestDigest,
		Packages: []imagecontents.PackageFacts{{ID: scannedPackage, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1}},
		ELF:      imagecontents.ELFSummary{Total: 1, Owned: 1},
	}, sdkevidence.WithPlatform("linux/amd64"), sdkevidence.WithCoverage(100),
		sdkevidence.WithTime(time.Now().Truncate(time.Second)), sdkevidence.WithSource("/clusters/local/collectors/scanner"))
	Expect(err).NotTo(HaveOccurred())
	return e
}

// resultSheet returns a sheet of one finding, which waits for an assessment.
func resultSheet() inventoryv1alpha1.ImageVerdictsStatus {
	return inventoryv1alpha1.ImageVerdictsStatus{
		Playbook:        ptr.To("container-cves"),
		FindingsVersion: ptr.To("v6.1.0"),
		Findings: []inventoryv1alpha1.Finding{{
			VulnerabilityID: "CVE-2026-0001",
			Package:         inventoryv1alpha1.PackageReference{ID: scannedPackage, Name: "libexample1", Type: "deb"},
			Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
			Severity:        inventoryv1alpha1.SeverityHigh,
			FixState:        inventoryv1alpha1.FixStateUnknown,
			KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
		}},
		Counts: counts(0, 1, 0, 0),
	}
}

// Evidence and sheets are bulky: up to about 1 MiB each. A cache would hold every one of them for
// as long as the operator runs, so the manager's client reads them from the API server, one at a
// time, and the stores watch the evidence through its metadata only.
var _ = Describe("The manager's client", func() {
	It("reads Evidence and ImageVerdicts from the API server, without an informer for them", func() {
		manifestDigest := newManifestDigest()
		cluster := func() string { return localCluster }
		key := evidence.Key{Subject: subjects.Manifest(manifestDigest), Type: imagecontents.Type, Source: scannerSource}
		// Written through the stores, so that the API server checks what they write against the schema.
		scanned := scannedEvent(manifestDigest)
		store := evidence.NewCRDStore(k8sClient, nil, cluster)
		Expect(store.Put(ctx, scannerSource, scannerImage, scanned)).To(Succeed())
		DeferCleanup(func() { Expect(store.DeleteSubject(ctx, key.Subject)).To(Succeed()) })
		verdicts := inventory.NewCRDVerdictsStore(k8sClient, cluster)
		Expect(verdicts.Put(ctx, manifestDigest, playbookName, resultSheet())).To(Succeed())
		DeferCleanup(func() { Expect(verdicts.Delete(ctx, manifestDigest, playbookName)).To(Succeed()) })

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
		managerEvidence := evidence.NewCRDStore(mgr.GetClient(), mgr.GetCache(), cluster)
		record, err := managerEvidence.Get(ctx, key)
		Expect(err).NotTo(HaveOccurred())
		Expect(record).NotTo(BeNil())
		Expect(record.CollectorVersion).To(Equal(scannerImage))
		want, err := json.Marshal(scanned)
		Expect(err).NotTo(HaveOccurred())
		Expect(json.Marshal(record.Event)).To(MatchJSON(want), "the event that was stored")
		records, err := managerEvidence.ListBySubject(ctx, key.Subject)
		Expect(err).NotTo(HaveOccurred())
		Expect(records).To(HaveLen(1))
		managerVerdicts := inventory.NewCRDVerdictsStore(mgr.GetClient(), cluster)
		sheet, err := managerVerdicts.Get(ctx, manifestDigest, playbookName)
		Expect(err).NotTo(HaveOccurred())
		Expect(sheet).NotTo(BeNil())
		Expect(sheet.Status.Findings).To(HaveLen(1))
		sheets, err := managerVerdicts.List(ctx, manifestDigest)
		Expect(err).NotTo(HaveOccurred())
		Expect(sheets).To(HaveLen(1), "the sheets of the manifest, listed by its label")

		By("seeing that the kinds the cache serves still go through it")
		err = mgr.GetClient().Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(manifestDigest)},
			&inventoryv1alpha1.ImageInventory{})
		var notCached *cache.ErrResourceNotCached
		Expect(errors.As(err, &notCached)).To(BeTrue(), "an ImageInventory is read through the cache, got %v", err)
	})
})
