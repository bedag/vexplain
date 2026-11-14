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

package chain_test

import (
	"context"
	"slices"
	"sync"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	"github.com/bedag/vexplain/sdk/collector"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

const (
	// playbookName is the default playbook.
	playbookName = "container-cves"
	// secondContents is the name of a second producer of the contents of a manifest, beside the scanner.
	secondContents = "contents-b"
)

// A producer's health doesn't stop a playbook (decision 0043): it only decides whether the producer is asked for
// work. While the scanner, the only producer of the contents and the SBOM that the default playbook needs, can't be
// used, the playbook stays Ready, and the vulnerabilities collector still matches the stored SBOMs again when its
// database changes, so that a new vulnerability isn't left out for as long as the scanner's outage lasts.
var _ = Describe("The hub, with the production wiring, while the scanner can't be used", func() {
	It("keeps the playbook Ready, and matches every stored SBOM again when the vulnerabilities collector's database "+
		"changes", func() {
		images := []string{digestOf(21), digestOf(22)}
		manifests := map[string]string{images[0]: digestOf(121), images[1]: digestOf(122)}
		scanner := newScannerStandIn(GinkgoT(), func(image string) string { return manifests[image] })
		vulnerabilities := newVulnerabilitiesStandIn(GinkgoT(), v1, libraryMatch)
		awaitForgotten(images...)

		By("installing the scanner, the vulnerabilities collector and the workloads collector, which reports two images")
		install("scanner", scanner)
		install("vulnerabilities", vulnerabilities)
		install("workloads", newWorkloadsStandIn(images...))
		for _, image := range images {
			Eventually(sheetOf(manifests[image]), startup, poll).Should(HaveField("FindingsVersion", HaveValue(Equal(v1))))
		}
		matched := len(vulnerabilities.matched())

		By("giving the scanner settings that its schema refuses, so that it can't be used")
		setSettings("scanner", []byte(`{"maxConcurrentScans": 99}`))
		Eventually(collectorReady("scanner"), startup, poll).Should(And(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", configv1alpha1.ReasonSettingsInvalid),
		))
		Consistently(playbookReady, quiet, poll).Should(HaveField("Status", metav1.ConditionTrue),
			"the playbook stays Ready while the scanner can't be used")

		By("matching every stored SBOM again when the vulnerabilities collector says that its database changed")
		exploited := libraryMatch
		exploited.KnownExploited = true
		vulnerabilities.setDatabase(v2, exploited)
		for _, manifest := range manifests {
			Eventually(sheetOf(manifest), startup, poll).Should(And(
				Not(BeNil()),
				HaveField("FindingsVersion", HaveValue(Equal(v2))),
				HaveField("Findings", ConsistOf(HaveField("KnownExploited", inventoryv1alpha1.KnownExploitedListed))),
			))
		}
		Expect(len(vulnerabilities.matched())).To(BeNumerically(">=", matched+len(manifests)),
			"each manifest was matched again, from its stored SBOM")
	})
})

// playbookReady reads the Ready condition of the default playbook, or nil while it has none.
func playbookReady(g Gomega) *metav1.Condition {
	var playbook configv1alpha1.Playbook
	g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: playbookName}, &playbook)).To(Succeed())
	return meta.FindStatusCondition(playbook.Status.Conditions, configv1alpha1.ConditionReady)
}

// Every producer of a type counts, and the hub asks each for its evidence, also of a type that only the rules read
// (decision 0043): a second producer of the contents of a manifest, beside the scanner, is asked for its contents of
// each image through the spoke, and the sheet rests on the contents of both. A producer whose evidence is current isn't
// asked again.
var _ = Describe("The hub, with the production wiring, with a second producer of the contents", func() {
	It("asks it for its contents of each image, evaluates the contents of both producers, and asks neither again",
		func() {
			image, manifest := digestOf(31), digestOf(131)
			scanner := newScannerStandIn(GinkgoT(), func(string) string { return manifest })
			contents := newContentsStandIn(GinkgoT(), func(string) string { return manifest })
			vulnerabilities := newVulnerabilitiesStandIn(GinkgoT(), v1, libraryMatch)
			awaitForgotten(image)

			By("installing the scanner, the second producer of the contents, the vulnerabilities collector, and the " +
				"workloads collector, which reports an image")
			install("scanner", scanner)
			install(secondContents, contents)
			install("vulnerabilities", vulnerabilities)
			install("workloads", newWorkloadsStandIn(image))

			By("asking the second producer for its contents through the spoke, which stores what it delivers")
			Eventually(contents.inspected, startup, poll).Should(ConsistOf(subjects.Image(image)))
			store := evidence.NewCRDStore(k8sClient, nil, func() string { return "cluster-a" })
			Eventually(func() (*evidence.Record, error) {
				return store.Get(ctx, evidence.Key{Subject: subjects.Manifest(manifest), Type: imagecontents.Type, Source: secondContents})
			}, startup, poll).ShouldNot(BeNil())

			By("writing the sheet from the contents of both producers")
			Eventually(sheetOf(manifest), startup, poll).Should(HaveField("Evidence", ConsistOf(
				And(HaveField("Name", "contents"), HaveField("Source", "scanner"), HaveField("Version", Not(BeNil()))),
				And(HaveField("Name", "contents"), HaveField("Source", secondContents), HaveField("Version", Not(BeNil()))),
				And(HaveField("Name", "sbom"), HaveField("Source", "scanner"), HaveField("Version", Not(BeNil()))),
			)))

			By("asking neither producer again while its evidence is current")
			Consistently(func() int { return len(scanner.scanned()) + len(contents.inspected()) }, quiet, poll).Should(Equal(2),
				"one scan of the image, for both of the scanner's types, and one look of the second producer")
		})
})

// contentsStandIn stands for a second producer of the contents of a manifest beside the scanner, as a checker that an
// admin installs: it takes the spoke role, and its operation inspect produces the scanner's type of contents, which
// only the rules read. It answers with the contents of the platform manifest that manifestOf names for the image, as
// the scanner stand-in finds them.
type contentsStandIn struct {
	caps       collector.Capabilities
	manifestOf func(image string) string

	mu    sync.Mutex
	asked []string
}

// newContentsStandIn returns the stand-in, which declares the contents as the scanner's golden file does, and takes
// the parameters of the scanner's scan.
func newContentsStandIn(t testingT, manifestOf func(image string) string) *contentsStandIn {
	t.Helper()
	scanner := capabilitiesOf(t, scannerCapabilitiesPath)
	i := slices.IndexFunc(scanner.Produces, func(e collector.EvidenceType) bool { return e.Type == imagecontents.Type })
	require.GreaterOrEqual(t, i, 0, "the scanner declares its contents")
	require.NotEmpty(t, scanner.Operations, "the scanner declares its scan")
	return &contentsStandIn{manifestOf: manifestOf, caps: collector.Capabilities{
		Roles:    []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{scanner.Produces[i]},
		Operations: []collector.Operation{{
			Name: "inspect", Description: "Finds the contents of the platform manifests of an image.", Role: collector.RoleSpoke,
			Produces: []string{imagecontents.Type}, ParameterSchema: scanner.Operations[0].ParameterSchema,
		}},
	}}
}

func (s *contentsStandIn) Info() collector.Info {
	return collector.Info{Name: secondContents, Version: standInVersion}
}

func (s *contentsStandIn) Capabilities() collector.Capabilities { return s.caps }

func (s *contentsStandIn) Invoke(_ context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure,
	error) {
	s.mu.Lock()
	s.asked = append(s.asked, req.Subject)
	s.mu.Unlock()
	about, err := subjects.Parse(req.Subject)
	if err != nil {
		return nil, nil, err
	}
	manifest := s.manifestOf(about.Digest)
	contents := imagecontents.Manifest{
		Platform: platform,
		Digest:   manifest,
		Packages: []imagecontents.PackageFacts{{ID: packageID, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1}},
		ELF:      imagecontents.ELFSummary{Total: 1, Owned: 1},
		Libraries: []imagecontents.Library{
			{Path: "/usr/lib/libexample.so.1", Soname: "libexample.so.1", PackageID: packageID},
		},
	}
	e, err := sdkevidence.New(imagecontents.Type, subjects.Manifest(manifest), contents, sdkevidence.WithPlatform(platform),
		sdkevidence.WithCoverage(100), sdkevidence.WithSource("/clusters/"+req.Context.Cluster+"/collectors/"+secondContents))
	if err != nil {
		return nil, nil, err
	}
	return []cloudevents.Event{e}, nil, nil
}

// inspected returns the images that the executor asked the stand-in about so far.
func (s *contentsStandIn) inspected() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.asked)
}
