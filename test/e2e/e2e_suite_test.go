//go:build e2e
// +build e2e

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

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bedag/vexplain/test/utils"
)

var (
	// The images that the suite builds from the Dockerfiles of the repository and loads on Kind: the
	// manager, the scanner that the manager's scan Jobs run, and the matcher.
	managerImage = "example.com/vexplain-manager:v0.0.1"
	scannerImage = "example.com/vexplain-scanner:v0.0.1"
	matcherImage = "example.com/vexplain-matcher:v0.0.1"
	// shouldCleanupCertManager tracks whether CertManager was installed by this suite.
	shouldCleanupCertManager = false
)

// registryHost is the address of the local registry, on the host and on the nodes. make setup-test-e2e
// starts the registry, and test/e2e/config tells the scanner where a pod reaches it.
const registryHost = "localhost:5001"

// plantedImages are the names of the images that the specs plant: each is built from
// test/e2e/images/<name> and pushed to the local registry as <registryHost>/<name>.
var plantedImages = []string{"installed-not-linked", "linked"}

// plantedDigests holds the digest of the manifest that the registry holds for each planted image, by
// name. BeforeSuite fills it. An image is pushed as one manifest for one platform, so this digest is
// also the digest of the platform manifest that gets scanned.
var plantedDigests = map[string]string{}

// TestE2E runs the e2e test suite to validate the solution in an isolated environment.
// The default setup requires Kind and CertManager.
//
// To enable kubectl kuberc (use custom kubectl configurations), set: KUBECTL_KUBERC=true
// By default, kuberc is disabled to ensure consistent test behavior across different environments.
// To skip CertManager installation, set: CERT_MANAGER_INSTALL_SKIP=true
//
// make test-e2e starts the Kind cluster with its own kubeconfig and a local registry, which the suite
// needs: run the suite through it.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting vexplain e2e test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	requireKindCluster()
	saveKustomizations()

	// The matcher can't download its database in the cluster, so its image holds one.
	By("building the manager, scanner and matcher images")
	cmd := exec.Command("make", "docker-build",
		fmt.Sprintf("IMG=%s", managerImage), fmt.Sprintf("SCANNER_IMG=%s", scannerImage),
		fmt.Sprintf("MATCHER_IMG=%s", matcherImage), "MATCHER_DB=true")
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the images")

	// TODO(user): If you want to change the e2e test vendor from Kind,
	// ensure the image is built and available, then remove the following block.
	for _, image := range []string{managerImage, scannerImage, matcherImage} {
		By(fmt.Sprintf("loading %s on Kind", image))
		err = utils.LoadImageToKindClusterWithName(image)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load %s into Kind", image)
	}

	// The nodes never pull the images of the specs: they have a pinned tag and the pull policy
	// IfNotPresent, and are loaded here. A node can't pull behind a proxy that it doesn't know.
	for _, image := range []string{nginxImage, curlImage} {
		By(fmt.Sprintf("loading %s on Kind", image))
		ExpectWithOffset(1, pullImageIfMissing(image)).To(Succeed(), "Failed to pull %s", image)
		ExpectWithOffset(1, utils.LoadImageToKindClusterWithName(image)).To(Succeed(),
			"Failed to load %s into Kind", image)
	}

	pushPlantedImages()

	configureKubectlKubeRC()
	setupCertManager()
})

var _ = AfterSuite(func() {
	teardownCertManager()
	restoreKustomizations()
})

// requireKindCluster stops the suite unless kubectl is set to the Kind cluster of these tests, through
// a kubeconfig of its own. The suite installs and removes the operator, and deletes namespaces, so
// it must never run on another cluster, such as the one of a developer's kubeconfig.
func requireKindCluster() {
	ExpectWithOffset(2, os.Getenv("KUBECONFIG")).NotTo(BeEmpty(),
		"KUBECONFIG is not set. Run the suite with make test-e2e, which gives the Kind cluster a kubeconfig of its own")
	current, err := utils.Run(exec.Command("kubectl", "config", "current-context"))
	ExpectWithOffset(2, err).NotTo(HaveOccurred(), "Failed to read the context of kubectl")
	ExpectWithOffset(2, strings.TrimSpace(current)).To(Equal("kind-"+utils.KindCluster()),
		"kubectl is not set to the Kind cluster of the e2e tests")
}

// editedKustomizations are the files that make deploy edits in place, to point the manifests at the images
// of the tests. savedKustomizations holds their content from before the suite.
var (
	editedKustomizations = []string{
		filepath.Join("config", "manager", "kustomization.yaml"),
		filepath.Join("config", "matcher", "kustomization.yaml"),
	}
	savedKustomizations = map[string][]byte{}
)

// saveKustomizations keeps the content of editedKustomizations, so that restoreKustomizations can put it back,
// and a run of the tests doesn't leave the names of its images in the working tree.
func saveKustomizations() {
	projectDir, err := utils.GetProjectDir()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	for _, name := range editedKustomizations {
		content, err := os.ReadFile(filepath.Join(projectDir, name))
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to read %s", name)
		savedKustomizations[name] = content
	}
}

// restoreKustomizations puts back what saveKustomizations kept, if it kept anything.
func restoreKustomizations() {
	projectDir, err := utils.GetProjectDir()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	for name, content := range savedKustomizations {
		err := os.WriteFile(filepath.Join(projectDir, name), content, 0o644)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to restore %s", name)
	}
}

// pushedDigest finds the digest of a pushed manifest in the output of docker push.
var pushedDigest = regexp.MustCompile(`digest: (sha256:[0-9a-f]{64})`)

// pushPlantedImages builds each planted image, pushes it to the local registry, and keeps its digest.
// The images carry neither provenance nor an SBOM attestation: with them the push would make an index,
// whose digest is not the digest of the manifest that gets scanned.
func pushPlantedImages() {
	for _, name := range plantedImages {
		reference := fmt.Sprintf("%s/%s:e2e", registryHost, name)
		By(fmt.Sprintf("building %s", reference))
		cmd := exec.Command("docker", "build", "--provenance=false", "--sbom=false", "-t", reference,
			filepath.Join("test", "e2e", "images", name))
		_, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build %s", reference)

		By(fmt.Sprintf("pushing %s", reference))
		output, err := utils.Run(exec.Command("docker", "push", reference))
		ExpectWithOffset(1, err).NotTo(HaveOccurred(),
			"Failed to push %s. make setup-test-e2e starts the registry", reference)
		found := pushedDigest.FindStringSubmatch(output)
		ExpectWithOffset(1, found).NotTo(BeNil(), "The output of docker push names no digest:\n%s", output)
		plantedDigests[name] = found[1]
	}
}

// pullImageIfMissing pulls an image into the local docker daemon, unless the daemon has it. An image
// that a spec starts in the cluster is loaded with utils.LoadImageToKindClusterWithName, which needs
// it in the daemon first.
func pullImageIfMissing(image string) error {
	if _, err := utils.Run(exec.Command("docker", "image", "inspect", image)); err == nil {
		return nil
	}
	_, err := utils.Run(exec.Command("docker", "pull", image))
	return err
}

// Disable kubectl kuberc by default for test isolation.
// This prevents local kubectl configurations from affecting test behavior.
// To enable kuberc, set: KUBECTL_KUBERC=true
func configureKubectlKubeRC() {
	if os.Getenv("KUBECTL_KUBERC") != "true" {
		By("disabling kubectl kuberc for test isolation")
		err := os.Setenv("KUBECTL_KUBERC", "false")
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to disable kubectl kuberc")
		_, _ = fmt.Fprintf(GinkgoWriter,
			"kubectl kuberc disabled for consistent test behavior (override with KUBECTL_KUBERC=true)\n")
	} else {
		_, _ = fmt.Fprintf(GinkgoWriter, "kubectl kuberc enabled (KUBECTL_KUBERC=true)\n")
	}
}

// setupCertManager installs CertManager if needed for webhook tests.
// Skips installation if CERT_MANAGER_INSTALL_SKIP=true or if already present.
func setupCertManager() {
	if os.Getenv("CERT_MANAGER_INSTALL_SKIP") == "true" {
		_, _ = fmt.Fprintf(GinkgoWriter, "Skipping CertManager installation (CERT_MANAGER_INSTALL_SKIP=true)\n")
		return
	}

	By("checking if CertManager is already installed")
	if utils.IsCertManagerCRDsInstalled() {
		_, _ = fmt.Fprintf(GinkgoWriter, "CertManager is already installed. Skipping installation.\n")
		return
	}

	// Mark for cleanup before installation to handle interruptions and partial installs.
	shouldCleanupCertManager = true

	By("installing CertManager")
	Expect(utils.InstallCertManager()).To(Succeed(), "Failed to install CertManager")
}

// teardownCertManager uninstalls CertManager if it was installed by setupCertManager.
// This ensures we only remove what we installed.
func teardownCertManager() {
	if !shouldCleanupCertManager {
		_, _ = fmt.Fprintf(GinkgoWriter, "Skipping CertManager cleanup (not installed by this suite)\n")
		return
	}

	By("uninstalling CertManager")
	utils.UninstallCertManager()
}
