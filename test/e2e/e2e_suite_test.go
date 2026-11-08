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

// registryHost is the address of the local registry, on the host and on the nodes. make setup-test-e2e
// starts the registry, and test/e2e/config tells the scanner where a pod reaches it.
const registryHost = "localhost:5001"

var (
	// The images that the suite builds from the Dockerfiles of the repository and loads on Kind: the
	// manager, and the built-in collectors, which the install's Collectors run as their packages.
	managerImage         = "example.com/vexplain-manager:v0.0.1"
	workloadsImage       = "example.com/vexplain-workloads:v0.0.1"
	vulnerabilitiesImage = "example.com/vexplain-vulnerabilities:v0.0.1"
	networkReachImage    = "example.com/vexplain-network-reach:v0.0.1"
	// scannerImage is pushed to the local registry instead. The scanner's scan Jobs run the image of its
	// own pod, by the repository digest that the pod's status reports, and a node finds an image by such
	// a digest only when it pulled the image from a registry: for an image that kind loaded, it reports
	// the digest under a repository that kind makes up, import-<date>, which no registry serves.
	scannerImage = registryHost + "/vexplain-scanner:e2e"
	// scannerPackage names scannerImage by the digest that the registry holds for it, as the install's
	// Collector scanner names it, so that the node of a cluster that outlived an earlier run never runs
	// that run's build under the same tag. BeforeSuite sets it.
	scannerPackage string
	// collectorVersion is the version that the suite builds the collectors at, which each reports in
	// GetInfo, and which their evidence is stored at. It is the one that the Makefile's VERSION takes by
	// default: the commit, as git describe names it. BeforeSuite reads it.
	collectorVersion string
	// shouldCleanupCertManager tracks whether CertManager was installed by this suite.
	shouldCleanupCertManager = false
)

// imageVariables are the variables of make that name the images of the suite, with scanner for the
// scanner's: docker-build builds them, and deploy writes them into the manifests.
func imageVariables(scanner string) []string {
	return []string{
		"IMG=" + managerImage, "WORKLOADS_IMG=" + workloadsImage,
		"SCANNER_IMG=" + scanner, "VULNERABILITIES_IMG=" + vulnerabilitiesImage, "NETWORK_REACH_IMG=" + networkReachImage,
	}
}

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

	// The suite names the version itself, so that the specs know which version each collector must
	// report. Only the standard output is read, so that a warning of git can't become part of it.
	By("reading the version of the commit, as the Makefile's VERSION does")
	projectDir, err := utils.GetProjectDir()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	describe := exec.Command("git", "describe", "--tags", "--always", "--dirty")
	describe.Dir = projectDir
	version, err := describe.Output()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to describe the commit")
	collectorVersion = strings.TrimSpace(string(version))

	// The vulnerabilities collector can't download its database in the cluster, so its image holds one.
	By("building the images of the manager and the collectors")
	cmd := exec.Command("make", append([]string{"docker-build", "VULNERABILITIES_DB=true", "VERSION=" + collectorVersion},
		imageVariables(scannerImage)...)...)
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the images")

	// TODO(user): If you want to change the e2e test vendor from Kind,
	// ensure the image is built and available, then remove the following block.
	for _, image := range []string{managerImage, workloadsImage, vulnerabilitiesImage, networkReachImage} {
		By(fmt.Sprintf("loading %s on Kind", image))
		err = utils.LoadImageToKindClusterWithName(image)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load %s into Kind", image)
	}
	scannerPackage = registryHost + "/vexplain-scanner@" + pushImage(scannerImage)

	// The nodes never pull the images of the specs: they have a pinned tag and the pull policy
	// IfNotPresent, and are loaded here. A node can't pull behind a proxy that it doesn't know.
	for _, image := range []string{nginxImage, curlImage} {
		By(fmt.Sprintf("loading %s on Kind", image))
		ExpectWithOffset(1, loadImageOfSpecs(image)).To(Succeed(), "Failed to load %s into Kind", image)
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
		filepath.Join("config", "collectors", "kustomization.yaml"),
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

		plantedDigests[name] = pushImage(reference)
	}
}

// pushImage pushes the image of the reference to the local registry, and returns the digest of the
// manifest that the registry holds for it.
func pushImage(reference string) string {
	By(fmt.Sprintf("pushing %s", reference))
	output, err := utils.Run(exec.Command("docker", "push", reference))
	ExpectWithOffset(2, err).NotTo(HaveOccurred(),
		"Failed to push %s. make setup-test-e2e starts the registry", reference)
	found := pushedDigest.FindStringSubmatch(output)
	ExpectWithOffset(2, found).NotTo(BeNil(), "The output of docker push names no digest:\n%s", output)
	return found[1]
}

// loadImageOfSpecs loads an image that a spec starts on Kind, and pulls it first unless the docker daemon has it. It
// loads the platform of the nodes alone. kind load docker-image imports every platform that the daemon's archive of
// an image names, and the containerd image store, which a fresh install of Docker 29 uses, keeps the whole list of a
// pulled image although it holds the content of one platform only, so that import fails.
func loadImageOfSpecs(image string) error {
	// The nodes are containers of the daemon, so they run on its platform. Only the standard output is read, so that a
	// warning of docker can't become part of it.
	output, err := exec.Command("docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}").Output()
	if err != nil {
		return fmt.Errorf("reading the platform of the docker daemon: %w", err)
	}
	platform := strings.TrimSpace(string(output))
	if _, err := utils.Run(exec.Command("docker", "image", "inspect", image)); err != nil {
		if _, err := utils.Run(exec.Command("docker", "pull", "--platform", platform, image)); err != nil {
			return err
		}
	}
	dir, err := os.MkdirTemp("", "vexplain-e2e-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	archive := filepath.Join(dir, "image.tar")
	if _, err := utils.Run(exec.Command("docker", "save", "--platform", platform, "--output", archive, image)); err != nil {
		return err
	}
	return utils.LoadImageArchiveToKindClusterWithName(archive)
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
