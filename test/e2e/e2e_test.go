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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/workloads"
	"github.com/bedag/vexplain/test/utils"
)

// namespace where the project is deployed in
const namespace = "vexplain-system"

// serviceAccountName created for the project
const serviceAccountName = "vexplain-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "vexplain-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "vexplain-metrics-binding"

// The images of the specs. Both have a pinned tag, and the suite loads both into the cluster before
// it starts. A node never pulls them: with the tag latest the default pull policy would be Always,
// and a node can't pull behind a proxy that it doesn't know.
const (
	// nginxImage is the image of the Deployment that the inventory spec starts.
	nginxImage = "nginx:1.27-alpine"
	// curlImage is the image of the pod that reads the metrics.
	curlImage = "curlimages/curl:8.14.1"
)

// What the inventory and ModelConfig specs create and look for.
const (
	// workloadNamespace and workloadName name the Deployment that the inventory spec starts.
	workloadNamespace = "e2e-workloads"
	workloadName      = "nginx"

	// clusterName is the name of this cluster in the inventory and in the metrics: with no
	// OperatorConfig, the operator uses its default.
	clusterName = "local"

	// staleDigest is the digest of an ImageInventory that exists before the operator starts, and
	// that no pod runs.
	staleDigest = "sha256:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

	// modelConfigName is the ModelConfig whose Secret doesn't exist.
	modelConfigName = "e2e"

	imageInventories = "imageinventories.inventory.vexplain.bedag.ch"
	imageVerdicts    = "imageverdicts.inventory.vexplain.bedag.ch"
	modelConfigs     = "modelconfigs.config.vexplain.bedag.ch"
)

// What the scanning specs plant and look for.
const (
	// plantedNamespace holds the Deployments of the planted images.
	plantedNamespace = "e2e-planted"

	// scanTimeout is how long a Deployment of a planted image has to get its findings: the inventory sees
	// the pod, the hub asks for a scan, a Job pulls the image and scans it, and the matcher matches it.
	scanTimeout = 5 * time.Minute

	// The vulnerabilities of the planted images. The matcher image holds the database that was current
	// when it was built, so the specs name only what the Grype of the matcher image, version 0.121.0,
	// reported for these images with the database v6.1.10+2026-10-30T06:23:28Z. The images never change:
	// Alpine 3.12 gets no more updates, and the Dockerfiles name their base image by its digest.
	//
	// exploitedVulnerability is in the package brotli-libs, in both images. The database lists it in the
	// catalog of known exploited vulnerabilities, so the rules track it and never reach the load check.
	// It is the only vulnerability that the database lists for brotli-libs in the releases from Alpine 3.12
	// to 3.20, and it lists none in 3.22. So no Brotli finding shows the load check, and the specs of the
	// load check use another library.
	exploitedVulnerability = "CVE-2026-111497"
	exploitedPackage       = "brotli-libs"
	// unexploitedVulnerability is in the package libxml2, which owns the library libxml2.so.2 and nothing
	// else. The catalog doesn't list it, and the package is a library alone, so the load check applies.
	// Nothing in installed-not-linked loads the library. The commands /usr/bin/xmlcatalog and
	// /usr/bin/xmllint, which the package libxml2-utils adds to linked, do.
	unexploitedVulnerability = "CVE-2024-56171"
	unexploitedPackage       = "libxml2"

	// matcherDeployment is the name of the matcher's Deployment, and matcherLabel selects its pods.
	// operatorLabel selects the pods of the manager and the matcher.
	matcherDeployment = "vexplain-matcher"
	matcherLabel      = "app.kubernetes.io/component=matcher"
	operatorLabel     = "app.kubernetes.io/name=vexplain"
)

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string
	// workloadInventory is the name of the ImageInventory of the image of the Deployment, which the
	// spec that starts the Deployment finds out and the spec that deletes it reads.
	var workloadInventory string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for the ImageInventory CRD to be established")
		cmd = exec.Command("kubectl", "wait", "--for=condition=Established", "crd/"+imageInventories,
			"--timeout=60s")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "The ImageInventory CRD was not established")

		// The operator is not running yet, so the object stays as it is until it starts. The entry
		// has this cluster's ID, and another name, as if the cluster had been renamed.
		By("creating an ImageInventory that no pod runs, with an entry of this cluster")
		createStaleInventory()

		// The deployment of the tests is config/default, with the settings of a cluster that has no
		// internet: test/e2e/config.
		By("deploying the controller-manager and the matcher")
		cmd = exec.Command("make", "deploy", "DEPLOY_CONFIG=test/e2e/config",
			fmt.Sprintf("IMG=%s", managerImage), fmt.Sprintf("SCANNER_IMG=%s", scannerImage),
			fmt.Sprintf("MATCHER_IMG=%s", matcherImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager and the matcher")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		// The cluster outlives a failed run, and the next run would fail on a binding that is there.
		By("cleaning up the ClusterRoleBinding for the metrics")
		cmd = exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("cleaning up the namespaces of the workloads, and the ModelConfig")
		cmd = exec.Command("kubectl", "delete", "ns", workloadNamespace, plantedNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", modelConfigs, modelConfigName, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager and the matcher")
		cmd = exec.Command("make", "undeploy", "DEPLOY_CONFIG=test/e2e/config")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching the ImageInventory objects and the events of the default namespace")
			cmd = exec.Command("kubectl", "get", imageInventories, "-o", "custom-columns="+
				"NAME:.metadata.name,CLUSTERS:.status.clusters[*].cluster")
			inventoryOutput, err := utils.Run(cmd)
			_, _ = fmt.Fprintf(GinkgoWriter, "ImageInventory objects (err %v):\n%s", err, inventoryOutput)
			cmd = exec.Command("kubectl", "get", "events.events.k8s.io", "-n", "default",
				"--sort-by=.metadata.creationTimestamp")
			defaultEvents, err := utils.Run(cmd)
			_, _ = fmt.Fprintf(GinkgoWriter, "Events in default (err %v):\n%s", err, defaultEvents)

			By("Fetching the matcher logs, and the scan Jobs and their pods")
			cmd = exec.Command("kubectl", "logs", "-l", matcherLabel, "-n", namespace, "--tail=100")
			matcherLogs, err := utils.Run(cmd)
			_, _ = fmt.Fprintf(GinkgoWriter, "Matcher logs (err %v):\n%s", err, matcherLogs)
			cmd = exec.Command("kubectl", "get", "jobs,pods", "-n", namespace, "-l", workloads.TaskLabel)
			scanObjects, err := utils.Run(cmd)
			_, _ = fmt.Fprintf(GinkgoWriter, "Scan Jobs and pods (err %v):\n%s", err, scanObjects)

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				By("getting the name of the controller-manager pod")
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				By("validating the pod's status")
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		// The readiness probe of the manager is a ping: it answers as soon as the server runs, and does
		// not wait for the caches. A pod whose Secret informer is refused is ready for two minutes,
		// until the manager gives up on the cache and exits. So the pod being ready proves nothing
		// about the RoleBinding of the Secrets (config/rbac/manager_secrets_rolebinding.yaml). A
		// controller starts its workers once every source it watches has synced, and the ModelConfig
		// controller watches Secrets, so that it has started proves the informer syncs.
		It("should have synced the cache of Secrets, because the ModelConfig controller runs", func() {
			By("waiting for the controller-manager pod to be ready")
			cmd := exec.Command("kubectl", "wait", "pod", controllerPodName, "--for=condition=Ready",
				"--timeout=3m", "-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "The controller-manager pod did not become ready")

			By("waiting for the ModelConfig controller to start its workers")
			verifyWorkersStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(MatchRegexp(`Starting workers\s+\{"controller": "config-modelconfig"`),
					"The ModelConfig controller did not start: its cache of Secrets has not synced")
			}
			Eventually(verifyWorkersStarted).Should(Succeed())
		})

		// The object was made before the operator started, with an entry of this cluster, and no pod
		// runs its digest. The first list of the store delivers it as created, so that the pod
		// inventory reconciles it, finds no pod, and forgets the entry. With no entry left it
		// deletes the object.
		It("should delete an ImageInventory that no pod runs, which was there when it started", func() {
			Eventually(func(g Gomega) {
				g.Expect(getInventory(g, inventory.NameForDigest(staleDigest))).To(BeNil(),
					"The ImageInventory that existed before the start is still there")
			}, 90*time.Second).Should(Succeed())
		})

		// A running Deployment shows up in the ImageInventory of its image. The digest is whatever the
		// container runtime reports for the pod. A preloaded image may be reported as an image ID, and
		// not as a repository digest, so the kind of the digest is not asserted.
		It("should list a running Deployment in the ImageInventory of its image", func() {
			By("creating a Deployment of one replica with a pinned image")
			cmd := exec.Command("kubectl", "create", "ns", workloadNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create the namespace of the workload")
			Expect(kubectlApply(deploymentManifest())).To(Succeed(), "Failed to create the Deployment")

			By("reading the image ID that the pod reports, and making the name of its ImageInventory")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "-n", workloadNamespace, "-l", "app="+workloadName,
					"-o", "jsonpath={.items[0].status.containerStatuses[0].imageID}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "The pod is not there yet")
				imageID := strings.TrimSpace(output)
				g.Expect(imageID).NotTo(BeEmpty(), "The container has not started")
				image, ok := workloads.DigestFromImageID(imageID)
				g.Expect(ok).To(BeTrue(), "The imageID %q is no digest", imageID)
				workloadInventory = inventory.NameForDigest(image.Digest)
			}).Should(Succeed())

			By("waiting for the ImageInventory to list the Deployment for this cluster")
			want := inventoryv1alpha1.WorkloadReference{
				APIGroup: ptr.To("apps"), Kind: "Deployment", Namespace: workloadNamespace, Name: workloadName,
			}
			Eventually(func(g Gomega) {
				found := getInventory(g, workloadInventory)
				g.Expect(found).NotTo(BeNil(), "There is no ImageInventory %s yet", workloadInventory)
				entry := entryOf(found, clusterName)
				g.Expect(entry).NotTo(BeNil(), "The ImageInventory has no entry for cluster %q", clusterName)
				g.Expect(entry.Workloads).To(ContainElement(want))
			}).Should(Succeed())
		})

		It("should delete the ImageInventory when the last pod of its image is gone", func() {
			By("deleting the Deployment")
			cmd := exec.Command("kubectl", "delete", "deployment", workloadName, "-n", workloadNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete the Deployment")

			By("waiting for the ImageInventory to be gone")
			Eventually(func(g Gomega) {
				g.Expect(getInventory(g, workloadInventory)).To(BeNil(),
					"The ImageInventory %s is still there", workloadInventory)
			}, 90*time.Second).Should(Succeed())
		})

		// The operator records the event through the events.k8s.io API, which its ClusterRole has to
		// allow, and that envtest, which enforces no RBAC, can't show. The events of a cluster-scoped
		// object land in the default namespace. The event also needs the ModelConfig controller to have
		// looked for the Secret that it names, in the cache of Secrets.
		It("should record a ModelUnavailable event for a ModelConfig whose Secret doesn't exist", func() {
			By("creating a ModelConfig that names a Secret that doesn't exist")
			Expect(kubectlApply(modelConfigManifest())).To(Succeed(), "Failed to create the ModelConfig")
			cmd := exec.Command("kubectl", "get", modelConfigs, modelConfigName, "-o", "jsonpath={.metadata.uid}")
			uid, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to read the UID of the ModelConfig")

			// The event is selected by the UID of this ModelConfig, so that the event of an earlier run,
			// which lives for an hour, can't pass for it.
			By("waiting for its ModelUnavailable event in the default namespace")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "events.events.k8s.io", "-n", "default",
					"--field-selector", "regarding.uid="+strings.TrimSpace(uid)+",reason=ModelUnavailable",
					"-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(utils.GetNonEmptyLines(output)).NotTo(BeEmpty(), "There is no ModelUnavailable event yet")
			}, time.Minute).Should(Succeed())
		})

		// The metrics are read last, so that the gauge of running images has been counted for some time
		// by then, with the pods of the cluster in the inventory.
		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=vexplain-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("ensuring the controller pod is ready")
			verifyControllerPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Controller pod not ready")
			}
			Eventually(verifyControllerPodReady, 3*time.Minute, time.Second).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 3*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image="+curlImage,
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "%s",
							"imagePullPolicy": "IfNotPresent",
							"command": ["/bin/sh", "-c"],
							"args": [
								"for i in $(seq 1 30); do curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics && exit 0 || sleep 2; done; exit 1"
							],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, curlImage, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
				// The gauge of the images that run in the cluster, labelled with its name, and counting
				// something: the pods of kube-system run images too.
				gauge := fmt.Sprintf(`vexplain_images_running{cluster=%q}`, clusterName)
				g.Expect(metricsOutput).To(ContainSubstring(gauge), "The gauge of running images is missing")
				g.Expect(metricsOutput).To(MatchRegexp(regexp.QuoteMeta(gauge)+` [1-9]`), "The gauge counts no image")
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		// TODO: Customize the e2e test suite with scenarios specific to your project.
		// Consider applying sample/CR(s) and check their status and/or verifying
		// the reconciliation by using the metrics, i.e.:
		// metricsOutput, err := getMetricsOutput()
		// Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
		// Expect(metricsOutput).To(ContainSubstring(
		//    fmt.Sprintf(`controller_runtime_reconcile_total{controller="%s",result="success"} 1`,
		//    strings.ToLower(<Kind>),
		// ))
	})

	// The scan path, from a Deployment to the findings of its image, on a real cluster: the hub asks for
	// a scan, the spoke runs it as a Job that pulls the image from the local registry, the matcher
	// matches the packages, and the rules settle the findings. The two images are Alpine 3.12 with the
	// libraries brotli-libs and libxml2: installed-not-linked has nothing that loads them, and linked has
	// a command for each that does.
	Context("Scanning", func() {
		var watch *scanWatch

		BeforeAll(func() {
			// A matcher that isn't ready fails the matches of the first scans, and the verdicts controller
			// waits longer before it tries again each time.
			By("waiting for the matcher to have its database")
			cmd := exec.Command("kubectl", "wait", "deployment/"+matcherDeployment, "--for=condition=Available",
				"--timeout=10m", "-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "The matcher did not become available")

			// The watch starts first, so that it sees every scan pod.
			watch = startScanWatch()

			By("starting a Deployment of each planted image, by its digest")
			cmd = exec.Command("kubectl", "create", "ns", plantedNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create the namespace of the planted images")
			for _, name := range plantedImages {
				Expect(plantedDigests).To(HaveKey(name))
				Expect(kubectlApply(plantedDeploymentManifest(name))).To(Succeed(),
					"Failed to create the Deployment of %s", name)
			}
		})

		AfterAll(func() {
			if watch != nil {
				watch.stop()
			}
		})

		// The finding is in a package that owns one library and nothing else. Nothing in the image needs
		// libxml2.so.2 or names it, and no pod sets LD_PRELOAD, so the load check settles it, on the
		// condition that none does.
		It("should suppress a finding in a library that nothing in the image loads", func() {
			finding, _ := waitForFinding("installed-not-linked", unexploitedVulnerability, unexploitedPackage)
			Expect(finding.Outcome).To(Equal(inventoryv1alpha1.OutcomeSuppressed))
			Expect(finding.Rule).To(HaveValue(Equal(inventoryv1alpha1.RuleLoadCheck)))
			Expect(finding.Justification).To(
				HaveValue(Equal(inventoryv1alpha1.JustificationVulnerableCodeNotInExecutePath)))
			Expect(finding.Conditions).To(ConsistOf(inventoryv1alpha1.FindingConditionNoPreloadEnvironment))
		})

		// The same package and vulnerability, in an image with a command that links the library. The reason
		// names the first of the commands that reach it.
		It("should keep the finding open in an image whose command links the library", func() {
			finding, _ := waitForFinding("linked", unexploitedVulnerability, unexploitedPackage)
			Expect(finding.Outcome).To(Equal(inventoryv1alpha1.OutcomeNeedsAssessment))
			Expect(finding.Rule).To(HaveValue(Equal(inventoryv1alpha1.RuleLoadCheck)))
			Expect(finding.Reason).To(HaveValue(MatchRegexp(`^reached by /usr/bin/(xmlcatalog|xmllint)$`)))
		})

		// Nothing in installed-not-linked loads brotli-libs either, so without the catalog of known
		// exploited vulnerabilities the load check would suppress the finding. The rules come to Tracked
		// first: an exploited vulnerability is not argued about, whatever the image can load.
		It("should track a known exploited vulnerability, which the load check never gets to see", func() {
			for _, image := range plantedImages {
				finding, sheet := waitForFinding(image, exploitedVulnerability, exploitedPackage)
				Expect(finding.Outcome).To(Equal(inventoryv1alpha1.OutcomeTracked), "image %s", image)
				Expect(finding.Rule).To(HaveValue(Equal(inventoryv1alpha1.RuleKnownExploited)), "image %s", image)
				Expect(finding.Justification).To(BeNil(), "image %s", image)
				AddReportEntry("database of the sheet of "+image, ptr.Deref(sheet.Status.DatabaseVersion, ""))
			}
		})

		// The scan of an image covers the platforms of the nodes that run it, and the facts say which.
		// They also name the scanner image of the manager's environment, which kustomize wrote there.
		It("should record the platform that each scan covered, and no failure", func() {
			for _, image := range plantedImages {
				digest := plantedDigests[image]
				Eventually(func(g Gomega) {
					found := getInventory(g, inventory.NameForDigest(digest))
					g.Expect(found).NotTo(BeNil(), "There is no ImageInventory of %s", image)
					facts := found.Status.Facts
					g.Expect(facts).NotTo(BeNil(), "The ImageInventory of %s has no facts", image)
					g.Expect(facts.Failure).To(BeNil(), "The last scan of %s failed", image)
					g.Expect(facts.ScannerImage).To(HaveValue(Equal(scannerImage)))
					g.Expect(facts.Platforms).To(HaveLen(1), "platforms of %s", image)
					g.Expect(facts.Platforms[0].Platform).To(MatchRegexp(`^linux/(amd64|arm64)`))
					g.Expect(facts.Platforms[0].ManifestDigest).To(Equal(digest))
				}).Should(Succeed())
			}
		})

		// A real cluster has a garbage collector, and envtest has none: it deletes the Secret of a scan
		// with the Job that owns it. The runner deletes the Job once it has the result.
		It("should leave no scan Job and no scan Secret behind", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "jobs,secrets", "-n", namespace, "-l", workloads.TaskLabel,
					"-o", "name")
				output, err := cmd.Output()
				g.Expect(err).NotTo(HaveOccurred(), "%q failed", strings.Join(cmd.Args, " "))
				g.Expect(utils.GetNonEmptyLines(string(output))).To(BeEmpty(), "Scan Jobs or Secrets are left")
			}).Should(Succeed())
		})

		// A scan pod lives for seconds, and the ImageInventory of an image goes with its last pod, so
		// the watch has looked at both every second since before the first scan started. The image of a
		// scan pod is the image of the scanner. The inventory never counts it.
		It("should never inventory a scan pod, so the scanner image has no ImageInventory", func() {
			seen := watch.seen()
			Expect(seen.scanImages).NotTo(BeEmpty(), "The watch saw no scan pod, so it proves nothing")
			Expect(seen.inventories).NotTo(BeEmpty(), "The watch saw no ImageInventory, so it proves nothing")
			for imageID := range seen.scanImages {
				image, ok := workloads.DigestFromImageID(imageID)
				Expect(ok).To(BeTrue(), "The imageID %q of a scan pod is no digest", imageID)
				Expect(seen.inventories).NotTo(HaveKey(inventory.NameForDigest(image.Digest)),
					"The ImageInventory %s counted a scan pod", inventory.NameForDigest(image.Digest))
				Eventually(func(g Gomega) {
					g.Expect(getInventory(g, inventory.NameForDigest(image.Digest))).To(BeNil())
				}).Should(Succeed())
			}
		})

		// The matcher answers whoever sends it an SBOM, so its NetworkPolicy lets only the manager's pods in.
		// The manager's matches work with or without the policy, and a policy that selects no pod restricts
		// nothing. So two pods ask the matcher for /healthz, again and again for a few seconds: one has the
		// manager's labels, and gets through. The other has none of them, and the policy drops every one of
		// its packets, so that it never does. Kind's CNI enforces NetworkPolicies. The first connections of
		// a new pod can fail whatever the policy says, which is why both pods try more than once.
		It("should let only the manager's pods reach the matcher", func() {
			callers := []struct {
				name     string
				labels   map[string]string
				exitCode string
			}{
				{name: "matcher-from-manager-labels", labels: managerPodLabels, exitCode: "0"},
				{name: "matcher-from-elsewhere", exitCode: "1"},
			}
			for _, caller := range callers {
				DeferCleanup(deletePod, caller.name)
				Expect(kubectlApply(matcherCallerManifest(caller.name, caller.labels))).To(Succeed(),
					"Failed to create pod %s", caller.name)
			}
			for _, caller := range callers {
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "pod", caller.name, "-n", namespace, "-o",
						"jsonpath={.status.containerStatuses[0].state.terminated.exitCode}")
					output, err := cmd.Output()
					g.Expect(err).NotTo(HaveOccurred(), "%q failed", strings.Join(cmd.Args, " "))
					g.Expect(string(output)).NotTo(BeEmpty(), "Pod %s has not finished yet", caller.name)
					g.Expect(string(output)).To(Equal(caller.exitCode),
						"Exit code of pod %s: 0 if it reached the matcher, 1 if it never did", caller.name)
				}).Should(Succeed())
			}
		})

		// The memory limits of the manager and the matcher are those of the manifests: a pod that the
		// kernel killed for its memory has restarted.
		It("should not have restarted the manager or the matcher", func() {
			cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", operatorLabel, "-o",
				`jsonpath={range .items[*]}{.metadata.name}{" "}{.status.containerStatuses[*].restartCount}{"\n"}{end}`)
			output, err := cmd.Output()
			Expect(err).NotTo(HaveOccurred(), "%q failed", strings.Join(cmd.Args, " "))
			pods := utils.GetNonEmptyLines(string(output))
			Expect(pods).To(ContainElement(HavePrefix("vexplain-controller-manager-")))
			Expect(pods).To(ContainElement(HavePrefix(matcherDeployment + "-")))
			for _, pod := range pods {
				Expect(pod).To(MatchRegexp(` 0$`), "A container of the pod restarted: %s", pod)
			}
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	By("creating temporary file to store the token request")
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		By("executing kubectl command to create the token")
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		By("parsing the JSON output to extract the token")
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}

// kubectlApply applies a manifest.
func kubectlApply(manifest string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	return err
}

// deploymentManifest returns the Deployment that the inventory spec starts: one replica of a pinned
// image, which is never pulled, because the suite has loaded it into the cluster.
func deploymentManifest() string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
    spec:
      containers:
      - name: %[1]s
        image: %[3]s
        imagePullPolicy: IfNotPresent
`, workloadName, workloadNamespace, nginxImage)
}

// modelConfigManifest returns a ModelConfig whose Secret doesn't exist.
func modelConfigManifest() string {
	return fmt.Sprintf(`apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: ModelConfig
metadata:
  name: %s
spec:
  endpoint: https://llm.example/v1
  model: model-a
  apiKeySecretRef:
    name: llm-api-key-that-does-not-exist
    key: api-key
`, modelConfigName)
}

// createStaleInventory creates an ImageInventory that no pod runs, and gives it an entry that has the
// ID of this cluster, the UID of kube-system, under a name that is not the cluster's. The status is a
// subresource, so the entry is written in a second call.
func createStaleInventory() {
	name := inventory.NameForDigest(staleDigest)
	Expect(kubectlApply(fmt.Sprintf(`apiVersion: inventory.vexplain.bedag.ch/v1alpha1
kind: ImageInventory
metadata:
  name: %s
spec:
  digest: %s
`, name, staleDigest))).To(Succeed(), "Failed to create the stale ImageInventory")

	cmd := exec.Command("kubectl", "get", "ns", "kube-system", "-o", "jsonpath={.metadata.uid}")
	clusterID, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to read the UID of kube-system")
	Expect(strings.TrimSpace(clusterID)).NotTo(BeEmpty())

	patch := fmt.Sprintf(`{"status":{"digestKind":"RepoDigest","clusters":[{"cluster":"former-name",`+
		`"clusterID":%q,"namespaceCount":1,"workloadCount":1,"firstSeenTime":"2026-01-01T00:00:00Z"}]}}`,
		strings.TrimSpace(clusterID))
	cmd = exec.Command("kubectl", "patch", imageInventories, name, "--subresource=status",
		"--type=merge", "--patch", patch)
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to write the status of the stale ImageInventory")

	// The spec that waits for the object to go would pass for an object that never had the entry.
	found := getInventory(Default, name)
	Expect(found).NotTo(BeNil(), "The stale ImageInventory is not there")
	Expect(found.Status.Clusters).To(HaveLen(1), "The stale ImageInventory has no entry")
	Expect(found.Status.Clusters[0].ClusterID).To(Equal(strings.TrimSpace(clusterID)))
}

// getObject reads the cluster-scoped object of a resource and name with kubectl, and returns nil when
// there is none. Only the standard output is parsed, so that a warning of kubectl can't break the JSON.
func getObject[T any](g Gomega, resource, name string) *T {
	cmd := exec.Command("kubectl", "get", resource, name, "--ignore-not-found", "-o", "json")
	output, err := cmd.Output()
	g.Expect(err).NotTo(HaveOccurred(), "%q failed", strings.Join(cmd.Args, " "))
	if strings.TrimSpace(string(output)) == "" {
		return nil
	}
	var found T
	g.Expect(json.Unmarshal(output, &found)).To(Succeed(), "Failed to parse the %s", resource)
	return &found
}

// getInventory reads the ImageInventory of a name with kubectl, and returns nil when there is none.
func getInventory(g Gomega, name string) *inventoryv1alpha1.ImageInventory {
	return getObject[inventoryv1alpha1.ImageInventory](g, imageInventories, name)
}

// entryOf returns the entry of a cluster in an ImageInventory, or nil when it has none.
func entryOf(found *inventoryv1alpha1.ImageInventory, cluster string) *inventoryv1alpha1.ClusterPresence {
	for i := range found.Status.Clusters {
		if found.Status.Clusters[i].Cluster == cluster {
			return &found.Status.Clusters[i]
		}
	}
	return nil
}

// plantedDeploymentManifest returns the Deployment of a planted image: one replica that sleeps. It
// names the image by its digest, so that the pod reports a repository digest, and the scan pulls the
// manifest that the registry holds.
func plantedDeploymentManifest(name string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
    spec:
      # sleep as process 1 ignores SIGTERM, so the pod would wait for the end of its grace period to go.
      terminationGracePeriodSeconds: 1
      containers:
      - name: %[1]s
        image: %[3]s/%[1]s@%[4]s
        command: ["sleep", "86400"]
`, name, plantedNamespace, registryHost, plantedDigests[name])
}

// managerPodLabels are the labels by which the NetworkPolicy of the matcher knows the pods of the manager.
var managerPodLabels = map[string]string{"control-plane": "controller-manager", "app.kubernetes.io/name": "vexplain"}

// deletePod deletes a pod of the operator's namespace, if it is there, without waiting for it to go.
func deletePod(name string) {
	cmd := exec.Command("kubectl", "delete", "pod", name, "-n", namespace, "--ignore-not-found", "--wait=false")
	_, _ = utils.Run(cmd)
}

// matcherCallerManifest returns a pod that asks the matcher's Service for /healthz, with the labels that
// it is given. It tries up to six times, two seconds each, and ends with exit code 0 at the first
// answer, or with 1 when it gets none. The pod meets the restricted security standard that the
// namespace of the operator enforces.
func matcherCallerManifest(name string, labels map[string]string) string {
	var labelLines strings.Builder
	for key, value := range labels {
		_, _ = fmt.Fprintf(&labelLines, "    %s: %s\n", key, value)
	}
	labelsField := ""
	if labelLines.Len() > 0 {
		labelsField = "  labels:\n" + labelLines.String()
	}
	script := fmt.Sprintf("for i in 1 2 3 4 5 6; do curl --silent --fail --max-time 2 --output /dev/null "+
		"http://%s.%s.svc:8080/healthz && exit 0; sleep 1; done; exit 1", matcherDeployment, namespace)
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
%sspec:
  restartPolicy: Never
  containers:
  - name: curl
    image: %s
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", %q]
    securityContext:
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      runAsUser: 1000
      seccompProfile:
        type: RuntimeDefault
`, name, namespace, labelsField, curlImage, script)
}

// findingOf returns the finding of a vulnerability in the package with the name, or nil when the sheet
// has none.
func findingOf(sheet *inventoryv1alpha1.ImageVerdicts, vulnerability, packageName string) *inventoryv1alpha1.Finding {
	for i := range sheet.Status.Findings {
		finding := &sheet.Status.Findings[i]
		if finding.VulnerabilityID == vulnerability && finding.Package.Name == packageName {
			return finding
		}
	}
	return nil
}

// waitForFinding waits until the ImageVerdicts of a planted image has a finding of the vulnerability
// in the package, for as long as scanTimeout, and returns the finding and the sheet. The sheet of an
// image is named for the digest of its platform manifest, which is the digest that the registry holds.
func waitForFinding(image, vulnerability, packageName string) (
	inventoryv1alpha1.Finding, *inventoryv1alpha1.ImageVerdicts,
) {
	name := inventory.NameForDigest(plantedDigests[image])
	var finding inventoryv1alpha1.Finding
	var sheet *inventoryv1alpha1.ImageVerdicts
	Eventually(func(g Gomega) {
		sheet = getObject[inventoryv1alpha1.ImageVerdicts](g, imageVerdicts, name)
		g.Expect(sheet).NotTo(BeNil(), "There is no ImageVerdicts of %s yet", image)
		found := findingOf(sheet, vulnerability, packageName)
		g.Expect(found).NotTo(BeNil(),
			"The ImageVerdicts of %s has no finding of %s in %s", image, vulnerability, packageName)
		finding = *found
	}, scanTimeout).Should(Succeed())
	return finding, sheet
}

// scanWatch looks, once a second, at what a spec can't see once the scans are over: the images of
// the scan pods, and the ImageInventory objects that exist while they run. A scan pod lives for
// seconds, and an ImageInventory goes with the last pod of its image.
type scanWatch struct {
	mu          sync.Mutex
	scanImages  map[string]bool
	inventories map[string]bool
	quit        chan struct{}
	done        chan struct{}
}

// scanWatched is what a scanWatch has seen so far.
type scanWatched struct {
	// scanImages are the imageIDs of the containers of scan pods, and inventories the names of the
	// ImageInventory objects.
	scanImages, inventories map[string]bool
}

// startScanWatch starts a scanWatch.
func startScanWatch() *scanWatch {
	w := &scanWatch{
		scanImages:  map[string]bool{},
		inventories: map[string]bool{},
		quit:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	go func() {
		defer close(w.done)
		for {
			w.look()
			select {
			case <-w.quit:
				return
			case <-time.After(time.Second):
			}
		}
	}()
	return w
}

// look reads the scan pods and the ImageInventory objects once. A call that fails misses one second,
// which the next call makes up for.
func (w *scanWatch) look() {
	// Not utils.Run: it changes the working directory and logs, which a goroutine must not.
	pods, podsErr := exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", workloads.TaskLabel, "-o",
		`jsonpath={range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{end}`).Output()
	inventories, inventoriesErr := exec.Command("kubectl", "get", imageInventories, "-o",
		`jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}`).Output()

	w.mu.Lock()
	defer w.mu.Unlock()
	if podsErr == nil {
		for _, imageID := range utils.GetNonEmptyLines(string(pods)) {
			w.scanImages[imageID] = true
		}
	}
	if inventoriesErr == nil {
		for _, name := range utils.GetNonEmptyLines(string(inventories)) {
			w.inventories[name] = true
		}
	}
}

// seen returns a copy of what the watch has seen.
func (w *scanWatch) seen() scanWatched {
	w.mu.Lock()
	defer w.mu.Unlock()
	copied := scanWatched{scanImages: map[string]bool{}, inventories: map[string]bool{}}
	for imageID := range w.scanImages {
		copied.scanImages[imageID] = true
	}
	for name := range w.inventories {
		copied.inventories[name] = true
	}
	return copied
}

// stop stops the watch, and waits for its last look.
func (w *scanWatch) stop() {
	close(w.quit)
	<-w.done
}
