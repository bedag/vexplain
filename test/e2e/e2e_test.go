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
	"os/exec"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/sdk/workloads"
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
	// curlImage is the image of the pods that read the metrics and call the collectors.
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

// What the install holds, and what the specs of its collectors look for.
const (
	collectors = "collectors.config.vexplain.bedag.ch"
	// collectorLabel marks the pods of a collector with the name of its Collector, and managerLabel
	// selects the pods of the manager.
	collectorLabel = "vexplain.bedag.ch/collector"
	managerLabel   = "control-plane=controller-manager"
	// defaultPlaybook is the playbook that the install ships, whose rules make the sheets.
	defaultPlaybook = "container-cves"

	// The types of evidence that the built-in collectors produce.
	presenceType      = "ch.bedag.vexplain.presence.v1alpha1"
	imageContentsType = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"
	findingsType      = "ch.bedag.vexplain.findings.v1alpha1"

	// collectorStartup bounds how long a collector takes to be Ready once its Collector exists. Its
	// Deployment rolls out first. Each start of the operator makes a new authority, and a collector
	// refuses the operator until it has loaded a certificate of the new one, which takes as long as the
	// kubelet takes to update a mounted Secret, about a minute: meanwhile Ready stays Unknown, with
	// NoData, for a grace of two minutes.
	collectorStartup = 5 * time.Minute
)

// builtinCollector is a collector that the install ships, and what its Collector records that it
// does.
type builtinCollector struct {
	name string
	// produces is the type of evidence that the collector produces, and watch whether it streams it.
	produces string
	watch    configv1alpha1.CollectorWatch
	// operation is the operation that it runs on demand, which produces its type, or empty for none.
	operation string
}

// builtinCollectors are the collectors of the install.
var builtinCollectors = []builtinCollector{
	{name: "workloads", produces: presenceType, watch: configv1alpha1.CollectorWatchSupported},
	{name: "scanner", produces: imageContentsType, watch: configv1alpha1.CollectorWatchNotSupported, operation: "scan"},
	{name: "matcher", produces: findingsType, watch: configv1alpha1.CollectorWatchSupported, operation: "match"},
}

// What the scanning specs plant and look for.
const (
	// plantedNamespace holds the Deployments of the planted images.
	plantedNamespace = "e2e-planted"

	// scanTimeout is how long a Deployment of a planted image has to get its findings: the inventory sees
	// the pod, the hub asks for a scan, a Job pulls the image and scans it, and the matcher matches it.
	scanTimeout = 5 * time.Minute

	// The vulnerabilities of the planted images. The matcher image holds the database that was current
	// when it was built, so the specs name only what the Grype of the matcher image, version 0.121.0,
	// reported for these images with the databases v6.1.10+2026-10-30T06:23:28Z and
	// v6.1.10+2026-11-06T06:21:59Z. The images never change: Alpine 3.12 gets no more updates, and the
	// Dockerfiles name their base image by its digest.
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
	// Nothing in installed-not-linked reaches or names the library. The commands /usr/bin/xmlcatalog and
	// /usr/bin/xmllint, which the package libxml2-utils adds to linked, reach it.
	unexploitedVulnerability = "CVE-2024-56171"
	unexploitedPackage       = "libxml2"
	// unreachedReason is the reason that the load check gives a finding in a library that nothing in the
	// image reaches or names. The check keeps the finding open, and settles nothing.
	unreachedReason = "nothing in the image reaches or names its libraries"
)

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string
	// workloadInventory is the name of the ImageInventory of the image of the Deployment, which the
	// spec that starts the Deployment finds out and the spec that deletes it reads.
	var workloadInventory string

	// Before running the tests, install the CRDs and deploy the operator with its collectors. The
	// install makes the namespace, which enforces the restricted Pod Security Standard.
	BeforeAll(func() {
		By("installing CRDs")
		cmd := exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		// The stale ImageInventory is created at once, and the install holds objects of the config
		// kinds, which kubectl can only apply once their CRDs serve them.
		By("waiting for the CRDs to be established")
		for _, crd := range []string{imageInventories, collectors, "collectorruntimeconfigs.config.vexplain.bedag.ch",
			"rules.config.vexplain.bedag.ch", "playbooks.config.vexplain.bedag.ch"} {
			cmd = exec.Command("kubectl", "wait", "--for=condition=Established", "crd/"+crd, "--timeout=60s")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "The CRD %s was not established", crd)
		}

		// The operator is not running yet, so the object stays as it is until it starts. The entry
		// has this cluster's ID, and another name, as if the cluster had been renamed.
		By("creating an ImageInventory that no pod runs, with an entry of this cluster")
		createStaleInventory()

		// The deployment of the tests is config/default, with the settings of a cluster that has no
		// internet: test/e2e/config. The Collector scanner names its package by its digest.
		By("deploying the controller-manager and the built-in collectors")
		cmd = exec.Command("make", append([]string{"deploy", "DEPLOY_CONFIG=test/e2e/config"},
			imageVariables(scannerPackage)...)...)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager and the collectors")
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

		// Undeploying deletes the Collectors first, while the manager still removes their finalizers.
		By("undeploying the controller-manager and the collectors")
		cmd = exec.Command("make", "undeploy", "DEPLOY_CONFIG=test/e2e/config", "ignore-not-found=true")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall", "ignore-not-found=true")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace, "--ignore-not-found")
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

			By("Fetching the Collectors, the logs of their collectors, and the scan Jobs and their pods")
			cmd = exec.Command("kubectl", "get", collectors, "-o", "yaml")
			collectorsOutput, err := utils.Run(cmd)
			_, _ = fmt.Fprintf(GinkgoWriter, "Collectors (err %v):\n%s", err, collectorsOutput)
			for _, collector := range builtinCollectors {
				cmd = exec.Command("kubectl", "logs", "deployment/"+collectorObjects(collector.name), "-n", namespace,
					"--tail=100")
				collectorLogs, err := utils.Run(cmd)
				_, _ = fmt.Fprintf(GinkgoWriter, "Logs of collector %s (err %v):\n%s", collector.name, err, collectorLogs)
			}
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
					"pods", "-l", managerLabel,
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

		// The install ships the built-in collectors as Collectors, and the operator runs each as the
		// Deployment vexplain-collector-<name>, and records what it answers: its version, which is the one
		// that this run built it at, and its capabilities.
		It("should run every built-in collector, Ready with its capabilities", func() {
			for _, want := range builtinCollectors {
				By("waiting for the collector " + want.name)
				Eventually(func(g Gomega) {
					found := expectReady(g, want.name)
					g.Expect(found.Status.Version).To(HaveValue(Equal(collectorVersion)),
						"The version of collector %s", want.name)
					capabilities := found.Status.Capabilities
					g.Expect(capabilities).NotTo(BeNil(), "Collector %s records no capabilities", want.name)
					g.Expect(capabilities.Produces).To(ConsistOf(HaveField("Type", want.produces)),
						"What collector %s produces", want.name)
					g.Expect(capabilities.Watch).To(Equal(want.watch), "Whether collector %s watches", want.name)
					if want.operation == "" {
						g.Expect(capabilities.Operations).To(BeEmpty(), "The operations of collector %s", want.name)
					} else {
						g.Expect(capabilities.Operations).To(ConsistOf(And(HaveField("Name", want.operation),
							HaveField("Produces", ConsistOf(want.produces)))), "The operations of collector %s", want.name)
					}
					g.Expect(availableReplicas(g, collectorObjects(want.name))).To(Equal("1"),
						"The Deployment of collector %s has no available replica", want.name)
				}, collectorStartup).Should(Succeed())
			}
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
		// runs its digest. The first complete snapshot of the workloads collector after the start lacks
		// it, so presence forgets the entry. With no entry left it deletes the object.
		It("should delete an ImageInventory that no pod runs, which was there when it started", func() {
			Eventually(func(g Gomega) {
				g.Expect(getInventory(g, inventory.NameForDigest(staleDigest))).To(BeNil(),
					"The ImageInventory that existed before the start is still there")
			}).Should(Succeed())
		})

		// A running Deployment shows up in the ImageInventory of its image, which the workloads collector
		// reports, as the presence of the image. The digest is whatever the container runtime reports for
		// the pod. A preloaded image may be reported as an image ID, and not as a repository digest, so
		// the kind of the digest is not asserted.
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

			// The NetworkPolicy of the metrics lets in the pods of the namespaces that carry this label
			// (config/network-policy/allow-metrics-traffic.yaml), and the curl pod runs in the operator's.
			By("labelling the operator's namespace, so that its pods may read the metrics")
			cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace, "metrics=enabled")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to label the namespace for the metrics")

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

	// The scan path, from a Deployment to the findings of its image, on a real cluster: the hub asks the
	// scanner collector for the evidence of the image, which scans it in a Job that pulls the image from
	// the local registry, the matcher collector matches the packages, and the default playbook's rules
	// settle the findings. The two images are Alpine 3.12 with the libraries brotli-libs and libxml2:
	// installed-not-linked has nothing that reaches or names them, and linked has a command for each that
	// reaches it.
	Context("Scanning", func() {
		var watch *scanWatch

		BeforeAll(func() {
			// A matcher without its database fails the matches of the first scans, and the assessor waits
			// longer before it tries again each time. The matcher copies the database of its image into its
			// volume once the operator watches it, and logs when it has loaded it.
			By("waiting for the matcher to load its database")
			Eventually(func(g Gomega) {
				logs := kubectl(g, "logs", "deployment/"+collectorObjects("matcher"), "-n", namespace)
				g.Expect(logs).To(ContainSubstring("Loaded the vulnerability database"))
			}, 10*time.Minute, 5*time.Second).Should(Succeed())

			// The watch starts first, so that it sees every scan pod.
			watch = startScanWatch()

			By("starting a Deployment of each planted image, by its digest")
			cmd := exec.Command("kubectl", "create", "ns", plantedNamespace)
			_, err := utils.Run(cmd)
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
		// libxml2.so.2 or names it, and the image preloads nothing. The load check notes that, and settles
		// nothing, since a program may build a name while it runs, or be given one from outside: no rule
		// decides the finding.
		It("should keep a finding open, with a hint, in a library that nothing in the image reaches or names", func() {
			finding, _ := waitForFinding("installed-not-linked", unexploitedVulnerability, unexploitedPackage)
			Expect(finding.Status).To(Equal(inventoryv1alpha1.VEXStatusUnderInvestigation))
			Expect(finding.Rule).To(BeNil())
			Expect(finding.StatusNotes).To(Equal([]inventoryv1alpha1.StatusNote{{Rule: "load-check", Text: unreachedReason}}))
			Expect(finding.Justification).To(BeNil())
			Expect(finding.Conditions).To(BeEmpty())
		})

		// The same package and vulnerability, in an image with a command that links the library. The note
		// names the first of the commands that reach it.
		It("should keep the finding open in an image whose command links the library", func() {
			finding, _ := waitForFinding("linked", unexploitedVulnerability, unexploitedPackage)
			Expect(finding.Status).To(Equal(inventoryv1alpha1.VEXStatusUnderInvestigation))
			Expect(finding.StatusNotes).To(ConsistOf(And(HaveField("Rule", "load-check"),
				HaveField("Text", MatchRegexp(`^reached by /usr/bin/(xmlcatalog|xmllint)$`)))))
		})

		// A vulnerability that the catalog of known exploited vulnerabilities lists is held open, so that no
		// rule can settle it, whatever the image can load (decision 0035).
		It("should hold a known exploited vulnerability open", func() {
			for _, image := range plantedImages {
				finding, sheet := waitForFinding(image, exploitedVulnerability, exploitedPackage)
				Expect(finding.Status).To(Equal(inventoryv1alpha1.VEXStatusUnderInvestigation), "image %s", image)
				Expect(finding.Rule).To(HaveValue(Equal("known-exploited")), "image %s", image)
				Expect(finding.Reason).To(HaveValue(Equal("known exploited")), "image %s", image)
				Expect(finding.KnownExploited).To(Equal(inventoryv1alpha1.KnownExploitedListed), "image %s", image)
				Expect(finding.Justification).To(BeNil(), "image %s", image)
				AddReportEntry("findings version of the sheet of "+image, ptr.Deref(sheet.Status.FindingsVersion, ""))
			}
		})

		// The scan of an image covers the platforms of the nodes that run it, and the facts say which.
		// Their evidence is the scanner's, at the version that the scanner answered, which is the one that
		// this run built it at, with the scanner's coverage.
		It("should record the platform that each scan covered, its evidence, and no failure", func() {
			for _, image := range plantedImages {
				digest := plantedDigests[image]
				Eventually(func(g Gomega) {
					found := getInventory(g, inventory.NameForDigest(digest))
					g.Expect(found).NotTo(BeNil(), "There is no ImageInventory of %s", image)
					facts := found.Status.Facts
					g.Expect(facts).NotTo(BeNil(), "The ImageInventory of %s has no facts", image)
					g.Expect(facts.Failures).To(BeEmpty(), "The last scan of %s failed", image)
					g.Expect(facts.Evidence).To(ContainElement(And(
						HaveField("Source", "scanner"), HaveField("Type", imageContentsType),
						HaveField("CollectorVersion", collectorVersion), HaveField("Coverage", Not(BeNil())))),
						"The evidence of %s", image)
					g.Expect(facts.Manifests).To(HaveLen(1), "manifests of %s", image)
					g.Expect(facts.Manifests[0].Platform).To(MatchRegexp(`^linux/(amd64|arm64)`))
					g.Expect(facts.Manifests[0].Digest).To(Equal(digest))
				}).Should(Succeed())
			}
		})

		// A sheet says which playbook made it, and what evidence its findings rest on: the evidence that the
		// default playbook names, the scanner's, at the version of the collector that delivered it, and with
		// its time and its coverage.
		It("should name the default playbook in each sheet, and the evidence that it rests on", func() {
			for _, image := range plantedImages {
				name := inventory.NameForDigest(plantedDigests[image])
				Eventually(func(g Gomega) {
					sheet := getObject[inventoryv1alpha1.ImageVerdicts](g, imageVerdicts, name)
					g.Expect(sheet).NotTo(BeNil(), "There is no ImageVerdicts of %s", image)
					g.Expect(sheet.Status.Playbook).To(HaveValue(Equal(defaultPlaybook)), "The playbook of %s", image)
					g.Expect(sheet.Status.FindingsVersion).NotTo(BeNil(), "The sheet of %s has no verdict yet", image)
					g.Expect(sheet.Status.Evidence).To(ConsistOf(And(
						HaveField("Name", "contents"), HaveField("Source", "scanner"),
						HaveField("Type", imageContentsType), HaveField("Version", HaveValue(Equal(collectorVersion))),
						HaveField("Time", Not(BeNil())), HaveField("Coverage", Not(BeNil())))),
						"The evidence of the sheet of %s", image)
				}).Should(Succeed())
			}
		})

		// A real cluster has a garbage collector, and envtest has none: it deletes the Secret of a scan
		// with the Job that owns it. The scanner deletes the Job once it has the result.
		It("should leave no scan Job and no scan Secret behind", func() {
			Eventually(func(g Gomega) {
				output := kubectl(g, "get", "jobs,secrets", "-n", namespace, "-l", workloads.TaskLabel, "-o", "name")
				g.Expect(utils.GetNonEmptyLines(output)).To(BeEmpty(), "Scan Jobs or Secrets are left")
			}).Should(Succeed())
		})

		// A scan pod lives for seconds, and the inventory never counts it: it is one of vexplain's own task
		// pods. It runs the scanner's image, which the scanner collector's Deployment runs too, so that image
		// has an ImageInventory. The watch has looked at it every second since before the first scan
		// started: it listed the Deployment, and never a scan Job.
		It("should never inventory a scan pod", func() {
			seen := watch.seen()
			Expect(seen.scanImages).NotTo(BeEmpty(), "The watch saw no scan pod, so it proves nothing")
			scannerDeployment := workloadKey(collectorDeployment("scanner"))
			for imageID := range seen.scanImages {
				image, ok := workloads.DigestFromImageID(imageID)
				Expect(ok).To(BeTrue(), "The imageID %q of a scan pod is no digest", imageID)
				listed := seen.workloads[inventory.NameForDigest(image.Digest)]
				Expect(listed).NotTo(BeEmpty(),
					"The watch never saw the ImageInventory of the scanner's image, so it proves nothing")
				Expect(listed).To(Equal(map[string]bool{scannerDeployment: true}),
					"The ImageInventory of the scanner's image listed more than the scanner's Deployment")
			}
			for name, listed := range seen.workloads {
				for workload := range listed {
					Expect(workload).NotTo(HavePrefix("batch/Job/"+namespace+"/"),
						"The ImageInventory %s listed a Job of the operator's namespace", name)
				}
			}
		})
	})

	// The rest of the install: the NetworkPolicy of the collectors, the Pod Security Standard of its
	// namespace, and the RBAC of the collectors, to which a copy of a collector is bound too; and that
	// nothing it runs restarted.
	Context("Install", func() {
		// Only the manager's pods may call a collector on 9443, which config/network-policy says, and its
		// health and its metrics on 8081 stay open to every pod. The manager's calls work with or without
		// the policy, and a policy that selects no pod restricts nothing. So two pods call each built-in
		// collector's Service on both ports, again and again for a few seconds: one has the manager's
		// labels, and gets through on both. The other has none of them: it gets through on 8081, and the
		// policy drops every packet that it sends to 9443. Kind's CNI enforces NetworkPolicies. The first
		// connections of a new pod can fail whatever the policy says, which is why a call is repeated.
		It("should let only the manager's pods reach the collectors on 9443", func() {
			callers := []struct {
				name    string
				labels  map[string]string
				reached string
			}{
				{name: "collectors-from-manager-labels", labels: managerPodLabels, reached: "reached"},
				{name: "collectors-from-elsewhere", reached: "not reached"},
			}
			for _, caller := range callers {
				DeferCleanup(deletePod, caller.name)
				Expect(kubectlApply(collectorCallerManifest(caller.name, caller.labels))).To(Succeed(),
					"Failed to create pod %s", caller.name)
			}
			for _, caller := range callers {
				var output string
				Eventually(func(g Gomega) {
					phase := kubectl(g, "get", "pod", caller.name, "-n", namespace, "-o", "jsonpath={.status.phase}")
					g.Expect(phase).To(Equal("Succeeded"), "Pod %s has not finished yet", caller.name)
					output = kubectl(g, "logs", caller.name, "-n", namespace)
				}, 3*time.Minute).Should(Succeed())
				var want []string
				for _, collector := range builtinCollectors {
					want = append(want, collector.name+":9443 "+caller.reached, collector.name+":8081 reached")
				}
				Expect(utils.GetNonEmptyLines(output)).To(ConsistOf(want), "What pod %s reached", caller.name)
			}
		})

		// The memory limit of the manager is its manifest's, and the matcher's its runtime config's: a
		// container that the kernel killed for its memory has restarted.
		It("should not have restarted the manager or any collector", func() {
			var pods []string
			for _, selector := range []string{managerLabel, collectorLabel} {
				output := kubectl(Default, "get", "pods", "-n", namespace, "-l", selector, "-o",
					`jsonpath={range .items[*]}{.metadata.name}{" "}{.status.containerStatuses[*].restartCount}{"\n"}{end}`)
				pods = append(pods, utils.GetNonEmptyLines(output)...)
			}
			Expect(pods).To(ContainElement(HavePrefix("vexplain-controller-manager-")))
			for _, collector := range builtinCollectors {
				Expect(pods).To(ContainElement(HavePrefix(collectorObjects(collector.name)+"-")),
					"There is no pod of collector %s", collector.name)
			}
			for _, pod := range pods {
				Expect(pod).To(MatchRegexp(` 0$`), "A container of the pod restarted: %s", pod)
			}
		})

		// The install's namespace enforces the restricted Pod Security Standard, which refuses a pod that
		// may run as root or keeps privileges. So every pod that vexplain makes there meets it: each
		// collector's, whose ReplicaSet would record FailedCreate for a pod that it refused, and each scan
		// pod, whose Job would.
		It("should enforce the restricted Pod Security Standard, and have admitted every collector pod", func() {
			By("reading the level that the install's namespace enforces")
			level := kubectl(Default, "get", "ns", namespace, "-o",
				`jsonpath={.metadata.labels.pod-security\.kubernetes\.io/enforce}`)
			Expect(level).To(Equal("restricted"), "The level of the namespace")

			By("checking that the namespace refuses a pod that doesn't meet the standard")
			cmd := exec.Command("kubectl", "run", "pod-security-check", "-n", namespace, "--image="+curlImage,
				"--restart=Never", "--dry-run=server", "--command", "--", "true")
			output, err := cmd.CombinedOutput()
			Expect(err).To(HaveOccurred(), "The namespace admitted a pod with the defaults of a container")
			Expect(string(output)).To(ContainSubstring(`violates PodSecurity "restricted:`))

			By("checking that no Deployment or Job failed to create a pod")
			refused := kubectl(Default, "get", "events", "-n", namespace, "--field-selector", "reason=FailedCreate",
				"-o", "custom-columns=OBJECT:.involvedObject.name,MESSAGE:.message", "--no-headers")
			Expect(utils.GetNonEmptyLines(refused)).To(BeEmpty(), "Pods that were refused")

			By("checking that each built-in collector runs its pod")
			for _, collector := range builtinCollectors {
				phases := kubectl(Default, "get", "pods", "-n", namespace, "-l", collectorLabel+"="+collector.name,
					"-o", `jsonpath={range .items[*]}{.status.phase}{"\n"}{end}`)
				Expect(utils.GetNonEmptyLines(phases)).To(ConsistOf("Running"), "The pods of collector %s", collector.name)
			}
		})

		// A second Collector of the workloads collector's package is a copy, which the operator runs as a
		// collector of its own: vexplain-collector-extra, whose service account an admin binds to the
		// ClusterRole of workloads, as for any collector that the install doesn't ship. The copy reports
		// the same presence as workloads. Deleting it removes what the operator made for it, through the
		// owner references, which the garbage collector of a real cluster follows and envtest has none of,
		// and the operator forgets what it delivered. Presence keeps what workloads delivers, so every
		// image that still runs keeps its ImageInventory.
		It("should run a copy of the workloads collector, and remove what is the copy's alone", func() {
			const extra = "extra"

			By("binding the copy's service account to the ClusterRole of workloads")
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "clusterrolebinding", collectorObjects(extra), "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			Expect(kubectlApply(collectorBindingManifest(extra, collectorObjects("workloads")))).To(Succeed(),
				"Failed to bind the copy's service account")

			By("installing the copy, with the package of workloads")
			workloadsPackage := kubectl(Default, "get", collectors, "workloads", "-o", "jsonpath={.spec.package}")
			Expect(workloadsPackage).NotTo(BeEmpty())
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", collectors, extra, "--ignore-not-found", "--timeout=2m")
				_, _ = utils.Run(cmd)
			})
			Expect(kubectlApply(collectorManifest(extra, workloadsPackage))).To(Succeed(), "Failed to install the copy")

			By("waiting for the copy to be Ready, with its Deployment running")
			Eventually(func(g Gomega) {
				expectReady(g, extra)
				g.Expect(availableReplicas(g, collectorObjects(extra))).To(Equal("1"),
					"The Deployment of the copy has no available replica")
			}, collectorStartup).Should(Succeed())

			// The copy's pod runs the image of workloads, as the pod of workloads does, so the ImageInventory
			// of that image lists both Deployments, once the copy's snapshot has been heard as well.
			workloadsInventory := collectorInventory("workloads")
			workloadsDeployment := collectorDeployment("workloads")
			extraDeployment := collectorDeployment(extra)
			By("waiting for the ImageInventory of the image of workloads to list the copy's Deployment")
			Eventually(func(g Gomega) {
				g.Expect(workloadsOf(g, workloadsInventory)).To(ContainElements(workloadsDeployment, extraDeployment))
			}).Should(Succeed())

			By("noting every image that runs in this cluster")
			present := inventoriesOfCluster(Default)
			Expect(present).To(ContainElement(workloadsInventory))
			for _, image := range plantedImages {
				Expect(present).To(ContainElement(inventory.NameForDigest(plantedDigests[image])))
			}

			By("deleting the copy")
			cmd := exec.Command("kubectl", "delete", collectors, extra, "--timeout=2m")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete the copy")

			By("waiting for its Deployment, Service, service account and TLS Secret to go")
			owned := []string{
				"deployment/" + collectorObjects(extra), "service/" + collectorObjects(extra),
				"serviceaccount/" + collectorObjects(extra), "secret/" + collectorObjects(extra) + "-tls",
			}
			Eventually(func(g Gomega) {
				for _, object := range owned {
					g.Expect(kubectl(g, "get", object, "-n", namespace, "--ignore-not-found", "-o", "name")).To(BeEmpty(),
						"%s is still there", object)
				}
			}).Should(Succeed())

			By("waiting for the ImageInventory of the image of workloads to list workloads alone")
			Eventually(func(g Gomega) {
				listed := workloadsOf(g, workloadsInventory)
				g.Expect(listed).To(ContainElement(workloadsDeployment))
				g.Expect(listed).NotTo(ContainElement(extraDeployment))
			}).Should(Succeed())

			By("checking that every image that ran keeps its ImageInventory")
			Consistently(func(g Gomega) {
				g.Expect(inventoriesOfCluster(g)).To(ContainElements(present))
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})
	})
})
