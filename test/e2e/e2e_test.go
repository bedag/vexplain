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
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/urgency"
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
	playbooks  = "playbooks.config.vexplain.bedag.ch"
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
	exposureType      = "ch.bedag.vexplain.exposure.v1alpha1"

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
	{name: "vulnerabilities", produces: findingsType, watch: configv1alpha1.CollectorWatchSupported, operation: "match"},
	{name: "network-reach", produces: exposureType, watch: configv1alpha1.CollectorWatchSupported},
}

// What the scanning specs plant and look for.
const (
	// plantedNamespace holds the Deployments of the planted images.
	plantedNamespace = "e2e-planted"

	// scanTimeout is how long a Deployment of a planted image has to get its findings: the inventory sees
	// the pod, the hub asks for a scan, a Job pulls the image and scans it, and the vulnerabilities collector matches it.
	scanTimeout = 5 * time.Minute

	// The vulnerabilities of the planted images. The vulnerabilities collector image holds the database that was current
	// when it was built, so the specs name only what the Grype of the vulnerabilities image, version 0.121.0,
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

// What the specs of exposure and reports start and look for.
const (
	workloadReports = "workloadreports.triage.vexplain.bedag.ch"
	operatorConfigs = "operatorconfigs.config.vexplain.bedag.ch"

	// nodePortNamespace holds the Deployment web behind a NodePort Service. Kind gives a LoadBalancer Service no
	// address, so a node port is how a workload faces outside here.
	nodePortNamespace = "e2e-node-port"
	// hopNamespace holds the Deployment backend, whose NetworkPolicy lets in only the pods of its namespace, and
	// later the Deployment frontend behind a NodePort Service, whose egress no policy restricts. kube-system's pods
	// on their nodes' network are external too, but outside the namespace, which the policy keeps out.
	hopNamespace = "e2e-one-hop"

	// linkedImage is the planted image whose report the specs of reports read.
	linkedImage = "linked"
	// knownExploitedReason is the reason of the rule known-exploited, which holds a finding open.
	knownExploitedReason = "known exploited"

	// ownerLabel is the namespace label that the spec of owner attribution allowlists, and ownerTeam its value on
	// the namespace of the planted images.
	ownerLabel = "team"
	ownerTeam  = "team-a"
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
		cmd := exec.Command("kubectl", "delete", "pod", metricsPod, "-n", namespace)
		_, _ = utils.Run(cmd)

		// The cluster outlives a failed run, and the next run would fail on a binding that is there.
		By("cleaning up the ClusterRoleBinding for the metrics")
		cmd = exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("cleaning up the namespaces of the workloads, the ModelConfig and the OperatorConfig")
		cmd = exec.Command("kubectl", "delete", "ns", workloadNamespace, plantedNamespace, nodePortNamespace,
			hopNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", modelConfigs, modelConfigName, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", operatorConfigs, settings.ConfigName, "--ignore-not-found")
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

			By("Fetching the WorkloadReports, with their counts and exposure")
			cmd = exec.Command("kubectl", "get", workloadReports, "-A")
			reports, err := utils.Run(cmd)
			_, _ = fmt.Fprintf(GinkgoWriter, "WorkloadReports (err %v):\n%s", err, reports)

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", metricsPod, "-n", namespace)
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
		// that this run built it at, and its capabilities. Each, and the default playbook, has a status that
		// kstatus reads as current once Ready (decision 0036).
		It("should run every built-in collector, Ready with its capabilities", func() {
			for _, want := range builtinCollectors {
				By("waiting for the collector " + want.name)
				Eventually(func(g Gomega) {
					found := expectReady(g, want.name)
					expectCurrent(g, "Collector "+want.name, found.Generation, found.Status.ObservedGeneration,
						found.Status.Conditions)
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
			By("waiting for the default playbook")
			Eventually(func(g Gomega) {
				found := expectPlaybookReady(g, defaultPlaybook)
				expectCurrent(g, "Playbook "+defaultPlaybook, found.Generation, found.Status.ObservedGeneration,
					found.Status.Conditions)
			}, collectorStartup).Should(Succeed())
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
			Expect(kubectlApply(deploymentManifest(workloadNamespace, workloadName))).To(Succeed(),
				"Failed to create the Deployment")

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
			Expect(createMetricsPod(token)).To(Succeed(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", metricsPod,
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
	// the local registry, the vulnerabilities collector matches the packages, and the default playbook's rules
	// settle the findings. The two images are Alpine 3.12 with the libraries brotli-libs and libxml2:
	// installed-not-linked has nothing that reaches or names them, and linked has a command for each that
	// reaches it.
	Context("Scanning", func() {
		var watch *scanWatch

		BeforeAll(func() {
			// A vulnerabilities collector without its database fails the matches of the first scans, and the assessor waits
			// longer before it tries again each time. The vulnerabilities collector copies the database of its image into its
			// volume once the operator watches it, and logs when it has loaded it.
			By("waiting for the vulnerabilities collector to load its database")
			Eventually(func(g Gomega) {
				logs := kubectl(g, "logs", "deployment/"+collectorObjects("vulnerabilities"), "-n", namespace)
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

		// The memory limit of the manager is its manifest's, and the vulnerabilities collector's its runtime config's: a
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
		// collector of its own: vexplain-collector-extra, to whose service account it grants what the copy
		// declares, within the ceilings, as for any collector that the install doesn't ship. The copy reports
		// the same presence as workloads. Deleting it removes what the operator made for it, through the
		// owner references, which the garbage collector of a real cluster follows and envtest has none of,
		// and the operator forgets what it delivered. Presence keeps what workloads delivers, so every
		// image that still runs keeps its ImageInventory.
		It("should run a copy of the workloads collector, and remove what is the copy's alone", func() {
			const extra = "extra"

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

	// How far a workload can be reached: the network-reach collector reports it, and the spoke writes it into the
	// workload's report as SSVC's system exposure. Open when something outside the cluster reaches the workload,
	// Controlled when an exposed workload reaches it in one hop or pods beyond its namespace do, and Small when only
	// its own namespace does. The collector has no settings here, so a node port counts as external. A report exists
	// once presence names its workload, and has the workload's exposure once the collector has reported it.
	Context("Exposure", func() {
		It("should give a Deployment behind a NodePort Service the exposure Open", func() {
			By("starting the Deployment web behind a NodePort Service")
			cmd := exec.Command("kubectl", "create", "ns", nodePortNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create the namespace %s", nodePortNamespace)
			Expect(kubectlApply(deploymentManifest(nodePortNamespace, "web"))).To(Succeed(),
				"Failed to create the Deployment web")
			Expect(kubectlApply(nodePortServiceManifest(nodePortNamespace, "web"))).To(Succeed(),
				"Failed to create the Service web")

			By("waiting for the report of web to say Open")
			Eventually(func(g Gomega) {
				g.Expect(deploymentExposure(g, nodePortNamespace, "web")).To(Equal(triagev1alpha1.SSVCExposureOpen))
			}).Should(Succeed())
		})

		// The policy is there before the Deployment, so the collector never sees the pods without it. Small can only
		// come from the policy: without it, the whole cluster reaches the pods, and kube-system's pods on their nodes'
		// network, which face outside and whose egress no policy restricts, reach them in one hop.
		It("should give a Deployment whose NetworkPolicy lets in only its namespace the exposure Small", func() {
			By("starting the Deployment backend, whose NetworkPolicy lets in only the pods of its namespace")
			cmd := exec.Command("kubectl", "create", "ns", hopNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create the namespace %s", hopNamespace)
			Expect(kubectlApply(ownNamespacePolicyManifest(hopNamespace, "backend"))).To(Succeed(),
				"Failed to create the NetworkPolicy of backend")
			Expect(kubectlApply(deploymentManifest(hopNamespace, "backend"))).To(Succeed(),
				"Failed to create the Deployment backend")

			By("waiting for the report of backend to say Small")
			Eventually(func(g Gomega) {
				g.Expect(deploymentExposure(g, hopNamespace, "backend")).To(Equal(triagev1alpha1.SSVCExposureSmall))
			}).Should(Succeed())
		})

		// The backend is Small, as the spec before left it. A frontend behind a NodePort Service joins its namespace:
		// the backend's policy lets in the frontend's pods, and no policy restricts where those go, so the frontend
		// reaches the backend in one hop. Nothing else changes, so the backend's new exposure comes from that hop
		// alone, and not from how far the rest of the cluster reaches it.
		It("should give a backend that an exposed frontend reaches the exposure Controlled", func() {
			By("checking that backend is Small before an exposed workload joins its namespace")
			Expect(deploymentExposure(Default, hopNamespace, "backend")).To(Equal(triagev1alpha1.SSVCExposureSmall))

			By("starting the Deployment frontend behind a NodePort Service, in the namespace of backend")
			Expect(kubectlApply(deploymentManifest(hopNamespace, "frontend"))).To(Succeed(),
				"Failed to create the Deployment frontend")
			Expect(kubectlApply(nodePortServiceManifest(hopNamespace, "frontend"))).To(Succeed(),
				"Failed to create the Service frontend")

			By("waiting for the report of backend to say Controlled, and that of frontend Open")
			Eventually(func(g Gomega) {
				g.Expect(deploymentExposure(g, hopNamespace, "backend")).To(Equal(triagev1alpha1.SSVCExposureControlled))
				g.Expect(deploymentExposure(g, hopNamespace, "frontend")).To(Equal(triagev1alpha1.SSVCExposureOpen))
			}).Should(Succeed())
		})
	})

	// The report of the Deployment of the planted image linked, whose scan the specs of scanning saw: its findings with
	// their urgency for its workload, the label by which one query finds every report of the image, the owner values
	// that an admin allowlists, the worklist's series, and its going with the Deployment.
	Context("Reports", func() {
		linkedReport := deploymentReport(linkedImage)
		// token is the token of the manager's service account, which the metrics endpoint asks for.
		var token string

		BeforeAll(func() {
			var err error
			token, err = serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())
		})

		// No policy selects the pods of the planted images, so the whole cluster reaches them: Controlled. The rule
		// known-exploited holds the Brotli finding open, and the catalog makes its exploitation Active. It is the only
		// vulnerability of brotli-libs, so its action has its urgency: the row of the published table for that
		// exploitation, the workload's exposure, and what the finding's CVSS vectors say of automation and human
		// impact, as urgency.FromFinding reads them. The finding in libxml2 is open, with no fix known, so libxml2 has an
		// action to investigate. The report lists actions (decision 0038); the sheet keeps each finding's reason and
		// notes.
		It("should list actions for the open findings of linked in its report, with the urgency that its exposure gives", func() {
			sheetFinding, _ := waitForFinding(linkedImage, exploitedVulnerability, exploitedPackage)
			Expect(sheetFinding.Rule).To(HaveValue(Equal("known-exploited")))
			Expect(sheetFinding.Reason).To(HaveValue(Equal(knownExploitedReason)))

			var report *triagev1alpha1.WorkloadReport
			By("waiting for the report of linked to have both actions, with the exposure of its workload")
			Eventually(func(g Gomega) {
				report = getReport(g, plantedNamespace, linkedReport)
				g.Expect(report).NotTo(BeNil(), "There is no report of linked yet")
				g.Expect(report.Status.Exposure).To(HaveValue(Equal(triagev1alpha1.SSVCExposureControlled)),
					"The exposure of linked")
				g.Expect(reportActionOf(report, exploitedVulnerability, exploitedPackage)).NotTo(BeNil(),
					"The report of linked has no action for %s", exploitedVulnerability)
				g.Expect(reportStepOf(report, unexploitedPackage, triagev1alpha1.NextStepInvestigate)).NotTo(BeNil(),
					"The report of linked has no action to investigate %s", unexploitedPackage)
			}, scanTimeout).Should(Succeed())

			By("checking the action of the known exploited finding: known exploited, with the urgency that the table gives")
			exploited := reportActionOf(report, exploitedVulnerability, exploitedPackage)
			Expect(exploited.KnownExploited).To(Equal(triagev1alpha1.KnownExploitedListed))
			inputs := urgency.FromFinding(sheetFinding, configv1alpha1.SSVCExposure(*report.Status.Exposure))
			Expect(inputs.Exploitation).To(Equal(configv1alpha1.SSVCExploitationActive))
			want := urgency.Decide(inputs, nil)
			AddReportEntry("urgency of the known exploited finding of linked", fmt.Sprintf("%+v: %s", inputs, want))
			Expect(exploited.Urgency).To(Equal(triagev1alpha1.SSVCOutcome(want)))

			By("checking the investigation of libxml2, and that the summary counts the actions")
			Expect(reportStepOf(report, unexploitedPackage, triagev1alpha1.NextStepInvestigate)).NotTo(BeNil())
			summary := report.Status.Summary
			Expect(summary).NotTo(BeNil(), "The report of linked has no summary")
			Expect(ptr.Deref(summary.OmittedActions, -1)).To(BeZero(), "a report of two packages leaves no action out")
			Expect(ptr.Deref(summary.Actions, 0)).To(BeEquivalentTo(len(report.Status.Actions)), "the summary's actions")
			Expect(ptr.Deref(summary.Investigations, 0)).To(BeNumerically(">=", 1), "the investigations of the summary")
			Expect(ptr.Deref(summary.Updates, 0)+ptr.Deref(summary.Mitigations, 0)+ptr.Deref(summary.Investigations, 0)).
				To(Equal(ptr.Deref(summary.Actions, 0)), "every action has one step")
			Expect(ptr.Deref(summary.Affected, 0)+ptr.Deref(summary.UnderInvestigation, 0)).To(BeNumerically(">=", 2),
				"the open findings of the summary")
			Expect(ptr.Deref(summary.Pending, -1)).To(BeZero(), "the one image of linked has its verdict")
			Expect(ptr.Deref(summary.Incomplete, -1)).To(BeZero(), "the sheet of linked lists every finding")
		})

		// The label names the digest that the pods of linked run, the one that the registry holds for the image. The
		// query is the design's: it lists every report of the image, in every namespace, and no other report.
		It("should list the report of linked by the digest label of its image", func() {
			label := digestLabel(plantedDigests[linkedImage])
			Eventually(func(g Gomega) {
				listed := kubectl(g, "get", "workloadreports", "-A", "-l", label, "-o",
					`jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}`)
				g.Expect(utils.GetNonEmptyLines(listed)).To(ConsistOf(plantedNamespace+"/"+linkedReport),
					"The reports that the label %s lists", label)
			}).Should(Succeed())
		})

		// The workloads collector copies a label of a workload's namespace into presence only when the OperatorConfig
		// allowlists its key, which comes in the context of the collector's stream: the stream opens again with the new
		// context. The report carries the value, and so does the owner info series of the namespace, which the metrics
		// build from the reports.
		It("should copy an allowlisted namespace label into the report and the owner info series", func() {
			By("labelling the namespace of the planted images with the team that owns them")
			kubectl(Default, "label", "--overwrite", "ns", plantedNamespace, ownerLabel+"="+ownerTeam)

			By("allowlisting the label in the OperatorConfig")
			Expect(kubectlApply(operatorConfigManifest(ownerLabel))).To(Succeed(), "Failed to apply the OperatorConfig")

			By("waiting for the report of linked to carry the label")
			Eventually(func(g Gomega) {
				report := getReport(g, plantedNamespace, linkedReport)
				g.Expect(report).NotTo(BeNil(), "There is no report of linked")
				g.Expect(report.Status.Owner).To(ContainElement(triagev1alpha1.OwnerValue{
					Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: ownerLabel, Value: ptr.To(ownerTeam),
				}), "The owner values of the report of linked")
			}).Should(Succeed())

			By("reading the owner info series of the namespace")
			Eventually(func(g Gomega) {
				g.Expect(metricSeries(readMetrics(g, token), "vexplain_namespace_owner_info")).To(ContainElement(And(
					HaveKeyWithValue("cluster", clusterName), HaveKeyWithValue("namespace", plantedNamespace),
					HaveKeyWithValue("label_"+ownerLabel, ownerTeam))), "The owner info series")
			}, 4*time.Minute, 5*time.Second).Should(Succeed())
		})

		// The worklist has one series for each workload, image and CVE that needs action, with the verdict and the
		// urgency that the image's own sheet gives it: the report's, for an image of one platform.
		It("should have an open case of the known exploited vulnerability in the workload of linked", func() {
			report := getReport(Default, plantedNamespace, linkedReport)
			Expect(report).NotTo(BeNil(), "There is no report of linked")
			exploited := reportActionOf(report, exploitedVulnerability, exploitedPackage)
			Expect(exploited).NotTo(BeNil(), "The report of linked has no action for %s", exploitedVulnerability)

			Eventually(func(g Gomega) {
				g.Expect(metricSeries(readMetrics(g, token), "vexplain_open_case")).To(ContainElement(And(
					HaveKeyWithValue("cluster", clusterName), HaveKeyWithValue("namespace", plantedNamespace),
					HaveKeyWithValue("workload", linkedImage), HaveKeyWithValue("digest", plantedDigests[linkedImage]),
					HaveKeyWithValue("cve", exploitedVulnerability),
					HaveKeyWithValue("verdict", string(inventoryv1alpha1.VEXStatusUnderInvestigation)),
					HaveKeyWithValue("urgency", string(exploited.Urgency)))), "The open cases")
			}, 4*time.Minute, 5*time.Second).Should(Succeed())
		})

		// The data kinds share the category vexplain-data, and an ImageInventory says in its summary which image it is
		// and how many workloads and namespaces run it, so that a listing needs no JSON (decision 0039).
		It("should list the data kinds by their category, and name the image and its workloads in the summary of its ImageInventory", func() {
			Eventually(func(g Gomega) {
				listed := kubectl(g, "get", "vexplain-data", "-o", "name")
				for _, kind := range []string{"evidence.", "imageinventory.", "imageverdicts."} {
					g.Expect(listed).To(ContainSubstring(kind), "kubectl get vexplain-data lists no %s", kind)
				}
			}).Should(Succeed())

			Eventually(func(g Gomega) {
				found := getInventory(g, inventory.NameForDigest(plantedDigests[linkedImage]))
				g.Expect(found).NotTo(BeNil(), "There is no ImageInventory of linked")
				summary := found.Status.Summary
				g.Expect(summary).NotTo(BeNil(), "The ImageInventory of linked has no summary")
				g.Expect(ptr.Deref(summary.Image, "")).To(HaveSuffix("/"+linkedImage), "The image of the summary")
				g.Expect(ptr.Deref(summary.Workloads, 0)).To(BeNumerically(">=", 1), "The workloads of the summary")
				g.Expect(ptr.Deref(summary.Namespaces, 0)).To(BeNumerically(">=", 1), "The namespaces of the summary")
				g.Expect(summary.ScanState).To(Equal(inventoryv1alpha1.ScanStateScanned))
				g.Expect(ptr.Deref(summary.Open, 0)).To(BeNumerically(">=", 2), "The open findings of the summary")
				g.Expect(ptr.Deref(summary.Fixable, -1)).To(BeNumerically(">=", 0), "The fixable findings of the summary")
			}, scanTimeout).Should(Succeed())
		})

		// The suite installs cert-manager unless CERT_MANAGER_INSTALL_SKIP is true, as CI sets it, and the spec skips
		// where cert-manager doesn't run. A node says no variant of its platform, so an image that lists
		// its manifest only under one (linux/arm64/v8, for an arm64 node's linux/arm64) is the case that the renderer
		// once left Pending, with no manifest. The case exists only where such an image runs, so the spec checks that
		// premise on the facts of the images, and skips without it: on an amd64 host the images list linux/amd64, which
		// matches exactly, and the spec would pass without the fix. The unit tests cover the matching on every host.
		// Only the one image is read to its sheet, and no count of findings is asserted: they depend on the vulnerabilities collector's
		// database.
		It("should name a manifest for an image of a cert-manager workload that lists its manifest only under a variant", func() {
			if kubectl(Default, "get", "deployment", "cert-manager", "-n", "cert-manager", "--ignore-not-found", "-o", "name") == "" {
				Skip("cert-manager doesn't run on this cluster, as when CERT_MANAGER_INSTALL_SKIP is true, so no workload " +
					"of it has a report")
			}
			var report *triagev1alpha1.WorkloadReport
			var variantOnly *triagev1alpha1.ReportImage
			Eventually(func(g Gomega) {
				report = getReport(g, "cert-manager", deploymentReport("cert-manager"))
				g.Expect(report).NotTo(BeNil(), "There is no report of cert-manager yet")
				g.Expect(report.Status.Images).NotTo(BeEmpty(), "The report of cert-manager lists no image")
				variantOnly = nil
				for i := range report.Status.Images {
					image := &report.Status.Images[i]
					found := getInventory(g, inventory.NameForDigest(image.Digest))
					g.Expect(found).NotTo(BeNil(), "There is no ImageInventory of %s", image.Digest)
					g.Expect(found.Status.Facts).NotTo(BeNil(), "The ImageInventory of %s has no facts yet", image.Digest)
					g.Expect(found.Status.Facts.Manifests).NotTo(BeEmpty(), "The facts of %s list no manifest", image.Digest)
					if variantOnly == nil && image.Platform != nil && listsOnlyUnderAVariantOf(found.Status.Facts.Manifests, *image.Platform) {
						variantOnly = image
					}
				}
			}, scanTimeout).Should(Succeed())

			if variantOnly == nil {
				Skip("the fix's end-to-end case needs an image that lists its manifest only under a variant of the node's " +
					"platform, which an arm64 host gives (linux/arm64/v8 for linux/arm64); no cert-manager image here does. " +
					"The unit tests cover the matching on every host")
			}

			By("waiting for the report to name a manifest for " + variantOnly.Digest + " that is no longer Pending")
			Eventually(func(g Gomega) {
				report = getReport(g, "cert-manager", deploymentReport("cert-manager"))
				g.Expect(report).NotTo(BeNil())
				var entries []triagev1alpha1.ReportImage
				for _, image := range report.Status.Images {
					if image.Digest == variantOnly.Digest {
						entries = append(entries, image)
					}
				}
				g.Expect(entries).NotTo(BeEmpty(), "The report lists no entry of %s", variantOnly.Digest)
				for _, image := range entries {
					g.Expect(image.ManifestDigest).NotTo(BeNil(), "The image %s has no manifest", image.Digest)
					g.Expect(image.State).NotTo(Equal(triagev1alpha1.ReportImageStatePending), "The image %s", image.Digest)
				}
			}, scanTimeout).Should(Succeed())
		})

		// The report is owned by its Deployment, by the Deployment's UID, so the garbage collector of a real cluster
		// deletes it with the Deployment, which envtest has none of. The renderer also deletes a report whose workload
		// left presence.
		It("should delete the report of linked with its Deployment", func() {
			By("checking that the Deployment of linked owns its report")
			uid := kubectl(Default, "get", "deployment", linkedImage, "-n", plantedNamespace, "-o", "jsonpath={.metadata.uid}")
			Expect(uid).NotTo(BeEmpty())
			report := getReport(Default, plantedNamespace, linkedReport)
			Expect(report).NotTo(BeNil(), "There is no report of linked")
			Expect(report.OwnerReferences).To(ContainElement(And(HaveField("APIVersion", "apps/v1"),
				HaveField("Kind", "Deployment"), HaveField("Name", linkedImage), HaveField("UID", BeEquivalentTo(uid)))))

			By("deleting the Deployment of linked")
			cmd := exec.Command("kubectl", "delete", "deployment", linkedImage, "-n", plantedNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete the Deployment of linked")

			By("waiting for its report to go")
			Eventually(func(g Gomega) {
				g.Expect(getReport(g, plantedNamespace, linkedReport)).To(BeNil(), "The report of linked is still there")
			}).Should(Succeed())
		})
	})
})
