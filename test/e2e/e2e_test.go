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
	modelConfigs     = "modelconfigs.config.vexplain.bedag.ch"
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

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", managerImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
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

		By("cleaning up the namespace of the workload, and the ModelConfig")
		cmd = exec.Command("kubectl", "delete", "ns", workloadNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", modelConfigs, modelConfigName, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
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

// getInventory reads the ImageInventory of a name with kubectl, and returns nil when there is none.
// Only the standard output is parsed, so that a warning of kubectl can't break the JSON.
func getInventory(g Gomega, name string) *inventoryv1alpha1.ImageInventory {
	cmd := exec.Command("kubectl", "get", imageInventories, name, "--ignore-not-found", "-o", "json")
	output, err := cmd.Output()
	g.Expect(err).NotTo(HaveOccurred(), "%q failed", strings.Join(cmd.Args, " "))
	if strings.TrimSpace(string(output)) == "" {
		return nil
	}
	var found inventoryv1alpha1.ImageInventory
	g.Expect(json.Unmarshal(output, &found)).To(Succeed(), "Failed to parse the ImageInventory")
	return &found
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
