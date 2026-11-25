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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/test/utils"
)

// What the specs of remote spokes create and look for, by the names of docs/remote-spokes.md.
const (
	// spokeName is the spoke's cluster, as the OperatorConfig of test/e2e/config-spoke names it, and its Spoke on the
	// hub. The hub's own cluster keeps the default name, clusterName, which a Spoke may not have.
	spokeName = "cluster-a"
	// spokeCredentials is the admin's Secret of the spoke on the hub, and hubTokenSecret the hub's own, into which it
	// renews its token.
	spokeCredentials = "cluster-a-credentials"
	hubTokenSecret   = "spoke-cluster-a-token"
	// hubAccount is the ServiceAccount that a spoke's install makes for the hub, in the operator's namespace.
	hubAccount = "vexplain-hub"

	spokes    = "spokes.config.vexplain.bedag.ch"
	evidences = "evidences.inventory.vexplain.bedag.ch"
)

// The kind cluster of the spoke and its kubeconfig, which make test-e2e sets up besides the hub's.
var (
	spokeCluster    = os.Getenv("KIND_SPOKE_CLUSTER")
	spokeKubeconfig = os.Getenv("E2E_SPOKE_KUBECONFIG")
)

// A hub and a spoke on two kind clusters, on kind's one Docker network (design section 6): the hub runs config/hub, the
// spoke config/spoke, and the hub reaches the spoke's API server directly. The admin's steps are those of
// docs/remote-spokes.md.
var _ = Describe("Remote spokes", Ordered, func() {
	// adminVersion is the resource version of the admin's Secret once it is made, which the hub never writes.
	var adminVersion string

	BeforeAll(func() {
		requireSpokeCluster()

		// The spoke runs the manager and its two collectors, which kind loads, and pulls the planted images from the
		// local registry.
		for _, image := range []string{managerImage, workloadsImage, networkReachImage} {
			By(fmt.Sprintf("loading %s on the spoke's cluster", image))
			Expect(utils.LoadImageToNamedKindCluster(image, spokeCluster)).To(Succeed(), "Failed to load %s", image)
		}

		// Both installs hold objects of vexplain's kinds, which kubectl can only apply once their CRDs serve them.
		for _, kubeconfig := range []string{os.Getenv("KUBECONFIG"), spokeKubeconfig} {
			By("installing the CRDs with " + kubeconfig)
			_, err := utils.Run(exec.Command("make", "install", "KUBECONFIG="+kubeconfig))
			Expect(err).NotTo(HaveOccurred(), "Failed to install the CRDs")
			kubectl(Default, "--kubeconfig", kubeconfig, "wait", "--for=condition=Established", "crd", "--all",
				"--timeout=60s")
		}

		By("deploying the hub and the spoke")
		_, err := utils.Run(exec.Command("make", append([]string{"deploy", "DEPLOY_CONFIG=test/e2e/config-hub"},
			imageVariables(scannerPackage)...)...))
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the hub")
		_, err = utils.Run(exec.Command("make", append([]string{"deploy", "DEPLOY_CONFIG=test/e2e/config-spoke",
			"KUBECONFIG=" + spokeKubeconfig}, imageVariables(scannerPackage)...)...))
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the spoke")

		// A vulnerabilities collector without its database fails the first matches, and the hub then waits longer
		// before each next try, as in the specs of scanning.
		By("waiting for the hub's vulnerabilities collector to load its database")
		Eventually(func(g Gomega) {
			logs := kubectl(g, "logs", "deployment/"+collectorObjects("vulnerabilities"), "-n", namespace)
			g.Expect(logs).To(ContainSubstring(databaseLoaded))
		}, 10*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterAll(func() {
		// As docs/remote-spokes.md removes a spoke: the Spoke goes first, while the hub's manager removes its
		// finalizer. A Spoke that keeps its finalizer would hold the deletion of its CRD, and with it the next install
		// of the CRDs, so the finalizer goes when the manager can't remove it.
		By("deleting the Spoke")
		if _, err := utils.Run(exec.Command("kubectl", "delete", spokes, spokeName, "--ignore-not-found",
			"--timeout=2m")); err != nil {
			_, _ = utils.Run(exec.Command("kubectl", "patch", spokes, spokeName, "--type=merge",
				"-p", `{"metadata":{"finalizers":null}}`))
		}

		By("undeploying the spoke")
		_, _ = utils.Run(exec.Command("kubectl", onSpoke("delete", "ns", plantedNamespace, "--ignore-not-found")...))
		_, _ = utils.Run(exec.Command("make", "undeploy", "DEPLOY_CONFIG=test/e2e/config-spoke",
			"KUBECONFIG="+spokeKubeconfig, "ignore-not-found=true"))

		By("undeploying the hub")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", socNamespace, "--ignore-not-found"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", operatorConfigs, settings.ConfigName, "--ignore-not-found"))
		_, _ = utils.Run(exec.Command("make", "undeploy", "DEPLOY_CONFIG=test/e2e/config-hub", "ignore-not-found=true"))
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		// Neither the Spoke nor a manager's log holds a token, so the suite may print them.
		for _, args := range [][]string{
			{"get", spokes, "-o", "yaml"},
			{"get", investigations, "-n", socNamespace, "-o", "yaml"},
			{"get", imageInventories, "-o", "custom-columns=NAME:.metadata.name,CLUSTERS:.status.clusters[*].cluster"},
			{"get", "events", "-n", namespace, "--sort-by=.lastTimestamp"},
			{"logs", "-l", managerLabel, "-n", namespace, "--tail=-1"},
			onSpoke("get", "pods", "-A"),
			onSpoke("get", collectors, "-o", "yaml"),
			onSpoke("logs", "-l", managerLabel, "-n", namespace, "--tail=-1"),
		} {
			output, err := utils.Run(exec.Command("kubectl", args...))
			_, _ = fmt.Fprintf(GinkgoWriter, "kubectl %s (err %v):\n%s\n", strings.Join(args, " "), err, output)
		}
	})

	It("should turn the Spoke Ready and Synced with the spoke's API server, its CA and a token of its account", func() {
		By("reading the spoke's API server and CA as the hub's pods reach them, on the kind network")
		internal, err := exec.Command(utils.KindBinary(), "get", "kubeconfig", "--internal", "--name", spokeCluster).Output()
		Expect(err).NotTo(HaveOccurred(), "Failed to read the internal kubeconfig of the spoke's cluster")
		config, err := clientcmd.Load(internal)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.Clusters).To(HaveLen(1), "The clusters of the spoke's internal kubeconfig")
		var server string
		var ca []byte
		for _, cluster := range config.Clusters {
			server, ca = cluster.Server, cluster.CertificateAuthorityData
		}

		// The token lives 10 minutes, as the hub's own do, rather than the guide's hour: so the hub renews within 6
		// minutes from any moment, at half the lifetime and with the minute between its checks.
		By("creating a token of the hub's account on the spoke")
		token := kubectl(Default, onSpoke("create", "token", hubAccount, "-n", namespace, "--duration=10m")...)

		// As in the guide, the token goes in from a file, which keeps it out of the arguments of a process, and so out of
		// the suite's output too.
		By("creating the admin's Secret on the hub")
		dir, err := os.MkdirTemp("", "vexplain-e2e-spoke-")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.RemoveAll(dir) }()
		caFile, tokenFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token")
		Expect(os.WriteFile(caFile, ca, 0o600)).To(Succeed())
		Expect(os.WriteFile(tokenFile, []byte(token), 0o600)).To(Succeed())
		kubectl(Default, "create", "secret", "generic", spokeCredentials, "-n", namespace, "--from-literal=server="+server,
			"--from-file=ca.crt="+caFile, "--from-file=token="+tokenFile)
		adminVersion = kubectl(Default, "get", "secret", spokeCredentials, "-n", namespace,
			"-o", "jsonpath={.metadata.resourceVersion}")

		By("creating the Spoke, named like the spoke's cluster")
		Expect(kubectlApply(fmt.Sprintf(`apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: Spoke
metadata:
  name: %s
spec:
  credentialsSecretRef:
    name: %s
`, spokeName, spokeCredentials))).To(Succeed(), "Failed to create the Spoke")

		By("waiting for it to be Ready and Synced, with the spoke's identity and its collectors")
		spokeID := kubectl(Default, onSpoke("get", "ns", "kube-system", "-o", "jsonpath={.metadata.uid}")...)
		Eventually(func(g Gomega) {
			found := getSpoke(g)
			g.Expect(found.Status.Conditions).To(ContainElements(
				haveCondition(configv1alpha1.ConditionReady, metav1.ConditionTrue),
				haveCondition(configv1alpha1.ConditionSynced, metav1.ConditionTrue)), "The conditions of the Spoke")
			g.Expect(found.Status.ClusterID).To(HaveValue(Equal(spokeID)), "The identity that the Spoke recorded")
			g.Expect(found.Status.Collectors).To(ConsistOf(HaveField("Name", "workloads"),
				HaveField("Name", "network-reach")), "The spoke's collectors, as the hub read them")
			g.Expect(found.Status.TokenExpirationTime).NotTo(BeNil(), "The Spoke says no expiry of its token")
		}, 5*time.Minute).Should(Succeed())
	})

	It("should give a Deployment on the spoke a case on the hub, through an investigation", func() {
		By("starting a Deployment of linked on the spoke, which pulls it from the local registry by its digest")
		kubectl(Default, onSpoke("create", "ns", plantedNamespace)...)
		Expect(kubectlApply(plantedDeploymentManifest(linkedImage), onSpoke()...)).To(Succeed(),
			"Failed to create the Deployment on the spoke")

		By("waiting for the hub to copy what the spoke runs")
		Eventually(expectCopies, scanTimeout).Should(Succeed())

		// With the agent switched off, an investigation shows where its cases are open, without a model.
		By("switching the hub's agent off, and creating an investigation of the known exploited vulnerability")
		Expect(kubectlApply(fmt.Sprintf(`apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: OperatorConfig
metadata:
  name: %s
spec:
  agent:
    state: Disabled
`, settings.ConfigName))).To(Succeed(), "Failed to switch the hub's agent off")
		kubectl(Default, "create", "ns", socNamespace)
		Expect(kubectlApply(investigationManifest(socNamespace, socInvestigation, exploitedVulnerability, ""))).To(Succeed(),
			"Failed to create the Investigation")

		By("waiting for the case of linked, which runs in the spoke's cluster alone")
		Eventually(func(g Gomega) {
			expectRemoteCase(g)
			found := getObjectIn[triagev1alpha1.Investigation](g, investigations, socNamespace, socInvestigation)
			g.Expect(found.Status.Impact).NotTo(BeNil(), "The investigation shows no impact")
			g.Expect(found.Status.Impact.Clusters).To(HaveValue(Equal(int32(1))), "The clusters of the impact")
		}, scanTimeout).Should(Succeed())
	})

	It("should scan the image on the hub with the test's login, though no pod of the hub runs it", func() {
		digest := plantedDigests[linkedImage]
		By("checking that no pod of the hub runs linked")
		running := kubectl(Default, "get", "pods", "-A", "-o",
			`jsonpath={range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{end}`)
		Expect(running).NotTo(ContainSubstring(digest), "A pod of the hub runs linked")

		By("checking the facts of linked")
		Eventually(func(g Gomega) { expectScanned(g, linkedImage) }).Should(Succeed())

		// The scanner names a scan Job after the start of the digest, and deletes it once it has the result. The events
		// of the Job stay.
		By("checking that a scan Job of linked made its pod on the hub")
		events := kubectl(Default, "get", "events", "-n", namespace, "--field-selector", "involvedObject.kind=Job",
			"-o", `jsonpath={range .items[*]}{.involvedObject.name} {.reason}{"\n"}{end}`)
		Expect(utils.GetNonEmptyLines(events)).To(ContainElement(MatchRegexp(`^scan-%s-[a-z0-9]{5} SuccessfulCreate$`,
			strings.TrimPrefix(digest, "sha256:")[:12])), "The events of the scan Jobs on the hub")
	})

	It("should give the hub's account no right to write vexplain's records on the spoke", func() {
		as := fmt.Sprintf("--as=system:serviceaccount:%s:%s", namespace, hubAccount)
		// The first answer shows that the others are those of the hub's account.
		for _, check := range []struct{ verb, resource, answer string }{
			{"list", evidences, "yes"},
			{"create", evidences, "no"},
			{"patch", imageInventories, "no"},
		} {
			// kubectl auth can-i exits with 1 when it says no.
			output, _ := exec.Command("kubectl", onSpoke("auth", "can-i", check.verb, check.resource, as)...).Output()
			Expect(strings.TrimSpace(string(output))).To(Equal(check.answer), "May the hub %s %s?", check.verb,
				check.resource)
		}
	})

	It("should renew the token within 6 minutes into the hub's own Secret, and leave the admin's unchanged", func() {
		before := getSpoke(Default).Status.TokenExpirationTime
		Expect(before).NotTo(BeNil(), "The Spoke says no expiry of its token")

		By("waiting for the expiry of the hub's token to move on")
		Eventually(func(g Gomega) {
			g.Expect(getSpoke(g).Status.TokenExpirationTime).To(HaveValue(HaveField("Time",
				BeTemporally(">", before.Time))), "The expiry of the hub's token")
		}, 6*time.Minute, 5*time.Second).Should(Succeed())

		By("checking the hub's own Secret, which the Spoke owns, and the admin's, which the hub never writes")
		owner := kubectl(Default, "get", "secret", hubTokenSecret, "-n", namespace, "-o", "jsonpath="+
			"{.metadata.ownerReferences[*].kind}/{.metadata.ownerReferences[*].name}/{.metadata.ownerReferences[*].controller}")
		Expect(owner).To(Equal("Spoke/"+spokeName+"/true"), "The owner of the hub's own Secret")
		Expect(kubectl(Default, "get", "secret", spokeCredentials, "-n", namespace,
			"-o", "jsonpath={.metadata.resourceVersion}")).To(Equal(adminVersion), "The version of the admin's Secret")
		expectNoTokenShown()
	})

	It("should keep the copies and the case of an unreachable spoke, also across a restart of the hub's manager", func() {
		By("stopping the spoke's control plane")
		for _, node := range spokeNodes() {
			_, err := utils.Run(exec.Command("docker", "stop", node))
			Expect(err).NotTo(HaveOccurred(), "Failed to stop %s", node)
		}

		By("waiting for the Spoke to turn Connected False")
		Eventually(func(g Gomega) {
			g.Expect(getSpoke(g).Status.Conditions).To(ContainElement(And(
				haveCondition(configv1alpha1.ConditionConnected, metav1.ConditionFalse),
				HaveField("Reason", configv1alpha1.ReasonUnreachable))), "The conditions of the Spoke")
		}, 3*time.Minute).Should(Succeed())
		expectCopies(Default)
		expectRemoteCase(Default)

		By("restarting the hub's manager")
		kubectl(Default, "scale", "deployment", managerDeployment, "-n", namespace, "--replicas=0")
		Eventually(func(g Gomega) {
			g.Expect(kubectl(g, "get", "pods", "-l", managerLabel, "-n", namespace, "-o", "name")).To(BeEmpty(),
				"A pod of the manager is still there")
		}).Should(Succeed())
		kubectl(Default, "scale", "deployment", managerDeployment, "-n", namespace, "--replicas=1")
		kubectl(Default, "rollout", "status", "deployment", managerDeployment, "-n", namespace, "--timeout=3m")

		// Each controller reconciles every object of its kind once its workers start: the new manager checks the Spoke,
		// and builds the investigation again, at once.
		By("waiting for the new manager's controller of the Spokes to start")
		Eventually(func(g Gomega) {
			g.Expect(kubectl(g, "logs", "-l", managerLabel, "-n", namespace, "--tail=-1")).To(
				MatchRegexp(`Starting workers\s+\{"controller": "config-spoke"`))
		}).Should(Succeed())

		By("checking that the Spoke stays not Connected, and that its copies and its case stay")
		Consistently(func(g Gomega) {
			g.Expect(getSpoke(g).Status.Conditions).To(ContainElement(
				haveCondition(configv1alpha1.ConditionConnected, metav1.ConditionFalse)), "The conditions of the Spoke")
			expectCopies(g)
			expectRemoteCase(g)
		}, 30*time.Second, 5*time.Second).Should(Succeed())
	})

	It("should turn the Spoke Ready again once the spoke is back", func() {
		By("starting the spoke's control plane again")
		for _, node := range spokeNodes() {
			_, err := utils.Run(exec.Command("docker", "start", node))
			Expect(err).NotTo(HaveOccurred(), "Failed to start %s", node)
		}

		By("waiting for the Spoke to be Ready, and to hold its copies")
		Eventually(func(g Gomega) {
			g.Expect(getSpoke(g).Status.Conditions).To(ContainElement(
				haveCondition(configv1alpha1.ConditionReady, metav1.ConditionTrue)), "The conditions of the Spoke")
		}, 5*time.Minute, 5*time.Second).Should(Succeed())
		Eventually(expectCopies).Should(Succeed())
		expectNoTokenShown()
	})

	It("should delete its copies with the Spoke, and the hub's own Secret of the spoke", func() {
		By("deleting the Spoke")
		kubectl(Default, "delete", spokes, spokeName, "--timeout=2m")

		// Only a real cluster's garbage collector deletes the Secret, which the Spoke owns: envtest runs none.
		By("waiting for the copies of the spoke's records and the hub's own Secret of the spoke to go")
		Eventually(func(g Gomega) {
			g.Expect(kubectl(g, "get", evidences, "-l", "vexplain.bedag.ch/cluster="+spokeName, "-o", "name")).To(BeEmpty(),
				"The hub's copies of the spoke's streamed records")
			g.Expect(inventoriesOfCluster(g, spokeName)).To(BeEmpty(),
				"The ImageInventory objects with an entry of the spoke's cluster")
			g.Expect(kubectl(g, "get", "secret", hubTokenSecret, "-n", namespace, "--ignore-not-found", "-o", "name")).To(
				BeEmpty(), "The hub's own Secret of the spoke")
		}).Should(Succeed())
	})
})

// requireSpokeCluster stops the specs of remote spokes unless the spoke's kubeconfig is set to the spoke's kind
// cluster, which isn't the hub's, as requireKindCluster checks the hub's: the specs install and remove the operator
// there, and stop its node.
func requireSpokeCluster() {
	ExpectWithOffset(1, spokeKubeconfig).NotTo(BeEmpty(),
		"E2E_SPOKE_KUBECONFIG is not set. Run the suite with make test-e2e, which sets up the spoke's kind cluster")
	ExpectWithOffset(1, spokeCluster).NotTo(BeElementOf("", utils.KindCluster()),
		"KIND_SPOKE_CLUSTER names no kind cluster of its own")
	ExpectWithOffset(1, kubectl(Default, onSpoke("config", "current-context")...)).To(Equal("kind-"+spokeCluster),
		"The spoke's kubeconfig is not set to the spoke's kind cluster")
}

// onSpoke returns the arguments of kubectl after the flag that points it at the spoke's cluster.
func onSpoke(args ...string) []string {
	return append([]string{"--kubeconfig", spokeKubeconfig}, args...)
}

// spokeNodes returns the nodes of the spoke's cluster: the containers that make up its control plane.
func spokeNodes() []string {
	output, err := exec.Command(utils.KindBinary(), "get", "nodes", "--name", spokeCluster).Output()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to list the nodes of the spoke's cluster")
	nodes := strings.Fields(string(output))
	ExpectWithOffset(1, nodes).NotTo(BeEmpty(), "The spoke's cluster has no node")
	return nodes
}

// getSpoke reads the Spoke, and fails g while there is none.
func getSpoke(g Gomega) *configv1alpha1.Spoke {
	found := getObject[configv1alpha1.Spoke](g, spokes, spokeName)
	g.ExpectWithOffset(1, found).NotTo(BeNil(), "There is no Spoke %s", spokeName)
	return found
}

// haveCondition matches a condition of the type with the status.
func haveCondition(conditionType string, status metav1.ConditionStatus) gomegatypes.GomegaMatcher {
	return And(HaveField("Type", conditionType), HaveField("Status", status))
}

// expectCopies checks that the hub holds its copies of what the spoke runs: the spoke's presence record that names the
// Deployment of linked, and the entry of the spoke's cluster in the ImageInventory of linked, which lists it.
func expectCopies(g Gomega) {
	var subjects []string
	for _, data := range onHub(g, "vexplain.bedag.ch/cluster="+spokeName, presenceType) {
		var presence sdkevidence.Presence
		g.ExpectWithOffset(1, json.Unmarshal(data, &presence)).To(Succeed())
		for _, w := range presence.Workloads {
			subjects = append(subjects, w.Subject)
		}
	}
	g.ExpectWithOffset(1, subjects).To(ContainElement(workloadSubject(spokeName, plantedNamespace, linkedImage)),
		"The workloads of the hub's copies of the spoke's presence")

	found := getInventory(g, inventory.NameForDigest(plantedDigests[linkedImage]))
	g.ExpectWithOffset(1, found).NotTo(BeNil(), "There is no ImageInventory of linked")
	entry := entryOf(found, spokeName)
	g.ExpectWithOffset(1, entry).NotTo(BeNil(), "The ImageInventory of linked has no entry of the spoke's cluster")
	g.ExpectWithOffset(1, entry.Workloads).To(ContainElement(inventoryv1alpha1.WorkloadReference{
		APIGroup: ptr.To("apps"), Kind: "Deployment", Namespace: plantedNamespace, Name: linkedImage,
	}), "The workloads of the spoke's entry")
}

// expectRemoteCase checks that the investigation shows the case of the known exploited vulnerability in linked, open,
// in the namespace of the spoke's cluster that runs it.
func expectRemoteCase(g Gomega) {
	result := caseResult(g, socNamespace, socInvestigation, exploitedVulnerability, linkedImage)
	g.ExpectWithOffset(1, result).NotTo(BeNil(), "The investigation shows no case of %s in linked", exploitedVulnerability)
	g.ExpectWithOffset(1, result.Status).To(HaveValue(Equal(triagev1alpha1.VEXStatusUnderInvestigation)),
		"The status of the case")
	g.ExpectWithOffset(1, result.Owners).To(ContainElement(And(HaveField("Cluster", spokeName),
		HaveField("Namespace", plantedNamespace))), "The namespaces that run the case")
}

// expectNoTokenShown checks that neither the log of the hub's manager nor the Spoke holds the admin's token or the
// hub's own. A failure names neither token, so that the suite's output never holds one.
func expectNoTokenShown() {
	shown := kubectl(Default, "logs", "-l", managerLabel, "-n", namespace, "--tail=-1") +
		kubectl(Default, "get", spokes, spokeName, "-o", "yaml")
	for _, secret := range []string{spokeCredentials, hubTokenSecret} {
		token, err := base64.StdEncoding.DecodeString(kubectl(Default, "get", "secret", secret, "-n", namespace,
			"-o", "jsonpath={.data.token}"))
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "The token of the Secret %s isn't base64", secret)
		ExpectWithOffset(1, token).NotTo(BeEmpty(), "The Secret %s holds no token", secret)
		ExpectWithOffset(1, strings.Contains(shown, string(token))).To(BeFalse(),
			"The hub shows the token of the Secret %s", secret)
	}
}
