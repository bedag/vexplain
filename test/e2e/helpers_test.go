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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/sdk/workloads"
	"github.com/bedag/vexplain/test/utils"
)

// collectorObjects returns the name of the Deployment, the Service and the service account that the
// operator makes for the Collector of the name.
func collectorObjects(collector string) string {
	return "vexplain-collector-" + collector
}

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
	cmd := exec.Command("kubectl", "logs", metricsPod, "-n", namespace)
	return utils.Run(cmd)
}

// metricsPod is the pod that reads the metrics endpoint: it calls the endpoint until it answers, at most 30 times,
// with curl's verbose output, and getMetricsOutput returns what it printed.
const metricsPod = "curl-metrics"

// createMetricsPod creates the metrics pod in the operator's namespace, with the token of the manager's service
// account, which the endpoint asks for. The pod meets the restricted security standard that the namespace enforces.
func createMetricsPod(token string) error {
	cmd := exec.Command("kubectl", "run", metricsPod, "--restart=Never",
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
	_, err := utils.Run(cmd)
	return err
}

// readMetrics reads the metrics endpoint again, with the token: it replaces the metrics pod with a new one, waits for
// it to finish, and returns what it printed, the series among curl's verbose output. The specs that look for a series
// read again until it is there, since the series follow the reports, which follow the cluster.
func readMetrics(g Gomega, token string) string {
	kubectl(g, "delete", "pod", metricsPod, "-n", namespace, "--ignore-not-found")
	g.Expect(createMetricsPod(token)).To(Succeed(), "Failed to create the metrics pod")
	kubectl(g, "wait", "pod", metricsPod, "-n", namespace, "--for=jsonpath={.status.phase}=Succeeded",
		"--timeout=90s")
	output, err := getMetricsOutput()
	g.Expect(err).NotTo(HaveOccurred(), "Failed to read what the metrics pod printed")
	return output
}

var (
	// seriesLine is a line of Prometheus's text format that holds a series with labels: the metric's name, its
	// labels and its value.
	seriesLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)\{(.*)\} \S+$`)
	// labelPair is one label of a series and its value, which the text format quotes.
	labelPair = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)
)

// metricSeries returns the labels of each series of the metric of the name in what a metrics pod printed. A value is
// returned as the text format escapes it, which leaves the values that the specs look for as they are.
func metricSeries(output, name string) []map[string]string {
	var found []map[string]string
	for _, line := range utils.GetNonEmptyLines(output) {
		match := seriesLine.FindStringSubmatch(line)
		if match == nil || match[1] != name {
			continue
		}
		labels := map[string]string{}
		for _, pair := range labelPair.FindAllStringSubmatch(match[2], -1) {
			labels[pair[1]] = pair[2]
		}
		found = append(found, labels)
	}
	return found
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}

// kubectl runs kubectl with the arguments, and returns what it writes to its standard output. Only that
// is returned, so that a warning of kubectl, on its standard error, can't spoil what a spec reads.
func kubectl(g Gomega, args ...string) string {
	cmd := exec.Command("kubectl", args...)
	output, err := cmd.Output()
	var exitErr *exec.ExitError
	stderr := ""
	if errors.As(err, &exitErr) {
		stderr = string(exitErr.Stderr)
	}
	g.ExpectWithOffset(1, err).NotTo(HaveOccurred(), "%q failed: %s", strings.Join(cmd.Args, " "), stderr)
	return strings.TrimSpace(string(output))
}

// kubectlApply applies a manifest.
func kubectlApply(manifest string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	return err
}

// deploymentManifest returns a Deployment of the name in the namespace ns: one replica of a pinned image, which is
// never pulled, because the suite has loaded it into the cluster. Its pods carry the label app: <name>.
func deploymentManifest(ns, name string) string {
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
`, name, ns, nginxImage)
}

// nodePortServiceManifest returns a Service of type NodePort in the namespace ns that selects the pods of the
// Deployment of the name, as deploymentManifest labels them. The API server gives its port a node port, on which every
// node forwards to them.
func nodePortServiceManifest(ns, name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  type: NodePort
  selector:
    app: %[1]s
  ports:
  - port: 80
    targetPort: 80
`, name, ns)
}

// ownNamespacePolicyManifest returns a NetworkPolicy in the namespace ns that selects the pods of the Deployment of the
// name, as deploymentManifest labels them, and lets in every pod of their namespace and nothing else. It leaves their
// egress alone.
func ownNamespacePolicyManifest(ns, name string) string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %[1]s-from-own-namespace
  namespace: %[2]s
spec:
  podSelector:
    matchLabels:
      app: %[1]s
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
`, name, ns)
}

// operatorConfigManifest returns the OperatorConfig that allowlists the key of a namespace label for owner
// attribution. It sets nothing else, so the cluster keeps its default name.
func operatorConfigManifest(namespaceLabel string) string {
	return fmt.Sprintf(`apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: OperatorConfig
metadata:
  name: %s
spec:
  ownerAttribution:
    namespaceLabels:
    - %s
`, settings.ConfigName, namespaceLabel)
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
// there is none.
func getObject[T any](g Gomega, resource, name string) *T {
	return getObjectIn[T](g, resource, "", name)
}

// getObjectIn reads the object of a resource and name in the namespace ns with kubectl, and returns nil when there is
// none. An empty ns reads a cluster-scoped object.
func getObjectIn[T any](g Gomega, resource, ns, name string) *T {
	args := []string{"get", resource, name, "--ignore-not-found", "-o", "json"}
	if ns != "" {
		args = append(args, "-n", ns)
	}
	output := kubectl(g, args...)
	if output == "" {
		return nil
	}
	var found T
	g.Expect(json.Unmarshal([]byte(output), &found)).To(Succeed(), "Failed to parse the %s", resource)
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

// workloadsOf returns the workloads that the ImageInventory of the name lists for this cluster, or none
// while it has no entry of it.
func workloadsOf(g Gomega, name string) []inventoryv1alpha1.WorkloadReference {
	found := getInventory(g, name)
	g.Expect(found).NotTo(BeNil(), "There is no ImageInventory %s", name)
	entry := entryOf(found, clusterName)
	if entry == nil {
		return nil
	}
	return entry.Workloads
}

// inventoriesOfCluster returns the names of the ImageInventory objects that have an entry of this
// cluster: one for each image that runs in it.
func inventoriesOfCluster(g Gomega) []string {
	var list inventoryv1alpha1.ImageInventoryList
	g.Expect(json.Unmarshal([]byte(kubectl(g, "get", imageInventories, "-o", "json")), &list)).To(Succeed(),
		"Failed to parse the ImageInventory objects")
	var names []string
	for i := range list.Items {
		if entryOf(&list.Items[i], clusterName) != nil {
			names = append(names, list.Items[i].Name)
		}
	}
	return names
}

// expectReady reads the Collector of the name, expects its Ready condition to be True, as for a collector
// that answers its health check, and returns it.
func expectReady(g Gomega, name string) *configv1alpha1.Collector {
	found := getObject[configv1alpha1.Collector](g, collectors, name)
	g.ExpectWithOffset(1, found).NotTo(BeNil(), "There is no Collector %s", name)
	ready := meta.FindStatusCondition(found.Status.Conditions, configv1alpha1.ConditionReady)
	g.ExpectWithOffset(1, ready).NotTo(BeNil(), "Collector %s has no Ready condition", name)
	g.ExpectWithOffset(1, ready.Status).To(Equal(metav1.ConditionTrue), "Collector %s is not Ready: %s: %s",
		name, ready.Reason, ready.Message)
	g.ExpectWithOffset(1, ready.Reason).To(Equal(configv1alpha1.ReasonHealthy), "The reason of collector %s", name)
	return found
}

// expectPlaybookReady reads the Playbook of the name, and checks that it is Ready.
func expectPlaybookReady(g Gomega, name string) *configv1alpha1.Playbook {
	found := getObject[configv1alpha1.Playbook](g, playbooks, name)
	g.ExpectWithOffset(1, found).NotTo(BeNil(), "There is no Playbook %s", name)
	ready := meta.FindStatusCondition(found.Status.Conditions, configv1alpha1.ConditionReady)
	g.ExpectWithOffset(1, ready).NotTo(BeNil(), "Playbook %s has no Ready condition", name)
	g.ExpectWithOffset(1, ready.Status).To(Equal(metav1.ConditionTrue), "Playbook %s is not Ready: %s: %s",
		name, ready.Reason, ready.Message)
	return found
}

// expectCurrent checks that a Ready object, named by what, has the status that kstatus reads as current: its
// status.observedGeneration is its generation, and it has neither Reconciling nor Stalled.
func expectCurrent(g Gomega, what string, generation int64, observed *int64, conditions []metav1.Condition) {
	g.ExpectWithOffset(1, observed).To(HaveValue(Equal(generation)), "The observedGeneration of %s", what)
	g.ExpectWithOffset(1, meta.FindStatusCondition(conditions, configv1alpha1.ConditionReconciling)).To(BeNil(),
		"%s is Ready and Reconciling", what)
	g.ExpectWithOffset(1, meta.FindStatusCondition(conditions, configv1alpha1.ConditionStalled)).To(BeNil(),
		"%s is Ready and Stalled", what)
}

// availableReplicas returns the number of available replicas of the Deployment of the operator's
// namespace with the name, as kubectl prints it: empty while there is none.
func availableReplicas(g Gomega, name string) string {
	return kubectl(g, "get", "deployment", name, "-n", namespace, "-o", "jsonpath={.status.availableReplicas}")
}

// collectorDeployment returns the workload of the Deployment of the Collector of the name, as an
// ImageInventory lists it.
func collectorDeployment(collector string) inventoryv1alpha1.WorkloadReference {
	return inventoryv1alpha1.WorkloadReference{
		APIGroup: ptr.To("apps"), Kind: "Deployment", Namespace: namespace, Name: collectorObjects(collector),
	}
}

// collectorInventory returns the name of the ImageInventory of the image that the pod of a collector
// runs, as its container's status reports it.
func collectorInventory(collector string) string {
	imageID := kubectl(Default, "get", "pods", "-n", namespace, "-l", collectorLabel+"="+collector, "-o",
		"jsonpath={.items[0].status.containerStatuses[0].imageID}")
	image, ok := workloads.DigestFromImageID(imageID)
	Expect(ok).To(BeTrue(), "The imageID %q of collector %s is no digest", imageID, collector)
	return inventory.NameForDigest(image.Digest)
}

// collectorManifest returns a Collector of the name that installs the package.
func collectorManifest(name, pkg string) string {
	return fmt.Sprintf(`apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: Collector
metadata:
  name: %s
spec:
  package: %s
`, name, pkg)
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

// managerPodLabels are the labels by which the NetworkPolicy of the collectors knows the pods of the
// manager.
var managerPodLabels = map[string]string{"control-plane": "controller-manager", "app.kubernetes.io/name": "vexplain"}

// deletePod deletes a pod of the operator's namespace, if it is there, without waiting for it to go.
func deletePod(name string) {
	cmd := exec.Command("kubectl", "delete", "pod", name, "-n", namespace, "--ignore-not-found", "--wait=false")
	_, _ = utils.Run(cmd)
}

// collectorCallerManifest returns a pod with the labels that it is given, which connects to each built-in
// collector's Service on 9443 and on 8081, and prints a line for each: "<collector>:<port> reached" when
// a connection was made, and "not reached" when none of six tries made one, each given two seconds. A
// connection is all that the policy decides, and all that the pod can make: a collector requires a client
// certificate on 9443, which the pod has none of. So curl only connects, with its telnet scheme, and says
// how many connections it made, also when the call then times out. The pod meets the restricted security
// standard that the namespace of the operator enforces.
func collectorCallerManifest(name string, labels map[string]string) string {
	var labelLines strings.Builder
	for key, value := range labels {
		_, _ = fmt.Fprintf(&labelLines, "    %s: %s\n", key, value)
	}
	labelsField := ""
	if labelLines.Len() > 0 {
		labelsField = "  labels:\n" + labelLines.String()
	}
	names := make([]string, 0, len(builtinCollectors))
	for _, collector := range builtinCollectors {
		names = append(names, collector.name)
	}
	script := fmt.Sprintf(`for c in %s; do
  for port in 9443 8081; do
    result="not reached"
    for i in 1 2 3 4 5 6; do
      connects=$(curl --silent --connect-timeout 2 --max-time 3 --output /dev/null --write-out '%%{num_connects}' \
        "telnet://vexplain-collector-$c.%s.svc:$port" </dev/null)
      if [ "$connects" = 1 ]; then result=reached; break; fi
      sleep 1
    done
    echo "$c:$port $result"
  done
done`, strings.Join(names, " "), namespace)
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

// waitForFinding waits until the default playbook's ImageVerdicts of a planted image has a finding of the
// vulnerability in the package, for as long as scanTimeout, and returns the finding and the sheet. The sheet
// of an image is named for the digest of its platform manifest, which is the digest that the registry holds,
// and for its playbook.
func waitForFinding(image, vulnerability, packageName string) (
	inventoryv1alpha1.Finding, *inventoryv1alpha1.ImageVerdicts,
) {
	name := inventory.SheetName(plantedDigests[image], defaultPlaybook)
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

// deploymentReport returns the name of the ResourceReport of the Deployment of the name: the kind in lower case, and
// the name.
func deploymentReport(deployment string) string {
	return "deployment-" + deployment
}

// getReport reads the ResourceReport of the name in the namespace ns with kubectl, and returns nil when there is
// none.
func getReport(g Gomega, ns, name string) *triagev1alpha1.ResourceReport {
	return getObjectIn[triagev1alpha1.ResourceReport](g, resourceReports, ns, name)
}

// deploymentExposure returns the exposure in the report of the Deployment of the name in the namespace ns, and fails
// while there is no report, or one without an exposure.
func deploymentExposure(g Gomega, ns, deployment string) triagev1alpha1.SSVCExposure {
	report := getReport(g, ns, deploymentReport(deployment))
	g.ExpectWithOffset(1, report).NotTo(BeNil(), "There is no report of Deployment %s/%s yet", ns, deployment)
	g.ExpectWithOffset(1, report.Status.Exposure).NotTo(BeNil(), "The report of Deployment %s/%s has no exposure",
		ns, deployment)
	return *report.Status.Exposure
}

// reportActionOf returns the action of a report for the package with the name that lists the vulnerability among its
// IDs, or nil when it lists none.
func reportActionOf(report *triagev1alpha1.ResourceReport,
	vulnerability, packageName string) *triagev1alpha1.ResourceAction {
	for i := range report.Status.Actions {
		action := &report.Status.Actions[i]
		if action.Package != nil && action.Package.Name == packageName && slices.Contains(action.VulnerabilityIDs, vulnerability) {
			return action
		}
	}
	return nil
}

// reportStepOf returns the action of a report for the package with the name and the step, or nil when it lists none.
func reportStepOf(report *triagev1alpha1.ResourceReport, packageName string,
	step triagev1alpha1.ResourceStep) *triagev1alpha1.ResourceAction {
	for i := range report.Status.Actions {
		action := &report.Status.Actions[i]
		if action.Package != nil && action.Package.Name == packageName && action.Step == step {
			return action
		}
	}
	return nil
}

// digestLabel returns the label that a report carries for an image digest that its workload runs: the prefix
// digest.vexplain.bedag.ch/ and the first 63 hex digits of the digest, as many as the name of a label holds.
func digestLabel(digest string) string {
	return "digest.vexplain.bedag.ch/" + strings.TrimPrefix(digest, "sha256:")[:63]
}

// scanWatch looks, once a second, at what a spec can't see once the scans are over: the images of
// the scan pods, and the workloads that the ImageInventory objects list while they run. A scan pod
// lives for seconds.
type scanWatch struct {
	mu         sync.Mutex
	scanImages map[string]bool
	workloads  map[string]map[string]bool
	quit       chan struct{}
	done       chan struct{}
}

// scanWatched is what a scanWatch has seen so far.
type scanWatched struct {
	// scanImages are the imageIDs of the containers of scan pods.
	scanImages map[string]bool
	// workloads holds, for the name of each ImageInventory, every workload that it listed for this
	// cluster, as workloadKey writes it.
	workloads map[string]map[string]bool
}

// workloadKey writes a workload as group/kind/namespace/name, with an empty group for the core group.
func workloadKey(w inventoryv1alpha1.WorkloadReference) string {
	return ptr.Deref(w.APIGroup, "") + "/" + w.Kind + "/" + w.Namespace + "/" + w.Name
}

// startScanWatch starts a scanWatch.
func startScanWatch() *scanWatch {
	w := &scanWatch{
		scanImages: map[string]bool{},
		workloads:  map[string]map[string]bool{},
		quit:       make(chan struct{}),
		done:       make(chan struct{}),
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
	// Not utils.Run nor kubectl: they change the working directory and log, or fail the spec, which a
	// goroutine must not.
	pods, podsErr := exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", workloads.TaskLabel, "-o",
		`jsonpath={range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{end}`).Output()
	var list inventoryv1alpha1.ImageInventoryList
	inventories, inventoriesErr := exec.Command("kubectl", "get", imageInventories, "-o", "json").Output()
	if inventoriesErr == nil {
		inventoriesErr = json.Unmarshal(inventories, &list)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if podsErr == nil {
		for _, imageID := range utils.GetNonEmptyLines(string(pods)) {
			w.scanImages[imageID] = true
		}
	}
	if inventoriesErr == nil {
		for i := range list.Items {
			entry := entryOf(&list.Items[i], clusterName)
			if entry == nil {
				continue
			}
			listed := w.workloads[list.Items[i].Name]
			if listed == nil {
				listed = map[string]bool{}
				w.workloads[list.Items[i].Name] = listed
			}
			for _, workload := range entry.Workloads {
				listed[workloadKey(workload)] = true
			}
		}
	}
}

// seen returns a copy of what the watch has seen.
func (w *scanWatch) seen() scanWatched {
	w.mu.Lock()
	defer w.mu.Unlock()
	copied := scanWatched{scanImages: map[string]bool{}, workloads: map[string]map[string]bool{}}
	for imageID := range w.scanImages {
		copied.scanImages[imageID] = true
	}
	for name, listed := range w.workloads {
		copied.workloads[name] = map[string]bool{}
		for workload := range listed {
			copied.workloads[name][workload] = true
		}
	}
	return copied
}

// stop stops the watch, and waits for its last look.
func (w *scanWatch) stop() {
	close(w.quit)
	<-w.done
}

// The objects through which the operator grants a collector what it declares (decision 0041), by the kinds that
// kubectl reads them as, each named vexplain-collector-<name>: a ClusterRole and its binding for what the collector
// needs in the whole cluster, and a Role and its binding, in the operator's namespace, for what it needs there.
var (
	clusterGrant    = []string{"clusterrole", "clusterrolebinding"}
	namespacedGrant = []string{"role", "rolebinding"}
	// roleOf names the kind of the role of each kind of binding.
	roleOf = map[string]string{"clusterrolebinding": "ClusterRole", "rolebinding": "Role"}
)

// rbacObject is what the specs read of an object of RBAC: a role's rules, and a binding's role and subjects.
type rbacObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Rules             []rbacv1.PolicyRule `json:"rules"`
	RoleRef           *rbacv1.RoleRef     `json:"roleRef"`
	Subjects          []rbacv1.Subject    `json:"subjects"`
}

// expectGrant checks that the operator granted the collector of the name, whose Collector has the UID uid, through
// objects of the kinds and of no other kind: each carries the collector's label and is owned by the Collector, a
// role holds rules, and a binding binds the role of the grant to the collector's service account. No other binding of
// the cluster names that service account, so what the collector holds, the operator granted.
func expectGrant(g Gomega, collector string, uid types.UID, kinds []string) {
	name := collectorObjects(collector)
	account := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: name, Namespace: namespace}
	var bindings []string
	for _, kind := range slices.Concat(clusterGrant, namespacedGrant) {
		// kubectl ignores the namespace for the cluster-scoped kinds.
		granted := getObjectIn[rbacObject](g, kind, namespace, name)
		if !slices.Contains(kinds, kind) {
			g.ExpectWithOffset(1, granted).To(BeNil(), "Collector %s has a %s", collector, kind)
			continue
		}
		g.ExpectWithOffset(1, granted).NotTo(BeNil(), "Collector %s has no %s", collector, kind)
		g.ExpectWithOffset(1, granted.Labels).To(HaveKeyWithValue(collectorLabel, collector),
			"The labels of the %s of collector %s", kind, collector)
		g.ExpectWithOffset(1, granted.OwnerReferences).To(ConsistOf(And(HaveField("Kind", "Collector"),
			HaveField("Name", collector), HaveField("UID", uid), HaveField("Controller", HaveValue(BeTrue())))),
			"The owner of the %s of collector %s", kind, collector)
		role, isBinding := roleOf[kind]
		if !isBinding {
			g.ExpectWithOffset(1, granted.Rules).NotTo(BeEmpty(), "The rules of the %s of collector %s", kind, collector)
			continue
		}
		g.ExpectWithOffset(1, granted.RoleRef).To(HaveValue(And(HaveField("Kind", role), HaveField("Name", name))),
			"The role of the %s of collector %s", kind, collector)
		g.ExpectWithOffset(1, granted.Subjects).To(ConsistOf(account), "The subjects of the %s of collector %s", kind,
			collector)
		bindings = append(bindings, granted.Kind+"/"+name)
	}

	var all struct {
		Items []rbacObject `json:"items"`
	}
	listed := kubectl(g, "get", "clusterrolebindings,rolebindings", "-A", "-o", "json")
	g.ExpectWithOffset(1, json.Unmarshal([]byte(listed), &all)).To(Succeed(), "Failed to parse the bindings")
	var naming []string
	for _, binding := range all.Items {
		if slices.Contains(binding.Subjects, account) {
			naming = append(naming, binding.Kind+"/"+binding.Name)
		}
	}
	g.ExpectWithOffset(1, naming).To(ConsistOf(bindings), "The bindings that name the service account of collector %s",
		collector)
}

// permissionsOf returns what the rules allow, one permission each, as API group/resource and verb, sorted and each
// once, so that two lists of rules compare by what they allow, whatever rules hold it. A permission of a rule that
// names objects keeps their names, and a rule of URLs gives a permission for each, which no collector can declare.
func permissionsOf(rules []rbacv1.PolicyRule) []string {
	var permissions []string
	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			for _, group := range rule.APIGroups {
				for _, resource := range rule.Resources {
					permissions = append(permissions, fmt.Sprintf("%s/%s %s %v", group, resource, verb, rule.ResourceNames))
				}
			}
			for _, url := range rule.NonResourceURLs {
				permissions = append(permissions, url+" "+verb)
			}
		}
	}
	slices.Sort(permissions)
	return slices.Compact(permissions)
}

// rulesPatch returns the merge patch that replaces the rules of a ClusterRole with rules.
func rulesPatch(rules []rbacv1.PolicyRule) string {
	patch, err := json.Marshal(map[string]any{"rules": rules})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return string(patch)
}

// expectNotAllowed checks that the Collector of the name isn't Ready, because the operator may not grant it a rule
// that it declares, which the message of the condition names by what has the text named.
func expectNotAllowed(g Gomega, collector, named string) {
	found := getObject[configv1alpha1.Collector](g, collectors, collector)
	g.ExpectWithOffset(1, found).NotTo(BeNil(), "There is no Collector %s", collector)
	ready := meta.FindStatusCondition(found.Status.Conditions, configv1alpha1.ConditionReady)
	g.ExpectWithOffset(1, ready).NotTo(BeNil(), "Collector %s has no Ready condition", collector)
	g.ExpectWithOffset(1, ready.Status).To(Equal(metav1.ConditionFalse), "Collector %s is Ready", collector)
	g.ExpectWithOffset(1, ready.Reason).To(Equal(configv1alpha1.ReasonPermissionsNotAllowed),
		"The reason of collector %s: %s", collector, ready.Message)
	g.ExpectWithOffset(1, ready.Message).To(ContainSubstring(named), "The message of collector %s", collector)
}

// runNow asks the operator to run the schedules of the Collector of the name now, with a value of the annotation that
// it never had, and waits until the operator handled it: it recorded the value as the one that it handled last, after
// it fired the schedule of the name without a failure.
func runNow(collector, schedule string) {
	// The times of the status are to the second, and the operator's clock is the host's, within a moment: a fire for
	// the request is at most a few seconds older than this.
	asked := time.Now().Add(-5 * time.Second)
	value := fmt.Sprintf("e2e-%d", time.Now().UnixNano())
	kubectl(Default, "annotate", "--overwrite", collectors, collector, configv1alpha1.AnnotationRunNow+"="+value)
	Eventually(func(g Gomega) {
		found := getObject[configv1alpha1.Collector](g, collectors, collector)
		g.Expect(found).NotTo(BeNil(), "There is no Collector %s", collector)
		g.Expect(found.Status.LastHandledRunNow).To(HaveValue(Equal(value)), "The run now that collector %s handled",
			collector)
		i := slices.IndexFunc(found.Status.Schedules, func(s configv1alpha1.ScheduleStatus) bool {
			return s.Name == schedule
		})
		g.Expect(i).NotTo(Equal(-1), "Collector %s lists no schedule %s", collector, schedule)
		fired := found.Status.Schedules[i]
		g.Expect(fired.LastFireTime).NotTo(BeNil(), "The schedule %s never fired", schedule)
		g.Expect(fired.LastFireTime.Time).To(BeTemporally(">=", asked), "The last fire of the schedule %s", schedule)
		g.Expect(fired.LastFailure).To(BeNil(), "The last fire of the schedule %s failed", schedule)
	}).WithOffset(1).Should(Succeed())
}

// collectorPods returns the names of the pods of the collector of the name.
func collectorPods(g Gomega, collector string) []string {
	return strings.Fields(kubectl(g, "get", "pods", "-n", namespace, "-l", collectorLabel+"="+collector,
		"-o", "jsonpath={.items[*].metadata.name}"))
}

// peerNamespacePolicyManifest returns a NetworkPolicy in the namespace ns that selects the pods of the Deployment of
// the name, as deploymentManifest labels them, and lets in every pod of the namespace peer and nothing else, by the
// label kubernetes.io/metadata.name that the API server gives every namespace. It leaves their egress alone.
func peerNamespacePolicyManifest(ns, name, peer string) string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %[1]s-from-%[3]s
  namespace: %[2]s
spec:
  podSelector:
    matchLabels:
      app: %[1]s
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: %[3]s
`, name, ns, peer)
}

// trustingSettings returns the settings of network-reach that trust every pod of the namespace ns, by the label that
// the API server gives every namespace, as a merge patch of its Collector.
func trustingSettings(ns string) string {
	return fmt.Sprintf(`{"spec": {"settings": {"trustedPeers": [`+
		`{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": %q}}}]}}}`, ns)
}

// pairManifest returns the namespace of the pair, with the label that the playbook onePlaybook selects, and the
// Deployment pair in it: one replica that runs a planted image in each of its two containers, by its digest, as
// plantedDeploymentManifest does, and sleeps.
func pairManifest() string {
	var containers strings.Builder
	for _, c := range pairContainers {
		_, _ = fmt.Fprintf(&containers, `      - name: %s
        image: %s/%s@%s
        command: ["sleep", "86400"]
`, c.name, registryHost, c.image, plantedDigests[c.image])
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
  labels:
    %[2]s: %[3]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[4]s
  namespace: %[1]s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[4]s
  template:
    metadata:
      labels:
        app: %[4]s
    spec:
      terminationGracePeriodSeconds: 1
      containers:
%[5]s`, pairNamespace, playbookLabel, onePlaybook, pairDeployment, containers.String())
}

// onePlaybookManifest returns the Playbook onePlaybook, which applies in the namespaces that carry its name in the
// label playbookLabel. It judges the vulnerabilities of the images that run, as the default playbook does, with the
// rule known-exploited alone, which reads no evidence: its evidence is the SBOM, which the vulnerabilities
// collector matches.
func onePlaybookManifest() string {
	return fmt.Sprintf(`apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: Playbook
metadata:
  name: %[1]s
spec:
  match:
    namespaces:
      matchLabels:
        %[2]s: %[1]s
  subjects:
    type: %[3]s
  findings:
    type: %[4]s
  evidence:
  - name: sbom
    type: %[5]s
  pipeline:
  - rule: known-exploited
`, onePlaybook, playbookLabel, presenceType, findingsType, sbomType)
}

// actionsOf returns the actions of a report that the playbook asks for, about the package with the name in the image
// of the digest.
func actionsOf(report *triagev1alpha1.ResourceReport, playbook, digest,
	packageName string) []triagev1alpha1.ResourceAction {
	var found []triagev1alpha1.ResourceAction
	for _, action := range report.Status.Actions {
		if action.Requirement.Playbook == playbook && ptr.Deref(action.Digest, "") == digest && action.Package != nil &&
			action.Package.Name == packageName {
			found = append(found, action)
		}
	}
	return found
}

// playbooksOf returns the playbooks that the actions of a report ask for, sorted and each once.
func playbooksOf(report *triagev1alpha1.ResourceReport) []string {
	var named []string
	for _, action := range report.Status.Actions {
		named = append(named, action.Requirement.Playbook)
	}
	slices.Sort(named)
	return slices.Compact(named)
}

// listsOnlyUnderAVariantOf reports whether the manifests list one for the platform, which names no variant, only under
// a platform that does: os/architecture/variant of the same os and architecture, and none under the platform itself.
func listsOnlyUnderAVariantOf(manifests []inventoryv1alpha1.ManifestFact, platform string) bool {
	if len(strings.Split(platform, "/")) != 2 {
		return false
	}
	variant := false
	for _, m := range manifests {
		if m.Platform == platform {
			return false
		}
		if parts := strings.Split(m.Platform, "/"); len(parts) == 3 && parts[0]+"/"+parts[1] == platform {
			variant = true
		}
	}
	return variant
}
