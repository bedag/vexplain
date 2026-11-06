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
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
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
// there is none.
func getObject[T any](g Gomega, resource, name string) *T {
	output := kubectl(g, "get", resource, name, "--ignore-not-found", "-o", "json")
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

// collectorBindingManifest returns a ClusterRoleBinding that binds the ClusterRole of the name to the
// service account of the Collector of the name, as an admin binds the roles of a collector.
func collectorBindingManifest(collector, clusterRole string) string {
	return fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %[2]s
subjects:
- kind: ServiceAccount
  name: %[1]s
  namespace: %[3]s
`, collectorObjects(collector), clusterRole, namespace)
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
