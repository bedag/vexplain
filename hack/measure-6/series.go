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

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// reportSeries prints the series of vexplain_open_case on the hub, by cluster, and the size of the whole scrape.
func (m *measurement) reportSeries(ctx context.Context) error {
	raw, err := m.scrapeManager(ctx)
	if err != nil {
		return err
	}
	families, err := parseMetrics(raw)
	if err != nil {
		return err
	}
	byCluster := map[string]int{}
	for _, metric := range families["vexplain_open_case"].GetMetric() {
		byCluster[labelsOf(metric)["cluster"]]++
	}
	series := 0
	for _, family := range families {
		series += len(family.GetMetric())
	}
	openCaseBytes := 0
	for line := range bytes.Lines(raw) {
		if bytes.HasPrefix(line, []byte("vexplain_open_case{")) {
			openCaseBytes += len(line)
		}
	}
	m.say("\nthe manager's metrics: %d B, %d series in %d families; vexplain_open_case: %d series in %d B\n", len(raw),
		series, len(families), len(families["vexplain_open_case"].GetMetric()), openCaseBytes)
	for _, clusterName := range slices.Sorted(maps.Keys(byCluster)) {
		m.say("  %s: %d\n", clusterName, byCluster[clusterName])
	}
	return nil
}

// scrapeManager reads the hub manager's metrics through a port forward of kubectl, with a token of the tool's own
// ServiceAccount, which may read them. The token stays in memory.
func (m *measurement) scrapeManager(ctx context.Context) ([]byte, error) {
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: toolAccount, Namespace: operatorNamespace}}
	if err := m.hub.api.Create(ctx, account); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: toolAccount},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: metricsReader},
		Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: toolAccount, Namespace: operatorNamespace}}}
	if err := m.hub.api.Create(ctx, binding); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	token, err := m.hub.clientset.CoreV1().ServiceAccounts(operatorNamespace).CreateToken(ctx, toolAccount,
		&authenticationv1.TokenRequest{}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	pod, err := managerPod(ctx, m.hub, "")
	if err != nil {
		return nil, err
	}
	address, stop, err := portForward(ctx, m.hub, pod.Name, managerMetricsPort)
	if err != nil {
		return nil, err
	}
	defer stop()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token.Status.Token)
	// The manager serves its metrics with a certificate of its own making, at the end of a forward to 127.0.0.1. The
	// transport has no proxy, so the request stays on the machine.
	httpClient := &http.Client{Timeout: time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // see above
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the manager's metrics answered %s", response.Status)
	}
	return io.ReadAll(response.Body)
}

// forwardingPattern finds the local port in what kubectl port-forward prints once it forwards.
var forwardingPattern = regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:([0-9]+) `)

// portForward forwards a free local port to the port of the pod in the operator's namespace with kubectl, which reads
// the cluster's own kubeconfig, and returns its address and a function that stops the forward.
func portForward(ctx context.Context, c *cluster, pod string, port int) (string, func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", c.kubeconfig, "port-forward", "-n", operatorNamespace,
		"pod/"+pod, ":"+strconv.Itoa(port))
	output, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return "", nil, err
	}
	if err = cmd.Start(); err != nil {
		cancel()
		return "", nil, err
	}
	stop := func() {
		cancel()
		_ = cmd.Wait()
	}
	lines := bufio.NewScanner(output)
	for lines.Scan() {
		if found := forwardingPattern.FindStringSubmatch(lines.Text()); found != nil {
			go func() {
				for lines.Scan() { // kubectl blocks once nobody reads what it prints.
				}
			}()
			return "127.0.0.1:" + found[1], stop, nil
		}
	}
	stop()
	return "", nil, errors.New("kubectl port-forward ended before it forwarded")
}

// apiServerMetrics reads the metrics of the cluster's API server.
func apiServerMetrics(ctx context.Context, c *cluster) (map[string]*dto.MetricFamily, error) {
	raw, err := c.clientset.CoreV1().RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the API server's metrics: %w", err)
	}
	return parseMetrics(raw)
}

// collectorMetrics reads the metrics of the pod of a collector's Deployment, which a collector serves in plain HTTP,
// through the API server's proxy.
func collectorMetrics(ctx context.Context, c *cluster, deployment string) (map[string]*dto.MetricFamily, error) {
	pods, err := podsOf(ctx, c, deployment)
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		return nil, fmt.Errorf("%s has no pod", deployment)
	}
	raw, err := c.clientset.CoreV1().RESTClient().Get().Namespace(operatorNamespace).Resource("pods").
		Name(pods[0].Name + ":" + strconv.Itoa(collectorMetricsPort)).SubResource("proxy").Suffix("metrics").
		DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the metrics of %s: %w", deployment, err)
	}
	return parseMetrics(raw)
}

// parseMetrics parses metrics in Prometheus' text format.
func parseMetrics(raw []byte) (map[string]*dto.MetricFamily, error) {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	return parser.TextToMetricFamilies(bytes.NewReader(raw))
}

// gaugeOf sums the values of the series of a gauge.
func gaugeOf(families map[string]*dto.MetricFamily, family string) float64 {
	total := 0.0
	for _, metric := range families[family].GetMetric() {
		total += metric.GetGauge().GetValue()
	}
	return total
}

func labelsOf(metric *dto.Metric) map[string]string {
	labels := map[string]string{}
	for _, pair := range metric.GetLabel() {
		labels[pair.GetName()] = pair.GetValue()
	}
	return labels
}
