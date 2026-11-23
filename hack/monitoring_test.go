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

package hack

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// renderMonitoring renders the install with its [PROMETHEUS] line switched on, with the kustomize that the Makefile
// pins, on a copy of config/ so that the working tree stays as it is. It returns the rendered objects by kind and
// name.
func renderMonitoring(t *testing.T) map[string]map[string]any {
	t.Helper()
	kustomize := os.Getenv("KUSTOMIZE")
	if kustomize == "" {
		kustomize = filepath.Join("..", "bin", "kustomize")
	}
	kustomize, err := filepath.Abs(kustomize)
	require.NoError(t, err)
	_, err = os.Stat(kustomize)
	require.NoError(t, err, "make kustomize installs the pinned kustomize")

	tmp := t.TempDir()
	require.NoError(t, os.CopyFS(tmp, os.DirFS("../config")))
	file := filepath.Join(tmp, "default", "kustomization.yaml")
	content, err := os.ReadFile(file)
	require.NoError(t, err)
	const off = "#- ../prometheus"
	require.Contains(t, string(content), off, "the [PROMETHEUS] line is commented out in the repository")
	require.NoError(t, os.WriteFile(file, []byte(strings.Replace(string(content), off, "- ../prometheus", 1)), 0o644))

	out, err := exec.Command(kustomize, "build", filepath.Join(tmp, "default")).CombinedOutput()
	require.NoError(t, err, string(out))

	objects := map[string]map[string]any{}
	for doc := range strings.SplitSeq(string(out), "\n---\n") {
		var object map[string]any
		require.NoError(t, yaml.Unmarshal([]byte(doc), &object))
		metadata, _ := object["metadata"].(map[string]any)
		objects[object["kind"].(string)+"/"+metadata["name"].(string)] = object
	}
	return objects
}

// at reads the value at a path of keys and indexes, and fails the test when the path leads nowhere.
func at(t *testing.T, object any, path ...any) any {
	t.Helper()
	for _, step := range path {
		switch key := step.(type) {
		case string:
			m, ok := object.(map[string]any)
			require.True(t, ok, "no map at %v", step)
			object = m[key]
		case int:
			l, ok := object.([]any)
			require.True(t, ok && key < len(l), "no item %d", key)
			object = l[key]
		}
	}
	return object
}

// TestTheMonitoringRendersWithoutAFile checks that what config/prometheus ships reads its token from a Secret rather
// than from a file of the scraper's pod, which managed Prometheus setups refuse, and that every reference between the
// objects names the prefixed objects that the install makes.
func TestTheMonitoringRendersWithoutAFile(t *testing.T) {
	objects := renderMonitoring(t)
	kinds := slices.Sorted(maps.Keys(objects))

	for _, name := range []string{"controller-manager", "agent", "collectors"} {
		require.Contains(t, kinds, "ServiceMonitor/vexplain-"+name)
	}
	require.Contains(t, kinds, "ClusterRole/vexplain-metrics-reader")

	for key, object := range objects {
		if strings.HasPrefix(key, "ServiceMonitor/") {
			require.NotContains(t, mustMarshal(t, object), "bearerTokenFile", key)
		}
	}
	for _, name := range []string{"controller-manager", "agent"} {
		monitor := objects["ServiceMonitor/vexplain-"+name]
		require.Equal(t, "https", at(t, monitor, "spec", "endpoints", 0, "scheme"), name)
		require.Equal(t, "vexplain-metrics-scraper-token",
			at(t, monitor, "spec", "endpoints", 0, "authorization", "credentials", "name"), name)
	}
	require.Equal(t, "http", at(t, objects["ServiceMonitor/vexplain-collectors"], "spec", "endpoints", 0, "port"))

	binding := objects["ClusterRoleBinding/vexplain-metrics-scraper"]
	require.Equal(t, "vexplain-metrics-reader", at(t, binding, "roleRef", "name"))
	require.Equal(t, "vexplain-metrics-scraper", at(t, binding, "subjects", 0, "name"))
	require.Equal(t, "vexplain-system", at(t, binding, "subjects", 0, "namespace"))

	secret := objects["Secret/vexplain-metrics-scraper-token"]
	require.Equal(t, "vexplain-metrics-scraper",
		at(t, secret, "metadata", "annotations", "kubernetes.io/service-account.name"))
	require.Contains(t, kinds, "ServiceAccount/vexplain-metrics-scraper")

	// Only the kubebuilder labels: no label that belongs to one platform's Prometheus.
	for _, key := range []string{"ServiceMonitor/vexplain-controller-manager", "ServiceMonitor/vexplain-agent",
		"ServiceMonitor/vexplain-collectors", "Secret/vexplain-metrics-scraper-token",
		"ServiceAccount/vexplain-metrics-scraper", "ClusterRoleBinding/vexplain-metrics-scraper"} {
		labels, _ := at(t, objects[key], "metadata").(map[string]any)["labels"].(map[string]any)
		for label := range labels {
			require.True(t, strings.HasPrefix(label, "app.kubernetes.io/") || label == "control-plane",
				"%s carries the label %s", key, label)
		}
	}
}

func mustMarshal(t *testing.T, object any) string {
	t.Helper()
	out, err := yaml.Marshal(object)
	require.NoError(t, err)
	return string(out)
}
