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

package localcluster_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	"github.com/bedag/vexplain/hack/internal/localcluster"
)

func TestOnlyALoopbackAddressIsLocal(t *testing.T) {
	for server, want := range map[string]bool{
		"https://127.0.0.1:6443":           true,
		"https://127.0.0.1:34567":          true,
		"https://localhost:6443":           true,
		"https://LOCALHOST:6443":           true,
		"https://[::1]:6443":               true,
		"127.0.0.1:6443":                   true,
		"localhost:6443":                   true,
		"::1":                              true,
		"https://127.1.2.3:6443":           true,
		"https://10.0.0.1:6443":            false,
		"https://192.168.1.10:6443":        false,
		"https://api.cluster.example:6443": false,
		"https://127.0.0.1.example:6443":   false,
		"https://localhost.example:6443":   false,
		"https://notlocalhost:6443":        false,
		"https://0.0.0.0:6443":             false,
		"https://[::ffff:10.0.0.1]:6443":   false,
		"":                                 false,
		"https://":                         false,
	} {
		require.Equal(t, want, localcluster.IsLoopback(server), server)
	}
}

// writeKubeconfig writes a kubeconfig whose current context, named contextName, is of a cluster at server,
// and returns its path. clusterFields are more fields of the cluster, such as "proxy-url: <url>". The cluster
// is never called: Connect makes a client and sends nothing.
func writeKubeconfig(t *testing.T, contextName, server string, clusterFields ...string) string {
	t.Helper()
	var fields strings.Builder
	for _, field := range clusterFields {
		fields.WriteString("    " + field + "\n")
	}
	kubeconfig := `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: ` + server + `
` + fields.String() + `contexts:
- name: ` + contextName + `
  context:
    cluster: test
    user: test
current-context: ` + contextName + `
users:
- name: test
  user:
    token: not-a-token
`
	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(kubeconfig), 0o600))
	return path
}

// useKubeconfigOf points KUBECONFIG at a kubeconfig of a cluster at server, whose current context is named
// contextName, so that the test never reads the kubeconfig of a developer.
func useKubeconfigOf(t *testing.T, contextName, server string) {
	t.Helper()
	t.Setenv("KUBECONFIG", writeKubeconfig(t, contextName, server))
}

// requireRefused requires that Connect refuses with want, and that it neither made a client nor let the tool
// see the configuration of the cluster.
func requireRefused(t *testing.T, want error) {
	t.Helper()
	tuned := false

	api, err := localcluster.Connect(runtime.NewScheme(), func(*rest.Config) { tuned = true })

	require.ErrorIs(t, err, want)
	require.Nil(t, api)
	require.False(t, tuned, "the configuration of a cluster that is refused is left alone")
}

// Without KUBECONFIG, kubectl falls back to the kubeconfig of the developer, whose current context can be any
// cluster, a tunnel to a remote one on a loopback address included. The tool never does: it reads no other
// kubeconfig than the one that KUBECONFIG names.
func TestConnectRefusesToRunWithoutKUBECONFIG(t *testing.T) {
	// A home whose kubeconfig would pass every other check, which Connect must not read.
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".kube"), 0o700))
	raw, err := os.ReadFile(writeKubeconfig(t, "kind-vexplain-test-e2e", "https://127.0.0.1:1"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(home, ".kube", "config"), raw, 0o600))
	t.Setenv("HOME", home)

	t.Run("set to nothing", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "")
		requireRefused(t, localcluster.ErrNoKubeconfig)
	})
	t.Run("unset", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "")
		require.NoError(t, os.Unsetenv("KUBECONFIG"))
		requireRefused(t, localcluster.ErrNoKubeconfig)
	})
}

// kind names the context of each of its clusters kind-<cluster>. Any other context is some other cluster,
// even on a loopback address, such as a tunnel to a remote one.
func TestConnectRefusesAContextThatIsNotAKindClusters(t *testing.T) {
	for what, contextName := range map[string]string{
		"another cluster's":           "dev",
		"one that only contains kind": "my-kind-cluster",
		"one that differs in case":    "KIND-vexplain-test-e2e",
	} {
		t.Run(what, func(t *testing.T) {
			useKubeconfigOf(t, contextName, "https://127.0.0.1:1")
			requireRefused(t, localcluster.ErrNotKind)
		})
	}

	t.Run("a kubeconfig that isn't there, which has no context", func(t *testing.T) {
		t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
		requireRefused(t, localcluster.ErrNotKind)
	})
}

func TestConnectRefusesAClusterThatIsNotLocal(t *testing.T) {
	useKubeconfigOf(t, "kind-vexplain-test-e2e", "https://203.0.113.7:6443")
	requireRefused(t, localcluster.ErrNotLocal)

	_, err := localcluster.Connect(runtime.NewScheme())
	require.ErrorContains(t, err, "loopback")
}

// A proxy carries the requests to wherever it is, whatever the address of the API server, and kind never writes
// one. A proxy on a loopback address can be a tunnel to another network too.
func TestConnectRefusesAClusterBehindAProxy(t *testing.T) {
	for what, proxy := range map[string]string{
		"a proxy elsewhere":         "http://203.0.113.7:3128",
		"a proxy on a loopback":     "http://127.0.0.1:3128",
		"a SOCKS proxy on the host": "socks5://localhost:1080",
	} {
		t.Run(what, func(t *testing.T) {
			t.Setenv("KUBECONFIG",
				writeKubeconfig(t, "kind-vexplain-test-e2e", "https://127.0.0.1:6443", "proxy-url: "+proxy))
			requireRefused(t, localcluster.ErrProxy)
		})
	}
}

func TestConnectGivesAClientForALocalKindClusterAndLetsTheToolTuneIt(t *testing.T) {
	useKubeconfigOf(t, "kind-vexplain-test-e2e", "https://127.0.0.1:6443")
	var host string
	var calls int

	api, err := localcluster.Connect(runtime.NewScheme(), func(cfg *rest.Config) {
		calls++
		host = cfg.Host
		cfg.QPS = 400
	})

	require.NoError(t, err)
	require.NotNil(t, api)
	require.Equal(t, 1, calls)
	require.Equal(t, "https://127.0.0.1:6443", host)
}
