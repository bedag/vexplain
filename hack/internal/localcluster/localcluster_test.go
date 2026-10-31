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

// useKubeconfigOf points KUBECONFIG at a kubeconfig of a cluster at server, so that the test never reads the
// kubeconfig of a developer. The cluster is never called: Connect makes a client and sends nothing.
func useKubeconfigOf(t *testing.T, server string) {
	t.Helper()
	kubeconfig := `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: ` + server + `
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user:
    token: not-a-token
`
	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(kubeconfig), 0o600))
	t.Setenv("KUBECONFIG", path)
}

func TestConnectRefusesAClusterThatIsNotLocal(t *testing.T) {
	useKubeconfigOf(t, "https://203.0.113.7:6443")
	tuned := false

	api, err := localcluster.Connect(runtime.NewScheme(), func(*rest.Config) { tuned = true })

	require.ErrorIs(t, err, localcluster.ErrNotLocal)
	require.ErrorContains(t, err, "loopback")
	require.Nil(t, api)
	require.False(t, tuned, "the configuration of a cluster that is refused is left alone")
}

func TestConnectGivesAClientForALocalClusterAndLetsTheToolTuneIt(t *testing.T) {
	useKubeconfigOf(t, "https://127.0.0.1:6443")
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
