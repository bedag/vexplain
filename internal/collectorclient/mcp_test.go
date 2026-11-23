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

package collectorclient_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
)

// authorization is the header that the tests' servers take.
const authorization = "Authorization"

// A secret that is a prefix of another is withheld only after the longer one, whatever the order of the headers, and
// of the words of a value: an echo of the longer one shows no tail.
func TestTheLongerOfTwoSecretsThatShareAPrefixIsWithheldWhole(t *testing.T) {
	const short, long = "sk-abcdefgh", "sk-abcdefgh-SECRETTAIL"
	for name, header := range map[string]http.Header{
		"two headers":         {"X-Api-Key": {short}, authorization: {long}},
		"two words of one":    {authorization: {short + " " + long}},
		"two words, reversed": {authorization: {long + " " + short}},
	} {
		// The headers are a map, whose order changes from one range to the next.
		for range 50 {
			require.Equal(t, "[withheld], and [withheld]",
				collectorclient.Withholding(header).Replace(long+", and "+short), name)
		}
	}
}

// An MCP server that redirects gets no answer from vexplain: the headers never reach the server that it names.
func TestAnMCPServerThatRedirectsNeverGetsTheHeadersElsewhere(t *testing.T) {
	var mu sync.Mutex
	var reached []string
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		reached = append(reached, r.Header.Get(authorization))
	}))
	t.Cleanup(elsewhere.Close)
	redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)
	const wiki, token = "wiki", "Bearer token-of-the-wiki-mcp-server"
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: wiki}, Spec: configv1alpha1.CollectorSpec{
			MCP: &configv1alpha1.CollectorMCP{URL: redirecting.URL + "/mcp", Tools: []string{"search"},
				HeadersFrom: []configv1alpha1.MCPHeaders{{SecretRef: configv1alpha1.SecretReference{Name: wiki}}}}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: wiki, Namespace: namespace,
			Labels: map[string]string{configv1alpha1.MCPHeadersLabel: "true"}},
			Data: map[string][]byte{authorization: []byte(token)}},
	).WithIndex(&corev1.Secret{}, "metadata.name", func(o client.Object) []string { return []string{o.GetName()} }).Build()
	pool := &collectorclient.MCPPool{Reader: reader, Secrets: reader, Namespace: namespace,
		HTTPClient: redirecting.Client()}

	_, listErr := pool.Tools(t.Context(), wiki)
	_, callErr := pool.Call(t.Context(), wiki, "search", json.RawMessage(`{"query":"brotli"}`))

	mu.Lock()
	defer mu.Unlock()
	require.Empty(t, reached, "no request reached the server that the redirect named, nor its headers")
	require.ErrorContains(t, listErr, "redirect")
	require.ErrorContains(t, callErr, "redirect")
}
