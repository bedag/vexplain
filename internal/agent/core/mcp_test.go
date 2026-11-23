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

package core_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/collectorclient/mcptest"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

const (
	// wiki is an MCP collector, whose list allows the stand-in's search and get_page, and not its delete_page.
	wiki = "wiki"
	// The tools of wiki, as the agent calls them.
	wikiSearch, wikiGetPage, wikiDeletePage = wiki + "__" + mcptest.Search, wiki + "__" + mcptest.GetPage,
		wiki + "__" + mcptest.DeletePage
	// wikiToken is what the Secret of wiki's headers sends, and what the stand-in takes. It never reaches the model,
	// the ledger or the log.
	wikiToken = "token-of-the-wiki-mcp-server"
	// operatorNamespace holds the Secret of wiki's headers.
	operatorNamespace = "vexplain-system"
	// page is what the calls of the wiki's tools look for.
	page = "brotli"
)

// paging returns the arguments of get_page and delete_page. search takes those of search_tools, a query: find.
func paging() map[string]any { return map[string]any{"id": page} }

// wikiTools returns the forwarder over the MCP collector wiki, whose Secret sends token, under the grants, and the
// stand-in of its server. Without grants, the profile grants every tool of the stand-in, delete_page too.
func wikiTools(t *testing.T, token string, grants ...configv1alpha1.AgentToolGrant) (*core.CollectorTools, *mcptest.Server) {
	t.Helper()
	server := mcptest.NewServer(wikiToken)
	t.Cleanup(server.Close)
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	const secret = "wiki-mcp"
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: wiki}, Spec: configv1alpha1.CollectorSpec{
			MCP: &configv1alpha1.CollectorMCP{URL: server.Endpoint(), Tools: []string{mcptest.Search, mcptest.GetPage},
				HeadersFrom: []configv1alpha1.MCPHeaders{{SecretRef: configv1alpha1.SecretReference{Name: secret}}}}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secret, Namespace: operatorNamespace,
			Labels: map[string]string{configv1alpha1.MCPHeadersLabel: "true"}},
			Data: map[string][]byte{"Authorization": []byte("Bearer " + token + "\n")}},
	).WithIndex(&corev1.Secret{}, "metadata.name", func(o client.Object) []string { return []string{o.GetName()} }).Build()
	if grants == nil {
		grants = []configv1alpha1.AgentToolGrant{{Collector: wiki,
			Operations: []string{mcptest.Search, mcptest.GetPage, mcptest.DeletePage}}}
	}
	return &core.CollectorTools{Reader: reader, Pool: &pool{}, Grants: grants, Subject: theSubject,
		MCP: &collectorclient.MCPPool{Reader: reader, Secrets: reader, Namespace: operatorNamespace,
			HTTPClient: server.Client()},
		Context: func(context.Context) (*collectorv1alpha1.Context, error) {
			return &collectorv1alpha1.Context{Cluster: cluster}, nil
		}}, server
}

// The Collector's list says what vexplain may ever call on the server: a tool off it is never offered and never called,
// whatever the profile grants, and its call is refused before any request.
func TestAToolOffTheCollectorsListIsNeverCalled(t *testing.T) {
	for _, grants := range [][]configv1alpha1.AgentToolGrant{
		{{Collector: wiki, Operations: []string{mcptest.Search, mcptest.DeletePage}}},
		{{Collector: wiki}},
	} {
		tools, server := wikiTools(t, wikiToken, grants...)
		found, err := tools.Tools(t.Context())
		require.NoError(t, err)
		require.Contains(t, names(found), wikiSearch)
		require.NotContains(t, names(found), wikiDeletePage, "never found, whatever the profile grants")

		before := server.Requests()
		_, _, err = tools.Call(t.Context(), wikiDeletePage, json.RawMessage(`{"id":"brotli"}`))
		require.Error(t, err)
		require.Equal(t, before, server.Requests(), "refused before any request")

		f := start(t, options{forwarder: tools})
		text, failed := f.call(t, "search_tools", find("delete a page of the wiki"))
		require.False(t, failed, text)
		require.NotContains(t, text, mcptest.DeletePage)
		res, err := f.client.CallTool(t.Context(), &mcp.CallToolParams{Name: wikiDeletePage,
			Arguments: paging()})
		require.True(t, err != nil || res.IsError, "a tool that the session never loaded")
		require.Zero(t, server.Calls(mcptest.DeletePage))
	}
}

// What an MCP collector's tool answers is external evidence, always: an answer and an error alike. It never fetches.
func TestAnMCPToolsOutputIsExternal(t *testing.T) {
	tools, server := wikiTools(t, wikiToken)
	found, err := tools.Tools(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{wikiGetPage, wikiSearch}, names(found))
	for _, tool := range found {
		require.False(t, tool.Fetches, "%s fetches no page that the core checks", tool.Name)
		require.Contains(t, string(tool.InputSchema), `"type":"object"`, "with the server's schema")
	}
	f := start(t, options{forwarder: tools})
	_, failed := f.call(t, "search_tools", find("search pages of the wiki"))
	require.False(t, failed)

	text, failed := f.call(t, wikiSearch, find(page))
	require.False(t, failed, text)
	require.Contains(t, text, "The page about brotli says: update the image.")
	require.Equal(t, 1, server.Calls(mcptest.Search))
	entry, ok := f.session.Outcome().Ledger.Entry("ev-2")
	require.True(t, ok)
	require.Equal(t, wikiSearch, entry.Tool)
	require.Equal(t, ledger.External, entry.Trust)

	text, failed = f.call(t, wikiGetPage, paging())
	require.True(t, failed, "an answer that is an error is a tool error")
	require.Contains(t, text, "the wiki has no page brotli", "with the server's text")
	entry, _ = f.session.Outcome().Ledger.Entry("ev-3")
	require.Equal(t, ledger.External, entry.Trust)
}

// The headers of an MCP collector are secret. They reach no output, error or log line, even from a server that echoes
// them: a careless one in its answers, and a gateway that refuses them in its errors.
func TestTheHeadersNeverReachTheLedgerOrTheLog(t *testing.T) {
	var mu sync.Mutex
	var log strings.Builder
	ctx := logf.IntoContext(t.Context(), funcr.New(func(prefix, args string) {
		mu.Lock()
		defer mu.Unlock()
		log.WriteString(prefix + " " + args + "\n")
	}, funcr.Options{Verbosity: 10}))
	logged := func() string {
		mu.Lock()
		defer mu.Unlock()
		return log.String()
	}

	tools, server := wikiTools(t, wikiToken)
	f := start(t, options{forwarder: tools})
	_, failed := f.call(t, "search_tools", find("search pages of the wiki"))
	require.False(t, failed)
	text, failed := f.call(t, wikiSearch, find(page))
	require.False(t, failed, text)
	require.Contains(t, text, "Asked with", "the server echoed the header")
	// shown collects what the model was shown, the ledger holds, the forwarder returned and the log holds.
	var shown strings.Builder
	shown.WriteString(text)
	text, _ = f.call(t, wikiGetPage, paging())
	require.Contains(t, text, "asked with", "the server echoed the header in its error")
	shown.WriteString(text)
	for _, e := range f.session.Outcome().Ledger.Entries() {
		shown.WriteString(string(e.Output) + f.stored(t, e.ID).Output)
	}

	out, _, err := tools.Call(ctx, wikiSearch, json.RawMessage(`{"query":"brotli"}`))
	require.NoError(t, err)
	shown.Write(out)
	_, _, err = tools.Call(ctx, wikiGetPage, json.RawMessage(`{"id":"brotli"}`))
	require.Error(t, err)
	shown.WriteString(err.Error())

	const refusedToken = "token-that-the-wiki-mcp-server-refuses"
	refused, _ := wikiTools(t, refusedToken)
	_, _, err = refused.Call(ctx, wikiSearch, json.RawMessage(`{"query":"brotli"}`))
	require.Error(t, err)
	shown.WriteString(err.Error())
	require.Contains(t, logged(), "unauthorized: [withheld]", "the server's error, which echoed the header, is logged")
	found, err := refused.Tools(ctx)
	require.NoError(t, err)
	require.Empty(t, found, "a server that refuses the headers offers no tool")
	require.NotEmpty(t, logged(), "the failures are logged")
	require.GreaterOrEqual(t, server.Calls(mcptest.Search), 2)

	shown.WriteString(logged())
	require.NotContains(t, shown.String(), wikiToken)
	require.NotContains(t, shown.String(), refusedToken)
}
