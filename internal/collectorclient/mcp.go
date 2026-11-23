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

package collectorclient

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// ErrMCPTool is the error of a call whose answer is an error: the tool's own, which the error's text holds.
var ErrMCPTool = errors.New("the tool answered with an error")

// minWithheld is the shortest value of a header, or word of one, that the MCPPool withholds: a shorter one would
// garble text that merely holds it, and is no credential worth the name.
const minWithheld = 8

// The pool lists the Secrets of the headers through the API reader, by their name and label, in the operator's
// namespace, so the rule is a Role there. Markers generate no bindings: config/rbac/manager_secrets_rolebinding.yaml
// binds it.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=list,namespace=vexplain-system

// MCPPool calls the tools of the MCP collectors: the Collectors that name an MCP server that runs elsewhere (design of
// the agent on image cases, 5.9). It speaks MCP's Streamable HTTP transport, with the headers of the Collector's
// labelled Secrets, and follows no redirect, which would take the headers to another server. An answer takes 16 MiB
// at most, as a message of the collector API does.
//
// It lists and calls only the tools on the Collector's list: a tool off it is never listed, and its call is refused
// before any request. A header's value, and each word of it, of 8 bytes or more, is withheld from what it returns,
// errors included, so that a server that echoes one can't show it. It is safe for concurrent use.
//
// shortcut: each listing or call opens a session of its own, which costs an initialize round trip; keep sessions open
// if calls become frequent.
type MCPPool struct {
	// Reader reads the Collectors.
	Reader client.Reader
	// Secrets lists the Secrets of the headers, which the manager's cache doesn't hold: the API reader. It lists only
	// those that carry the label, so a Secret without it is never read.
	Secrets client.Reader
	// Namespace is the operator's, which holds the Secrets.
	Namespace string
	// HTTPClient's transport takes the requests. Nil means http.DefaultTransport, which honours HTTPS_PROXY, NO_PROXY
	// and SSL_CERT_FILE.
	HTTPClient *http.Client
}

// Tools returns the tools that the collector's MCP server serves and its Collector lists, with their descriptions and
// input schemas.
func (p *MCPPool) Tools(ctx context.Context, collector string) ([]*mcp.Tool, error) {
	c, err := p.collector(ctx, collector)
	if err != nil {
		return nil, err
	}
	session, withheld, err := p.connect(ctx, c)
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	var tools []*mcp.Tool
	for t, err := range session.Tools(ctx, nil) {
		if err != nil {
			return nil, withhold(withheld, fmt.Errorf("list the tools of the MCP server of collector %s: %w", collector, err))
		}
		if !slices.Contains(c.Spec.MCP.Tools, t.Name) ||
			slices.ContainsFunc(tools, func(listed *mcp.Tool) bool { return listed.Name == t.Name }) {
			continue
		}
		t.Description = withheld.Replace(t.Description)
		if schema, err := json.Marshal(t.InputSchema); err == nil {
			t.InputSchema = json.RawMessage(withheld.Replace(string(schema)))
		}
		tools = append(tools, t)
	}
	return tools, nil
}

// Call calls the tool of the collector's MCP server with the arguments, and returns the text of its answer. It refuses a
// tool off the Collector's list before any request. An answer that is an error is ErrMCPTool, with the answer's text.
func (p *MCPPool) Call(ctx context.Context, collector, tool string, args json.RawMessage) (string, error) {
	c, err := p.collector(ctx, collector)
	if err != nil {
		return "", err
	}
	if !slices.Contains(c.Spec.MCP.Tools, tool) {
		return "", fmt.Errorf("the tool %s isn't on the list of collector %s", tool, collector)
	}
	session, withheld, err := p.connect(ctx, c)
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return "", withhold(withheld, fmt.Errorf("call the tool %s of collector %s: %w", tool, collector, err))
	}
	text := withheld.Replace(textOf(res))
	if res.IsError {
		return "", fmt.Errorf("%w: %s", ErrMCPTool, text)
	}
	return text, nil
}

// collector reads the Collector of the name, which must name an MCP server.
func (p *MCPPool) collector(ctx context.Context, name string) (*configv1alpha1.Collector, error) {
	var c configv1alpha1.Collector
	if err := p.Reader.Get(ctx, client.ObjectKey{Name: name}, &c); err != nil {
		return nil, fmt.Errorf("read the Collector %s: %w", name, err)
	}
	if c.Spec.MCP == nil {
		return nil, fmt.Errorf("the Collector %s names no MCP server", name)
	}
	return &c, nil
}

// connect opens a session with the MCP server of c, with the headers of its Secrets, and returns it with what to
// withhold of them.
func (p *MCPPool) connect(ctx context.Context, c *configv1alpha1.Collector) (*mcp.ClientSession, *strings.Replacer, error) {
	header := http.Header{}
	for _, from := range c.Spec.MCP.HeadersFrom {
		var secrets corev1.SecretList
		if err := p.Secrets.List(ctx, &secrets, client.InNamespace(p.Namespace),
			client.MatchingLabels{configv1alpha1.MCPHeadersLabel: "true"},
			client.MatchingFields{"metadata.name": from.SecretRef.Name}); err != nil {
			return nil, nil, fmt.Errorf("read the Secret %s/%s of the headers: %w", p.Namespace, from.SecretRef.Name, err)
		}
		if len(secrets.Items) == 0 {
			return nil, nil, fmt.Errorf("the Secret %s/%s of the headers doesn't exist, or doesn't carry the label %s: "+
				`"true"`, p.Namespace, from.SecretRef.Name, configv1alpha1.MCPHeadersLabel)
		}
		for name, value := range secrets.Items[0].Data {
			header.Set(name, strings.TrimSpace(string(value)))
		}
	}
	withheld := withholding(header)
	base := http.DefaultTransport
	if p.HTTPClient != nil && p.HTTPClient.Transport != nil {
		base = p.HTTPClient.Transport
	}
	transport := &mcp.StreamableClientTransport{Endpoint: c.Spec.MCP.URL, DisableStandaloneSSE: true,
		HTTPClient: &http.Client{Transport: headerTransport{header: header, base: base},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("the MCP server redirects, and vexplain follows no redirect")
			}}}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "vexplain", Version: configv1alpha1.GroupVersion.Version}, nil).
		Connect(ctx, transport, nil)
	if err != nil {
		return nil, nil, withhold(withheld, fmt.Errorf("connect to the MCP server of collector %s: %w", c.Name, err))
	}
	return session, withheld, nil
}

// headerTransport adds the headers to each request, and bounds each answer to maxMessageSize.
type headerTransport struct {
	header http.Header
	base   http.RoundTripper
}

func (t headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	maps.Copy(req.Header, t.header)
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, maxMessageSize)
	return resp, nil
}

// withholding returns the replacer that withholds the values of the headers, and each word of them, of minWithheld
// bytes or more. The replacer tries them in their order, so the longest comes first: a secret that starts with a
// shorter one is withheld whole, and not up to the shorter one's end, which would show the rest of it.
func withholding(header http.Header) *strings.Replacer {
	var secrets []string
	for _, values := range header {
		for _, v := range values {
			for _, s := range append([]string{v}, strings.Fields(v)...) {
				if len(s) >= minWithheld {
					secrets = append(secrets, s)
				}
			}
		}
	}
	slices.SortFunc(secrets, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	pairs := make([]string, 0, 2*len(secrets))
	for _, s := range secrets {
		pairs = append(pairs, s, "[withheld]")
	}
	return strings.NewReplacer(pairs...)
}

// withhold returns the error with what the replacer withholds replaced.
func withhold(withheld *strings.Replacer, err error) error {
	return errors.New(withheld.Replace(err.Error()))
}

// textOf returns the text of the answer's content, one item a line. Content that isn't text is left out, and said so.
func textOf(res *mcp.CallToolResult) string {
	var out strings.Builder
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			out.WriteString(t.Text)
		} else {
			out.WriteString("[content that isn't text, which vexplain leaves out]")
		}
		out.WriteByte('\n')
	}
	return out.String()
}
