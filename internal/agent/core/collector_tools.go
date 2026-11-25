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

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/text"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/hosts"
)

// CollectorPool reaches the collectors: *collectorclient.Pool.
type CollectorPool interface {
	Capabilities(ctx context.Context, collector string) (*collectorv1alpha1.GetCapabilitiesResponse, error)
	Invoke(ctx context.Context, collector string, req *collectorv1alpha1.InvokeRequest, opts ...collectorclient.InvokeOption) (
		[]cloudevents.Event, *collectorclient.Failure, error)
}

var _ CollectorPool = (*collectorclient.Pool)(nil)

// MCPPool reaches the MCP collectors' servers: *collectorclient.MCPPool. It lists and calls only the tools on a
// Collector's list.
type MCPPool interface {
	Tools(ctx context.Context, collector string) ([]*mcp.Tool, error)
	Call(ctx context.Context, collector, tool string, args json.RawMessage) (string, error)
}

var _ MCPPool = (*collectorclient.MCPPool)(nil)

// CollectorTools forwards to the operations of collectors that a profile grants, as tools named
// <collector>__<operation> (design of the agent on image cases, 5.7). It offers an operation only when it runs in the
// hub's role and takes its input from the agent alone: a spoke operation, such as scan, is never a tool. The output of
// a call is the data of the answer's events, of known trust when each is of a type that the operation declares, but
// for a page, which anyone can write. An operation that produces pages fetches them, and the core checks its URLs.
//
// The operations' descriptions, roles and parameter schemas come from the collector's GetCapabilities, which the
// Collector's status doesn't record. A collector that can't be used now offers no tool.
//
// An MCP collector offers the tools of its server that its Collector lists, as tools named <collector>__<tool>, with
// the server's descriptions and input schemas (5.9). A tool off the list is never offered, and its call is refused
// before any request, whatever the grant. The output of a call is external evidence, always, and an MCP tool never
// fetches for the core: a server that fetches pages answers for them itself.
type CollectorTools struct {
	// Reader reads the Collectors, and Pool calls them. MCP calls the MCP collectors' servers; nil offers none of their
	// tools.
	Reader client.Reader
	Pool   CollectorPool
	MCP    MCPPool
	// Context builds the context of the collectors, as for every call of the hub.
	Context func(context.Context) (*collectorv1alpha1.Context, error)
	// Grants are the profile's grants.
	Grants []configv1alpha1.AgentToolGrant
	// Subject is the subject of the case, such as manifest/sha256:<64 hex>, which the calls are for.
	Subject string
}

var _ Forwarder = (*CollectorTools)(nil)

// toolSeparator separates a collector's name from its operation's in a tool's name. A collector's name is a DNS label,
// which has no underscore.
const toolSeparator = "__"

// Tools returns the granted operations of the collectors, and the granted tools of the MCP collectors, that can be used
// now.
func (f *CollectorTools) Tools(ctx context.Context) ([]Tool, error) {
	var tools []Tool
	for _, g := range f.Grants {
		c, err := f.collector(ctx, g.Collector)
		var operations []*collectorv1alpha1.Operation
		if err == nil {
			operations, err = f.operations(ctx, c)
		}
		if err != nil {
			logf.FromContext(ctx).V(1).Info("A granted collector offers no tool now", "collector", g.Collector,
				"reason", err.Error())
			continue
		}
		for _, op := range operations {
			if granted(g, op.GetName()) {
				t := Tool{Name: g.Collector + toolSeparator + op.GetName(),
					Description: op.GetDescription(), InputSchema: op.GetParameterSchema(),
					Fetches: slices.Contains(op.GetProduces(), sdkevidence.TypePage)}
				if t.Fetches {
					t.AllowedDomains = allowedDomains(c)
				}
				tools = append(tools, t)
			}
		}
	}
	return tools, nil
}

// Call runs the operation that the tool names with the model's arguments as its parameters, for the case's subject.
// It refuses an operation that the profile doesn't grant, or that isn't a tool, before any call. Its errors say what
// failed in vexplain's words, with the collector's reason and a short message: never the settings, an address, or
// more of the collector's text, which could carry them.
func (f *CollectorTools) Call(ctx context.Context, tool string, args json.RawMessage) ([]byte, ledger.Trust, error) {
	collector, operation, _ := strings.Cut(tool, toolSeparator)
	if !slices.ContainsFunc(f.Grants, func(g configv1alpha1.AgentToolGrant) bool {
		return g.Collector == collector && granted(g, operation)
	}) {
		return nil, "", fmt.Errorf("the profile doesn't allow the tool %s", tool)
	}
	c, err := f.collector(ctx, collector)
	if err != nil {
		return nil, "", fmt.Errorf("%s can't be called now: %w", tool, err)
	}
	if c.Spec.MCP != nil {
		return f.callMCP(ctx, c, tool, operation, args)
	}
	operations, err := f.operations(ctx, c)
	if err != nil {
		return nil, "", fmt.Errorf("%s can't be called now: %w", tool, err)
	}
	i := slices.IndexFunc(operations, func(op *collectorv1alpha1.Operation) bool { return op.GetName() == operation })
	if i < 0 {
		return nil, "", fmt.Errorf("%s is no operation of the collector that the agent can call", tool)
	}
	clusterContext, err := f.Context(ctx)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not build the context of the collectors", "tool", tool)
		return nil, "", fmt.Errorf("vexplain could not build the context of %s's call", tool)
	}
	req := &collectorv1alpha1.InvokeRequest{Operation: operation, Subject: f.Subject, Parameters: args,
		Context: clusterContext, Role: collectorv1alpha1.Role_ROLE_HUB}
	if c.Spec.Settings != nil {
		req.Settings = slices.Clone(c.Spec.Settings.Raw)
	}
	events, failure, err := f.Pool.Invoke(ctx, collector, req)
	if err != nil {
		// The model gets the code alone; the log says why.
		logf.FromContext(ctx).Error(err, "A call of a collector's tool got no answer", "tool", tool)
		return nil, "", callFailure(tool, err)
	}
	if failure != nil {
		return nil, "", fmt.Errorf("%s failed: %s: %s", tool, text.CutChars(text.Printable(failure.Reason), maxReason),
			text.CutChars(text.Printable(failure.Message), maxMessage))
	}
	trust := ledger.Known
	var out bytes.Buffer
	for _, e := range events {
		if !slices.Contains(operations[i].GetProduces(), e.Type()) || e.Type() == sdkevidence.TypePage {
			trust = ledger.External
		}
		out.Write(e.Data())
		out.WriteByte('\n')
	}
	return out.Bytes(), trust, nil
}

// The most characters of a collector's failure that the model gets: its reason, and its message.
const (
	maxReason  = 64
	maxMessage = 256
)

// callFailure returns the error of a call that got no answer: its gRPC code, and the collector's message only where it
// names what is wrong with the parameters, which the model gave. Any other message can name an address, and one about
// the settings quotes them.
func callFailure(tool string, err error) error {
	if errors.Is(err, collectorclient.ErrContract) {
		return fmt.Errorf("%s answered in a way that breaks the collector API's contract", tool)
	}
	code, message := codes.Unknown, ""
	var s interface{ GRPCStatus() *status.Status }
	if errors.As(err, &s) {
		code, message = s.GRPCStatus().Code(), s.GRPCStatus().Message()
	}
	if code == codes.InvalidArgument && strings.HasPrefix(message, "the parameters ") {
		return fmt.Errorf("%s refused the arguments: %s", tool, text.CutChars(text.Printable(message), maxMessage))
	}
	return fmt.Errorf("%s failed: %s", tool, code)
}

// collector reads the Collector of the name. Its error is vexplain's words.
func (f *CollectorTools) collector(ctx context.Context, name string) (*configv1alpha1.Collector, error) {
	var c configv1alpha1.Collector
	if err := f.Reader.Get(ctx, client.ObjectKey{Name: name}, &c); err != nil {
		return nil, errors.New("its Collector can't be read")
	}
	return &c, nil
}

// operations returns the operations of the collector of c that the agent can call, when it can be used now: those in
// the hub's role that consume no evidence, since the agent gives only parameters. For an MCP collector, they are the
// tools that its server serves and its Collector lists. Its errors are vexplain's words.
func (f *CollectorTools) operations(ctx context.Context, c *configv1alpha1.Collector) ([]*collectorv1alpha1.Operation,
	error) {
	if c.Spec.MCP != nil {
		return f.mcpTools(ctx, c)
	}
	if !collectorclient.Usable(c) {
		return nil, errors.New("its collector can't be used now")
	}
	capabilities, err := f.Pool.Capabilities(ctx, c.Name)
	if err != nil {
		return nil, errors.New("its collector doesn't say what it can do")
	}
	var operations []*collectorv1alpha1.Operation
	for _, op := range capabilities.GetOperations() {
		// An operation that produces the SBOM is the one that scans images: the hub's executor asks for it, and
		// it is never a tool.
		if op.GetRole() == collectorv1alpha1.Role_ROLE_HUB && len(op.GetConsumes()) == 0 &&
			!slices.Contains(op.GetProduces(), sdkevidence.TypeSBOM) {
			operations = append(operations, op)
		}
	}
	return operations, nil
}

// mcpTools returns the tools of the MCP collector of c, as operations in the hub's role that produce no known type,
// when it can be used now. Its errors are vexplain's words.
func (f *CollectorTools) mcpTools(ctx context.Context, c *configv1alpha1.Collector) ([]*collectorv1alpha1.Operation,
	error) {
	if f.MCP == nil || !mcpUsable(c) {
		return nil, errors.New("its collector can't be used now")
	}
	tools, err := f.MCP.Tools(ctx, c.Name)
	if err != nil {
		return nil, errors.New("its MCP server doesn't say what tools it serves")
	}
	operations := make([]*collectorv1alpha1.Operation, 0, len(tools))
	for _, t := range tools {
		schema, err := json.Marshal(t.InputSchema)
		if err != nil {
			continue
		}
		operations = append(operations, &collectorv1alpha1.Operation{Name: t.Name, Description: t.Description,
			Role: collectorv1alpha1.Role_ROLE_HUB, ParameterSchema: schema})
	}
	return operations, nil
}

// callMCP calls the tool name of the MCP collector of c, for tool, the name that the model called. It refuses a tool
// off the Collector's list before any request. An answer that is an error reaches the model as the call's output, with
// the server's text, and any other failure in vexplain's words: its error can name the server's address.
func (f *CollectorTools) callMCP(ctx context.Context, c *configv1alpha1.Collector, tool, name string,
	args json.RawMessage) ([]byte, ledger.Trust, error) {
	switch {
	case !slices.Contains(c.Spec.MCP.Tools, name):
		return nil, "", fmt.Errorf("%s isn't on the list of tools that its Collector allows", tool)
	case f.MCP == nil || !mcpUsable(c):
		return nil, "", fmt.Errorf("%s can't be called now: its collector can't be used now", tool)
	}
	out, err := f.MCP.Call(ctx, c.Name, name, args)
	switch {
	case errors.Is(err, collectorclient.ErrMCPTool):
		return nil, "", fmt.Errorf("%s: %w", tool, err)
	case err != nil:
		logf.FromContext(ctx).Info("A call of an MCP collector's tool failed", "tool", tool, "reason", err.Error())
		return nil, "", fmt.Errorf("%s failed: its MCP server can't be reached, or broke MCP", tool)
	}
	return []byte(out), ledger.External, nil
}

// mcpUsable says whether the agent may use the MCP collector of c: its Collector isn't being deleted, and Ready isn't
// False. Unknown is usable, as for every collector, and so is a Collector that the deployer hasn't checked yet: the
// list bounds what it may call.
func mcpUsable(c *configv1alpha1.Collector) bool {
	return c.DeletionTimestamp.IsZero() && !meta.IsStatusConditionFalse(c.Status.Conditions, configv1alpha1.ConditionReady)
}

// granted reports whether the grant allows the operation: one that it names, or any when it names none.
func granted(g configv1alpha1.AgentToolGrant, operation string) bool {
	return len(g.Operations) == 0 || slices.Contains(g.Operations, operation)
}

const (
	// describeTool is the tool whose answers of known trust name the URLs that a fetch may take: their references.
	describeTool = "vulnerabilities__describe"
	// untrustedURL is the reason of a fetch that vexplain refused for its URL, in the metric of refusals.
	untrustedURL = "UntrustedURL"
)

// allowedDomains returns the hosts that the collector's fetch reaches: its settings' allowedDomains, or the default of
// hosts. A collector's settings that can't be read leave them unknown.
func allowedDomains(c *configv1alpha1.Collector) []string {
	var settings struct {
		AllowedDomains []string `json:"allowedDomains"`
	}
	if c.Spec.Settings != nil && len(c.Spec.Settings.Raw) > 0 && json.Unmarshal(c.Spec.Settings.Raw, &settings) != nil {
		return nil
	}
	if len(settings.AllowedDomains) == 0 {
		settings.AllowedDomains = hosts.Default
	}
	domains, _ := hosts.Domains(settings.AllowedDomains)
	return domains
}

// unreadable is why fetch refuses a reference that isn't a URL, in the note of describe.
const unreadable = "the URL can't be read"

// describeNote is the note after an answer of describe: the usual line, and the references that the granted fetch
// refuses, by the check that the fetch runs, so that the agent spends no step on them. It names them by host where the
// host isn't on the allowlist, and otherwise by why, in fixed words that repeat no URL. The answer itself stays as the
// collector wrote it.
func (s *Session) describeNote(e ledger.Entry) string {
	note := s.note(e)
	if s.fetch == nil {
		return note
	}
	var unreachable, why []string
	refused := 0
	decoder := json.NewDecoder(bytes.NewReader(e.Output))
	for {
		var answer struct {
			References []string `json:"references"`
		}
		if decoder.Decode(&answer) != nil {
			break
		}
		for _, r := range answer.References {
			u, err := url.Parse(r)
			if err == nil {
				err = hosts.Check(s.fetch.AllowedDomains, u)
			}
			switch {
			case err == nil:
				continue
			case errors.Is(err, hosts.RefusedHost):
				if host := strings.ToLower(u.Hostname()); !slices.Contains(unreachable, host) {
					unreachable = append(unreachable, host)
				}
				continue
			case !errors.As(err, new(hosts.Refusal)):
				err = errors.New(unreadable)
			}
			refused++
			if !slices.Contains(why, err.Error()) {
				why = append(why, err.Error())
			}
		}
	}
	if len(unreachable) > 0 {
		slices.Sort(unreachable)
		note += fmt.Sprintf("\n%s can't reach the references on these hosts, which aren't on its allowlist: %s. "+
			"Don't fetch them.", s.fetch.Name, strings.Join(unreachable, ", "))
	}
	if refused > 0 {
		slices.Sort(why)
		note += fmt.Sprintf("\n%s refuses %d of its references for their form: %s. Don't fetch them.", s.fetch.Name,
			refused, strings.Join(why, "; "))
	}
	return note
}

// trusted returns the reference of describe, in an answer of known trust of the case, that the arguments of a fetch
// name, and false when none does. A URL that the model wrote, or found in a page or another tool's output, could carry
// the case's data to a page that anyone can write on an allowed host. The caller holds mu.
func (s *Session) trusted(args json.RawMessage) (string, bool) {
	var in struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(args, &in) != nil || in.URL == "" {
		return "", false
	}
	want := normalURL(in.URL)
	for _, e := range s.ledger.Entries() {
		if e.Tool != describeTool || e.Trust != ledger.Known {
			continue
		}
		// The output holds the data of each event of the answer, one after the other.
		decoder := json.NewDecoder(bytes.NewReader(e.Output))
		for {
			var answer struct {
				References []string `json:"references"`
			}
			if decoder.Decode(&answer) != nil {
				break
			}
			for _, r := range answer.References {
				if normalURL(r) == want {
					return r, true
				}
			}
		}
	}
	return "", false
}

// normalURL returns the URL as fetches compare it: the ASCII letters of its scheme and host in lower case, as they
// compare on the web, without its fragment, which is never sent, and its path and query as written. Other letters stay
// as they are: strings.ToLower lowers some of them to ASCII ones, such as the Kelvin sign to k, but IDNA maps a name
// with one to another host.
func normalURL(raw string) string {
	raw, _, _ = strings.Cut(raw, "#")
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return raw
	}
	host, path := rest, ""
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	return asciiLower(scheme) + "://" + asciiLower(host) + path
}

// asciiLower returns s with its ASCII capitals in lower case, and every other character as it is.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// maxAliases is the most aliases that describe takes.
const maxAliases = 8

// caseIDs returns the IDs that name the case's vulnerability: its own, and the IDs and aliases of its findings, sorted.
func caseIDs(c cases.Case) []string {
	ids := []string{c.VulnerabilityID}
	for _, f := range c.Findings {
		ids = append(ids, f.VulnerabilityID)
		ids = append(ids, f.Aliases...)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// withAliases adds the case's other IDs to the aliases of a call of describe, when it asks for an ID of the case: the
// ecosystem's own record of the vulnerability then answers whether or not the model names it. The model's aliases come
// first, and the list stops at maxAliases. Any other call goes as it is.
func (s *Session) withAliases(args json.RawMessage) json.RawMessage {
	var in map[string]json.RawMessage
	var id string
	var aliases []string
	if json.Unmarshal(args, &in) != nil || json.Unmarshal(in["vulnerabilityID"], &id) != nil {
		return args
	}
	if len(in["aliases"]) > 0 && json.Unmarshal(in["aliases"], &aliases) != nil {
		return args
	}
	if !slices.ContainsFunc(s.ids, func(c string) bool { return strings.EqualFold(c, id) }) {
		return args
	}
	given := len(aliases)
	for _, c := range s.ids {
		if len(aliases) >= maxAliases {
			break
		}
		if !strings.EqualFold(c, id) && !slices.ContainsFunc(aliases, func(a string) bool { return strings.EqualFold(a, c) }) {
			aliases = append(aliases, c)
		}
	}
	if len(aliases) == given {
		return args
	}
	// A string list always marshals.
	in["aliases"], _ = json.Marshal(aliases)
	out, err := json.Marshal(in)
	if err != nil {
		return args
	}
	return out
}
