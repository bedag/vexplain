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
	"fmt"
	"strings"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/metrics"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/hosts"
)

// These tests fetch through the stand-in of the collectors, never from the internet: vexplain's MCP server forwards a
// fetch only for a URL that a trusted result of the case named (design 5.8, decision 0054).

const (
	// The collector advisories, and its operation fetch, as a tool. The collector mirror offers fetch too.
	advisories, fetchOp, fetchTool = "advisories", "fetch", "advisories__fetch"
	mirror, mirrorFetch            = "mirror", "mirror__fetch"
	// lookup is the fixture's other operation of vulnerabilities that answers in describe's shape, of known trust.
	lookup = "vulnerabilities__lookup"
	// reference is the URL that describe names for the case's vulnerability, and pageLink a URL that the fetched page
	// shows as text.
	reference = "https://security-tracker.debian.org/tracker/CVE-2026-0001"
	pageLink  = "https://github.com/team-a/notes/issues/1"
	// untrusted is the reason of a refused fetch in the metric.
	untrusted = "UntrustedURL"
	// decoderFlaw is the description that describe gives of the vulnerability.
	decoderFlaw = "A flaw in the decoder."
)

// fetching returns the forwarder of the grants, by default of describe and fetch, and the stand-in of the
// collectors: fetch answers with a page that shows pageLink as text, and any other operation with a description that
// names the reference.
func fetching(t *testing.T, grants ...configv1alpha1.AgentToolGrant) (*core.CollectorTools, *pool) {
	t.Helper()
	if grants == nil {
		grants = []configv1alpha1.AgentToolGrant{{Collector: vulnerabilities, Operations: []string{describeOp}},
			{Collector: advisories, Operations: []string{fetchOp}}}
	}
	tools, p := collectorTools(t, grants...)
	p.answer = func(context.Context) ([]cloudevents.Event, *collectorclient.Failure, error) {
		var params struct{ URL string }
		req := p.requests[len(p.requests)-1]
		if req.GetOperation() != fetchOp {
			e, err := sdkevidence.New(sdkevidence.TypeDescription, "vulnerability/"+vulnerability,
				sdkevidence.Description{VulnerabilityID: vulnerability, Description: decoderFlaw,
					References: []string{"https://www.cve.org/CVERecord?id=" + vulnerability, reference}},
				sdkevidence.WithSource("/hub/collectors/vulnerabilities"))
			return []cloudevents.Event{e}, nil, err
		}
		require.NoError(t, json.Unmarshal(req.GetParameters(), &params))
		e, err := sdkevidence.New(sdkevidence.TypePage, "page/"+params.URL,
			sdkevidence.Page{URL: params.URL, FinalURL: params.URL, ContentType: "text/html",
				Text: "Fixed in 1.0.9-3. Read on at " + pageLink},
			sdkevidence.WithSource("/hub/collectors/advisories"))
		return []cloudevents.Event{e}, nil, err
	}
	return tools, p
}

// open starts a session with the forwarder, and loads its tools.
func open(t *testing.T, forwarder core.Forwarder) *fixture {
	t.Helper()
	f := start(t, options{forwarder: forwarder})
	text, failed := f.call(t, "search_tools", find("describe fetch search lookup"))
	require.False(t, failed, text)
	return f
}

// fetchOf returns the arguments of fetch.
func fetchOf(url string) map[string]any { return map[string]any{"url": url} }

// fetches returns how many calls of fetch reached the collectors.
func fetches(p *pool) int {
	n := 0
	for _, req := range p.requests {
		if req.GetOperation() == fetchOp {
			n++
		}
	}
	return n
}

// forwarded returns the arguments of the last call that reached the collectors.
func forwarded(p *pool) string { return string(p.requests[len(p.requests)-1].GetParameters()) }

// refusals returns how many calls of the tool the metric counts as refused for their URL.
func refusals(tool string) float64 {
	return testutil.ToFloat64(metrics.AgentToolRefusalsTotal.WithLabelValues(cluster, tool, untrusted))
}

// requireRefused calls the fetch tool with the URL, and requires a refusal: a tool error that doesn't repeat the URL,
// recorded in the ledger, and counted.
func requireRefused(t *testing.T, f *fixture, tool, url string) {
	t.Helper()
	before := refusals(tool)
	id := fmt.Sprintf("ev-%d", f.session.Outcome().Ledger.Len()+1)
	text, failed := f.call(t, tool, fetchOf(url))
	require.True(t, failed, "%s: %s", url, text)
	if url != "" {
		require.NotContains(t, text, url, "the refusal doesn't repeat the URL")
	}
	require.Contains(t, text, "trusted result")
	entry, ok := f.session.Outcome().Ledger.Entry(id)
	require.True(t, ok, "the refusal is in the ledger")
	require.Equal(t, tool, entry.Tool)
	require.Equal(t, ledger.External, entry.Trust)
	require.JSONEq(t, fmt.Sprintf(`{"url": %q}`, url), entry.Arguments)
	require.Equal(t, before+1, refusals(tool), "%s is counted", url)
}

func TestAFetchTakesAURLFromDescribe(t *testing.T) {
	tools, p := fetching(t)
	f := open(t, tools)
	text, failed := f.call(t, describe, describing(vulnerability))
	require.False(t, failed, text)

	before := refusals(fetchTool)
	// The ASCII letters of the scheme and the host compare in any case, and the fragment is never compared. What is
	// fetched is the reference as describe named it, never the model's spelling.
	cve := "https://www.cve.org/CVERecord?id=" + vulnerability
	for url, named := range map[string]string{reference: reference,
		"HTTPS://Security-Tracker.Debian.ORG/tracker/CVE-2026-0001": reference, reference + "#bookworm": reference,
		cve: cve} {
		text, failed = f.call(t, fetchTool, fetchOf(url))
		require.False(t, failed, "%s: %s", url, text)
		require.Contains(t, text, "Fixed in 1.0.9-3.")
		require.JSONEq(t, fmt.Sprintf(`{"url": %q}`, named), forwarded(p), url)
	}
	require.Equal(t, 4, fetches(p))
	require.Equal(t, before, refusals(fetchTool))

	entry, ok := f.session.Outcome().Ledger.Entry("ev-3")
	require.True(t, ok)
	require.Equal(t, fetchTool, entry.Tool)
	require.Equal(t, ledger.External, entry.Trust, "a page is anyone's text, though fetch declares its type")
}

func TestAFetchRefusesAURLTheModelWrote(t *testing.T) {
	tools, p := fetching(t)
	f := open(t, tools)

	// Before describe, no URL is trusted.
	requireRefused(t, f, fetchTool, reference)

	text, failed := f.call(t, describe, describing(vulnerability))
	require.False(t, failed, text)
	for _, url := range []string{
		// github.com is on the default allowlist, and anyone can write a page there, or ask for one with data in it.
		"https://github.com/team-a/notes/issues/new?body=CVE-2026-0001+libbrotli1+1.0.9-2",
		// The path and the query compare exactly.
		reference + "?q=libbrotli1",
		"https://security-tracker.debian.org/tracker/CVE-2026-0002",
		"https://security-tracker.debian.org/tracker/cve-2026-0001",
		"http://security-tracker.debian.org/tracker/CVE-2026-0001",
		"",
		// Only ASCII letters compare in any case: a capital I with a dot, or the Kelvin sign, lowers to an ASCII letter
		// in Unicode, but IDNA maps the name to another host.
		"https://secur\u0130ty-tracker.debian.org/tracker/CVE-2026-0001",
		"https://security-trac\u212Aer.debian.org/tracker/CVE-2026-0001",
	} {
		requireRefused(t, f, fetchTool, url)
	}
	require.Zero(t, fetches(p), "refused before any request")
}

// Only an answer of describe of known trust names URLs that a fetch may take.
func TestAFetchTrustsOnlyAKnownAnswerOfDescribe(t *testing.T) {
	t.Run("describe's answer of external trust", func(t *testing.T) {
		tools, p := fetching(t)
		answer := p.answer
		p.answer = func(ctx context.Context) ([]cloudevents.Event, *collectorclient.Failure, error) {
			events, failure, err := answer(ctx)
			if p.requests[len(p.requests)-1].GetOperation() == describeOp {
				events[0].SetType("ch.bedag.vexplain.vulnerabilities.other.v1alpha1")
			}
			return events, failure, err
		}
		f := open(t, tools)
		text, failed := f.call(t, describe, describing(vulnerability))
		require.False(t, failed, text)
		require.Contains(t, text, reference)
		entry, _ := f.session.Outcome().Ledger.Entry("ev-2")
		require.Equal(t, ledger.External, entry.Trust, "a type that describe doesn't declare")

		requireRefused(t, f, fetchTool, reference)
		require.Zero(t, fetches(p))
	})
	t.Run("another tool's answer of known trust", func(t *testing.T) {
		tools, p := fetching(t, configv1alpha1.AgentToolGrant{Collector: vulnerabilities,
			Operations: []string{"lookup"}}, configv1alpha1.AgentToolGrant{Collector: advisories})
		f := open(t, tools)
		text, failed := f.call(t, lookup, describing(vulnerability))
		require.False(t, failed, text)
		require.Contains(t, text, reference)
		entry, _ := f.session.Outcome().Ledger.Entry("ev-2")
		require.Equal(t, ledger.Known, entry.Trust)

		requireRefused(t, f, fetchTool, reference)
		require.Zero(t, fetches(p))
	})
}

// An operation that produces pages is checked as a fetch, whatever its collector's name.
func TestAFetchUnderAnotherNameIsChecked(t *testing.T) {
	tools, p := fetching(t, configv1alpha1.AgentToolGrant{Collector: vulnerabilities,
		Operations: []string{describeOp}}, configv1alpha1.AgentToolGrant{Collector: mirror})
	f := open(t, tools)
	_, failed := f.call(t, describe, describing(vulnerability))
	require.False(t, failed)

	requireRefused(t, f, mirrorFetch, pageLink)
	require.Zero(t, fetches(p), "refused before any request")

	text, failed := f.call(t, mirrorFetch, fetchOf(reference+"#bookworm"))
	require.False(t, failed, text)
	require.JSONEq(t, fmt.Sprintf(`{"url": %q}`, reference), forwarded(p))
	entry, _ := f.session.Outcome().Ledger.Entry(fmt.Sprintf("ev-%d", f.session.Outcome().Ledger.Len()))
	require.Equal(t, ledger.External, entry.Trust, "a page is of external trust")
}

func TestAFetchRefusesAURLFromAFetchedPage(t *testing.T) {
	tools, p := fetching(t)
	f := open(t, tools)
	_, failed := f.call(t, describe, describing(vulnerability))
	require.False(t, failed)
	text, failed := f.call(t, fetchTool, fetchOf(reference))
	require.False(t, failed, text)
	require.Contains(t, text, pageLink)

	requireRefused(t, f, fetchTool, pageLink)
	require.Equal(t, 1, fetches(p), "refused before any request")
}

// mcpCollector is a stand-in for an MCP collector's tool, wiki__search, beside the collectors: its output is External,
// as an MCP collector's always is, and it answers in describe's shape, with pageLink as a reference.
type mcpCollector struct{ core.Forwarder }

func (m mcpCollector) Tools(ctx context.Context) ([]core.Tool, error) {
	tools, err := m.Forwarder.Tools(ctx)
	return append(tools, tool("wiki__search", "Searches the wiki")), err
}

func (m mcpCollector) Call(ctx context.Context, name string, args json.RawMessage) ([]byte, ledger.Trust, error) {
	if name != "wiki__search" {
		return m.Forwarder.Call(ctx, name, args)
	}
	out, err := json.Marshal(sdkevidence.Description{VulnerabilityID: vulnerability, References: []string{pageLink}})
	return out, ledger.External, err
}

func TestAFetchRefusesAURLFromAnMCPCollector(t *testing.T) {
	tools, p := fetching(t)
	f := open(t, mcpCollector{tools})
	_, failed := f.call(t, describe, describing(vulnerability))
	require.False(t, failed)
	text, failed := f.call(t, "wiki__search", describing(vulnerability))
	require.False(t, failed, text)
	require.Contains(t, text, pageLink)

	requireRefused(t, f, fetchTool, pageLink)
	require.Zero(t, fetches(p), "refused before any request")
}

// Each case has a session of its own, which trusts only the results of its own calls, whatever forwarder it shares.
func TestAFetchRefusesAURLFromAnotherCase(t *testing.T) {
	tools, p := fetching(t)
	other, this := open(t, tools), open(t, tools)
	_, failed := other.call(t, describe, describing(vulnerability))
	require.False(t, failed)

	requireRefused(t, this, fetchTool, reference)
	require.Zero(t, fetches(p), "refused before any request")

	text, failed := other.call(t, fetchTool, fetchOf(reference))
	require.False(t, failed, text)
	require.Equal(t, 1, fetches(p))
}

// describe's answer says which of its references the granted fetch can't reach, by the fetching collector's allowlist,
// so that the agent spends no step on them. The answer itself stays as the collector wrote it.
func TestDescribeSaysWhichOfItsReferencesFetchCantReach(t *testing.T) {
	tools, _ := fetching(t)
	f := open(t, tools)
	text, failed := f.call(t, describe, describing(vulnerability))
	require.False(t, failed, text)
	_, line, found := strings.Cut(text, "[ledger ID ev-2]")
	require.True(t, found, text)
	require.Contains(t, line, "can't reach")
	require.Contains(t, line, "www.cve.org", "a host off the default allowlist")
	require.NotContains(t, line, "security-tracker.debian.org", "a host on it")
	entry, ok := f.session.Outcome().Ledger.Entry("ev-2")
	require.True(t, ok)
	require.NotContains(t, string(entry.Output), "can't reach", "the ledger holds the answer as the collector wrote it")
}

// The note also names the references that fetch refuses for their form, by why, in fixed words that repeat no URL,
// which the answer gave.
func TestDescribeSaysWhichOfItsReferencesFetchRefusesForTheirForm(t *testing.T) {
	tools, p := fetching(t)
	refs := []string{"http://security-tracker.debian.org/a", "https://security-tracker.debian.org:8443/b",
		"https://someone@security-tracker.debian.org/c", "https://192.0.2.1/d",
		"https://security-tracker.debian.org/" + strings.Repeat("e", 2100), reference}
	p.answer = func(context.Context) ([]cloudevents.Event, *collectorclient.Failure, error) {
		e, err := sdkevidence.New(sdkevidence.TypeDescription, "vulnerability/"+vulnerability,
			sdkevidence.Description{VulnerabilityID: vulnerability, Description: decoderFlaw, References: refs},
			sdkevidence.WithSource("/hub/collectors/vulnerabilities"))
		return []cloudevents.Event{e}, nil, err
	}
	f := open(t, tools)
	text, failed := f.call(t, describe, describing(vulnerability))
	require.False(t, failed, text)
	_, line, found := strings.Cut(text, "[ledger ID ev-2]")
	require.True(t, found, text)
	for _, why := range []error{hosts.RefusedScheme, hosts.RefusedPort, hosts.RefusedUser, hosts.RefusedIP,
		hosts.RefusedLength} {
		require.Contains(t, line, why.Error())
	}
	require.Contains(t, line, "5 of its references")
	for _, part := range []string{"192.0.2.1", "someone", "8443/b", "http://"} {
		require.NotContains(t, line, part)
	}
	require.NotContains(t, line, "can't reach the references on these hosts", "every host is on the allowlist")
}

func TestDescribeNamesNoHostWhereFetchReachesEveryReferenceOrIsNotGranted(t *testing.T) {
	t.Run("the settings allow every host", func(t *testing.T) {
		tools, _ := fetching(t)
		var c configv1alpha1.Collector
		api := tools.Reader.(client.Client)
		require.NoError(t, api.Get(t.Context(), client.ObjectKey{Name: advisories}, &c))
		c.Spec.Settings = &runtime.RawExtension{Raw: []byte(
			`{"allowedDomains": ["www.cve.org", ".debian.org"]}`)}
		require.NoError(t, api.Update(t.Context(), &c))
		f := open(t, tools)
		text, failed := f.call(t, describe, describing(vulnerability))
		require.False(t, failed, text)
		require.NotContains(t, text, "can't reach")
	})
	t.Run("no fetch is granted", func(t *testing.T) {
		tools, _ := fetching(t, configv1alpha1.AgentToolGrant{Collector: vulnerabilities, Operations: []string{describeOp}})
		f := open(t, tools)
		text, failed := f.call(t, describe, describing(vulnerability))
		require.False(t, failed, text)
		require.NotContains(t, text, "can't reach")
	})
}
