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
	"slices"
	"strings"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/collectorclient"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

const (
	// settings are the settings of the collector vulnerabilities, which never reach the model.
	settings = `{"databaseURL":"https://artifacts.example/vulnerability-db"}`
	// describeSchema is the parameter schema of describe.
	describeSchema = `{"type":"object","properties":{"vulnerabilityID":{"type":"string"}},"required":["vulnerabilityID"]}`
	theSubject     = "manifest/" + manifest
	// The collectors, and the operation describe.
	vulnerabilities, scanner, describeOp = "vulnerabilities", "scanner", "describe"
	// describeArgs are describe's arguments as JSON.
	describeArgs = `{"vulnerabilityID":"CVE-2026-0001"}`
)

// pool is a stand-in for the collectors: their declared operations, and an answer to every Invoke.
type pool struct {
	operations map[string][]*collectorv1alpha1.Operation
	answer     func(ctx context.Context) ([]cloudevents.Event, *collectorclient.Failure, error)
	requests   []*collectorv1alpha1.InvokeRequest
}

func (p *pool) Capabilities(_ context.Context, collector string) (*collectorv1alpha1.GetCapabilitiesResponse, error) {
	return &collectorv1alpha1.GetCapabilitiesResponse{Operations: p.operations[collector]}, nil
}

func (p *pool) Invoke(ctx context.Context, _ string, req *collectorv1alpha1.InvokeRequest,
	_ ...collectorclient.InvokeOption) ([]cloudevents.Event, *collectorclient.Failure, error) {
	p.requests = append(p.requests, req)
	return p.answer(ctx)
}

// fetchOperation is advisories' fetch, which produces pages. The collector mirror offers it too, under its own name.
var fetchOperation = &collectorv1alpha1.Operation{Name: fetchOp,
	Description: "Fetches a page that a trusted result linked to.", Role: collectorv1alpha1.Role_ROLE_HUB,
	Produces:        []string{sdkevidence.TypePage},
	ParameterSchema: []byte(`{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}`)}

// description is describe's answer about the case's vulnerability.
func description(t *testing.T) cloudevents.Event {
	t.Helper()
	e, err := sdkevidence.New(sdkevidence.TypeDescription, "vulnerability/"+vulnerability,
		sdkevidence.Description{VulnerabilityID: vulnerability, Description: decoderFlaw},
		sdkevidence.WithSource("/hub/collectors/vulnerabilities"))
	require.NoError(t, err)
	return e
}

// collectorTools returns the forwarder over the collectors vulnerabilities and scanner, under the grants, and the
// stand-in of the collectors, which answers with describe's answer.
func collectorTools(t *testing.T, grants ...configv1alpha1.AgentToolGrant) (*core.CollectorTools, *pool) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	collector := func(name string, roles ...configv1alpha1.CollectorRole) *configv1alpha1.Collector {
		c := &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: name}}
		c.Status.Capabilities = &configv1alpha1.CollectorCapabilities{Roles: roles}
		return c
	}
	theCollector := collector(vulnerabilities, configv1alpha1.CollectorRoleHub)
	theCollector.Spec.Settings = &runtime.RawExtension{Raw: []byte(settings)}
	broken := collector("broken", configv1alpha1.CollectorRoleHub)
	meta.SetStatusCondition(&broken.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
		Status: metav1.ConditionFalse, Reason: "CollectorFailing", Message: "down"})
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(theCollector,
		collector(scanner, configv1alpha1.CollectorRoleHub), broken,
		collector(advisories, configv1alpha1.CollectorRoleHub), collector(mirror, configv1alpha1.CollectorRoleHub)).Build()

	p := &pool{operations: map[string][]*collectorv1alpha1.Operation{
		vulnerabilities: {
			{Name: describeOp, Description: "Describes a vulnerability from the vulnerability database.",
				Role: collectorv1alpha1.Role_ROLE_HUB, Produces: []string{sdkevidence.TypeDescription},
				ParameterSchema: []byte(describeSchema)},
			{Name: "match", Description: "Matches an SBOM against the vulnerability database.",
				Role: collectorv1alpha1.Role_ROLE_HUB, Produces: []string{sdkevidence.TypeFindings},
				Consumes: []string{sdkevidence.TypeSBOM}, ParameterSchema: []byte(`{"type":"object"}`)},
			{Name: "lookup", Description: "Looks a vulnerability up in the vulnerability database.",
				Role: collectorv1alpha1.Role_ROLE_HUB, Produces: []string{sdkevidence.TypeDescription},
				ParameterSchema: []byte(describeSchema)},
		},
		scanner: {{Name: "scan", Description: "Scans an image of the vulnerability database's subject.",
			Role: collectorv1alpha1.Role_ROLE_HUB, Produces: []string{sdkevidence.TypeSBOM}, ParameterSchema: []byte(`{"type":"object"}`)}},
		"broken": {{Name: describeOp, Description: "Describes a vulnerability from the vulnerability database.",
			Role: collectorv1alpha1.Role_ROLE_HUB, ParameterSchema: []byte(describeSchema)}},
		advisories: {fetchOperation},
		mirror:     {fetchOperation},
	}}
	p.answer = func(context.Context) ([]cloudevents.Event, *collectorclient.Failure, error) {
		return []cloudevents.Event{description(t)}, nil, nil
	}
	if grants == nil {
		grants = []configv1alpha1.AgentToolGrant{{Collector: vulnerabilities, Operations: []string{describeOp}},
			{Collector: scanner}, {Collector: "broken"}}
	}
	return &core.CollectorTools{Reader: reader, Pool: p, Grants: grants, Subject: theSubject,
		Context: func(context.Context) (*collectorv1alpha1.Context, error) {
			return &collectorv1alpha1.Context{Cluster: "cluster-a"}, nil
		}}, p
}

// names returns the names of the tools.
func names(tools []core.Tool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name)
	}
	slices.Sort(out)
	return out
}

func TestSearchToolsFindsAGrantedHubOperation(t *testing.T) {
	tools, _ := collectorTools(t)
	f := start(t, options{forwarder: tools})

	text, failed := f.call(t, "search_tools", find("vulnerability database scan describe"))
	require.False(t, failed, text)
	require.Contains(t, text, describe)
	require.Contains(t, text, describeSchema, "with its parameter schema")
	require.NotContains(t, text, "scanner__scan", "the scan of images is the executor's, never a tool")
	require.NotContains(t, text, "vulnerabilities__lookup", "outside the grant")
	require.NotContains(t, text, "broken__describe", "a collector that can't be used now")
	require.Equal(t, append(slices.Clone(coreTools), describe), sorted(f.tools(t)))

	all, _ := collectorTools(t, configv1alpha1.AgentToolGrant{Collector: vulnerabilities},
		configv1alpha1.AgentToolGrant{Collector: scanner})
	found, err := all.Tools(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{describe, "vulnerabilities__lookup"}, names(found),
		"without operations, every hub operation that takes its input from the agent alone")
}

func TestAnOperationOutsideTheGrantIsRefused(t *testing.T) {
	tools, p := collectorTools(t)
	for _, tool := range []string{"vulnerabilities__lookup", "vulnerabilities__match", "scanner__scan",
		"advisories__fetch", "broken__describe", "vulnerabilities", "__describe"} {
		_, _, err := tools.Call(t.Context(), tool, json.RawMessage(describeArgs))
		require.Error(t, err, tool)
	}
	require.Empty(t, p.requests, "refused before any call")

	_, _, err := tools.Call(t.Context(), describe, json.RawMessage(describeArgs))
	require.NoError(t, err)
	require.Len(t, p.requests, 1)
}

func TestAToolCallIsForwardedAndItsTrustRecorded(t *testing.T) {
	tools, p := collectorTools(t)
	f := start(t, options{forwarder: tools})
	_, failed := f.call(t, "search_tools", find("describe"))
	require.False(t, failed)

	text, failed := f.call(t, describe, describing(vulnerability))
	require.False(t, failed, text)
	require.Contains(t, text, decoderFlaw)
	require.NotContains(t, text, "artifacts.example", "the settings never reach the model")

	require.Len(t, p.requests, 1)
	req := p.requests[0]
	require.Equal(t, describeOp, req.GetOperation())
	require.Equal(t, collectorv1alpha1.Role_ROLE_HUB, req.GetRole())
	require.JSONEq(t, describeArgs, string(req.GetParameters()))
	require.JSONEq(t, settings, string(req.GetSettings()))
	require.Equal(t, theSubject, req.GetSubject())
	require.Equal(t, "cluster-a", req.GetContext().GetCluster())

	entry, ok := f.session.Outcome().Ledger.Entry("ev-2")
	require.True(t, ok)
	require.Equal(t, describe, entry.Tool)
	require.Equal(t, ledger.Known, entry.Trust, "describe produces the type that it declares")
	var d sdkevidence.Description
	require.NoError(t, json.Unmarshal(entry.Output, &d), "the output is the data of the answer")
	require.Equal(t, vulnerability, d.VulnerabilityID)

	search, _ := f.session.Outcome().Ledger.Entry("ev-1")
	require.Equal(t, ledger.External, search.Trust, "a tool listing is never evidence")

	p.answer = func(context.Context) ([]cloudevents.Event, *collectorclient.Failure, error) {
		e := description(t)
		e.SetType("ch.bedag.vexplain.vulnerabilities.other.v1alpha1")
		return []cloudevents.Event{e}, nil, nil
	}
	// Another alias makes it another call: the same call would be answered from the ledger.
	_, failed = f.call(t, describe, describing(vulnerability, "A-1"))
	require.False(t, failed)
	entry, _ = f.session.Outcome().Ledger.Entry("ev-3")
	require.Equal(t, ledger.External, entry.Trust, "a type that the operation doesn't declare")

	p.answer = func(context.Context) ([]cloudevents.Event, *collectorclient.Failure, error) {
		return nil, &collectorclient.Failure{Reason: "NotFound",
			Message: "the vulnerability database holds no vulnerability of the ID"}, nil
	}
	text, failed = f.call(t, describe, describing("CVE-2026-9999"))
	require.True(t, failed, "a failure is a tool error")
	require.Contains(t, text, "NotFound")
	require.Contains(t, text, "holds no vulnerability")
	entry, _ = f.session.Outcome().Ledger.Entry("ev-4")
	require.Equal(t, ledger.External, entry.Trust)
}

// What the model learns of a failed call is the collector's reason and a short message, or the call's status, and
// never an address, a setting or more of the collector's text.
func TestAToolsErrorsCarryNoSecretOrEnvironmentValue(t *testing.T) {
	tools, p := collectorTools(t)
	for _, c := range []struct {
		name               string
		err                error
		failure            *collectorclient.Failure
		contains, notWords []string
	}{{
		name:     "an unreachable collector",
		err:      fmt.Errorf("Invoke of collector vulnerabilities: %w", status.Error(codes.Unavailable, "dial tcp 10.0.0.7:9443: refused")),
		contains: []string{"Unavailable"}, notWords: []string{"10.0.0.7", "9443"},
	}, {
		name:     "settings that the collector refuses",
		err:      fmt.Errorf("Invoke of collector vulnerabilities: %w", status.Error(codes.InvalidArgument, "the settings are not valid: at '/token': got hunter2")),
		contains: []string{"InvalidArgument"}, notWords: []string{"hunter2", "token"},
	}, {
		name: "parameters that the collector refuses",
		err: fmt.Errorf("Invoke of collector vulnerabilities: %w",
			status.Error(codes.InvalidArgument, "the parameters are not valid: at '/vulnerabilityID': pattern mismatch")),
		contains: []string{"/vulnerabilityID", "pattern mismatch"},
	}, {
		name:    "a failure",
		failure: &collectorclient.Failure{Reason: "Internal\nX", Message: strings.Repeat("m", 1000)},
		// The reason is made printable, and the message cut.
		contains: []string{"Internal�X", strings.Repeat("m", 256)}, notWords: []string{strings.Repeat("m", 257)},
	}} {
		p.answer = func(context.Context) ([]cloudevents.Event, *collectorclient.Failure, error) {
			return nil, c.failure, c.err
		}
		_, _, err := tools.Call(t.Context(), describe, json.RawMessage(describeArgs))
		require.Error(t, err, c.name)
		for _, s := range c.contains {
			require.Contains(t, err.Error(), s, c.name)
		}
		for _, s := range append(c.notWords, "artifacts.example", "collector vulnerabilities:") {
			require.NotContains(t, err.Error(), s, c.name)
		}
	}
}

func TestAToolThatTimesOutEndsAsAToolError(t *testing.T) {
	tools, p := collectorTools(t)
	p.answer = func(ctx context.Context) ([]cloudevents.Event, *collectorclient.Failure, error) {
		<-ctx.Done()
		return nil, nil, fmt.Errorf("Invoke of collector vulnerabilities: %w", status.Error(codes.DeadlineExceeded, ctx.Err().Error()))
	}
	limits := defaultLimits
	limits.ToolTimeoutSeconds = 1
	f := start(t, options{forwarder: tools, limits: limits})
	_, failed := f.call(t, "search_tools", find("describe"))
	require.False(t, failed)

	began := time.Now()
	text, failed := f.call(t, describe, describing(vulnerability))
	require.True(t, failed, text)
	require.GreaterOrEqual(t, time.Since(began), time.Second)
	require.Less(t, time.Since(began), 10*time.Second)
	require.Contains(t, text, "toolTimeoutSeconds")
	entry, ok := f.session.Outcome().Ledger.Entry("ev-2")
	require.True(t, ok, "a call that timed out is in the ledger")
	require.Equal(t, ledger.External, entry.Trust)
}
