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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/agent/prompt"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/llm"
	"github.com/bedag/vexplain/internal/setup"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

const (
	manifest      = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	vulnerability = "CVE-2026-0001"
	playbook      = "playbook-a"
	describe      = "vulnerabilities__describe"
	apiKey        = "key-123"
	// guidance is the guidance of the investigation that the case was judged for.
	guidance = "Only images built with the HTTP/2 module are affected."
	// investigationUID is the uid of that investigation: the fake API server sets none.
	investigationUID = "uid-investigation-a"
)

// cluster-a holds a judged case: an Assessment, its sheet, its evidence and its ledger, of which ev-1 is a search of
// the tools and ev-2 a call of describe, and the investigation with guidance that it was charged to.
func theCluster(t *testing.T) (client.Client, string) {
	t.Helper()
	ctx := t.Context()
	scheme := runtime.NewScheme()
	require.NoError(t, setup.AddToScheme(scheme))
	api := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&inventoryv1alpha1.ImageVerdicts{}).Build()
	local := func() string { return "cluster-a" }
	store := evidence.NewCRDStore(api, nil, local)

	sbom, err := sdkevidence.New(sdkevidence.TypeSBOM, subjects.Manifest(manifest), sdkevidence.SBOM{
		Packages: []sdkevidence.SBOMPackage{{ID: "pkg-1", Name: "libbrotli1", Version: "1.0.9-2", Type: "deb",
			PURL: "pkg:deb/debian/libbrotli1@1.0.9-2"}},
		Distro:   &sdkevidence.Distro{ID: "debian", Version: "12"},
		Producer: sdkevidence.Producer{Name: "syft", Version: "1.0.0"},
	}, sdkevidence.WithPlatform("linux/amd64"), sdkevidence.WithSource("/clusters/cluster-a/collectors/scanner"))
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, "scanner", "v1", sbom))
	finding := inventoryv1alpha1.Finding{VulnerabilityID: vulnerability,
		Package: inventoryv1alpha1.PackageReference{ID: "pkg-1", Name: "libbrotli1", Version: ptr.To("1.0.9-2"), Type: "deb"},
		Status:  inventoryv1alpha1.VEXStatusUnderInvestigation, Severity: inventoryv1alpha1.SeverityHigh,
		FixState: inventoryv1alpha1.FixStateNotFixed, KnownExploited: inventoryv1alpha1.KnownExploitedNotListed}
	require.NoError(t, inventory.NewCRDVerdictsStore(api, local).Put(ctx, manifest, playbook,
		inventoryv1alpha1.ImageVerdictsStatus{Playbook: ptr.To(playbook), FindingsVersion: ptr.To("v1"),
			Findings: []inventoryv1alpha1.Finding{finding},
			Evidence: []inventoryv1alpha1.SheetEvidence{{Name: "sbom", Source: "scanner", Type: sdkevidence.TypeSBOM,
				Version: ptr.To("v1")}}}))
	require.NoError(t, api.Create(ctx, &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: playbook},
		Spec: configv1alpha1.PlaybookSpec{Agent: &configv1alpha1.PlaybookAgent{Evidence: []string{"sbom"}}}}))

	require.NoError(t, api.Create(ctx, &configv1alpha1.AgentProfile{ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: configv1alpha1.AgentProfileSpec{Limits: &configv1alpha1.AgentLimits{MaxSteps: ptr.To(int32(6))}}}))
	name := "assessment-a"
	require.NoError(t, api.Create(ctx, &triagev1alpha1.Assessment{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: triagev1alpha1.AssessmentSpec{VulnerabilityID: vulnerability, Subject: triagev1alpha1.AssessmentSubject{
			Type:           triagev1alpha1.SubjectTypeContainerImage,
			ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: manifest}}}}))
	var a triagev1alpha1.Assessment
	require.NoError(t, api.Get(ctx, client.ObjectKey{Name: name}, &a))
	a.Status.CaseFilePlaybook = ptr.To(playbook)
	a.Status.InvestigationRef = &triagev1alpha1.InvestigationReference{Namespace: "team-a", Name: "investigation-a",
		UID: investigationUID}
	require.NoError(t, api.Update(ctx, &a))
	require.NoError(t, api.Create(ctx, &triagev1alpha1.Investigation{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "investigation-a", UID: investigationUID},
		Spec: triagev1alpha1.InvestigationSpec{PlaybookRef: triagev1alpha1.PlaybookReference{Name: playbook},
			Agent: triagev1alpha1.InvestigationAgent{MaxCases: 1, Guidance: ptr.To(guidance)}}}))

	subject := ledger.SubjectOf(name)
	l := ledger.New(name, nil, 16000)
	l.Add("search_tools", json.RawMessage(`{"query":"describe a vulnerability"}`), []byte(describe+": Describe\n"),
		ledger.External, 0)
	l.Add(describe, json.RawMessage(`{"vulnerabilityID":"CVE-2026-0001"}`), []byte("answer of describe\n"),
		ledger.Known, 0)
	for _, e := range l.Entries() {
		rec, err := sdkevidence.New(sdkevidence.TypeToolOutput, subject, sdkevidence.ToolOutput{Entry: e.ID, Tool: e.Tool,
			Output: string(e.Output), OutputBytes: int64(len(e.Output))}, sdkevidence.WithSource("/hub/agent"))
		require.NoError(t, err)
		require.NoError(t, store.Put(ctx, e.ID, "run", rec))
	}
	require.NoError(t, inventory.NewCRDLedgerStore(api).Put(ctx, l.Object()))
	return api, name
}

// message is the part of a request that the scripted endpoint reads.
type request struct {
	Messages []struct {
		Role    string  `json:"role"`
		Content *string `json:"content"`
	} `json:"messages"`
}

// endpoint is a scripted model over TLS: it answers the n-th request with the tool call that script names.
type endpoint struct {
	*httptest.Server
	seen []request
}

func newEndpoint(t *testing.T, script func(n int) [2]string) *endpoint {
	t.Helper()
	e := &endpoint{}
	e.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req request
		_ = json.Unmarshal(body, &req)
		e.seen = append(e.seen, req)
		c := script(len(e.seen))
		if c[0] == "fail" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "tool_calls": []map[string]any{{
				"id": fmt.Sprintf("call_%d", len(e.seen)), "type": "function",
				"function": map[string]any{"name": c[0], "arguments": c[1]}}}}, "finish_reason": "stop"}},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	t.Cleanup(e.Close)
	return e
}

const affected = `{"status":"affected","nextStep":"update the image","summary":"The image installs libbrotli1.",` +
	`"claims":[{"text":"the image installs the package","evidence":["ev-2"]}]}`

// describedThen is a model that finds describe, calls it, and then submits the verdict.
func describedThen(verdict string) func(n int) [2]string {
	return func(n int) [2]string {
		switch n {
		case 1:
			return [2]string{"search_tools", `{"query":"describe a vulnerability"}`}
		case 2:
			return [2]string{describe, `{"vulnerabilityID":"CVE-2026-0001"}`}
		}
		return [2]string{"submit_verdict", verdict}
	}
}

// exported exports the case, and returns the directory of the cases.
func exported(t *testing.T) string {
	t.Helper()
	api, name := theCluster(t)
	dir := t.TempDir()
	require.NoError(t, export(t.Context(), api, name, dir, "vexplain-system"))
	return dir
}

// replayCases runs the cases against the endpoint, and returns what it printed.
func replayCases(t *testing.T, e *endpoint, dir string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	code := run(t.Context(), []string{cmdRun, "--cases", dir, "--endpoint", e.URL, "--model", "model-a",
		"--context-window", "200000"}, func(k string) string {
		if k == keyEnv {
			return apiKey
		}
		return ""
	}, &out, llm.WithHTTPClient(e.Client()))
	return out.String(), code
}

func TestAnExportedCaseReplaysToTheSameOutcome(t *testing.T) {
	dir := exported(t)
	for _, f := range []string{caseFile, casefileFile, evidenceFile, validatorFile, profileFile, callsFile} {
		require.FileExists(t, filepath.Join(dir, "assessment-a", f))
	}
	raw, err := os.ReadFile(filepath.Join(dir, "assessment-a", "calls.json"))
	require.NoError(t, err)
	require.Contains(t, string(raw), "answer of describe", "the forwarded call is recorded with its output")
	require.NotContains(t, string(raw), "Describe", "a core tool is run again, not recorded")

	var saved savedProfile
	require.NoError(t, readJSON(filepath.Join(dir, "assessment-a", profileFile), &saved))
	require.Equal(t, 6, saved.Limits.MaxSteps, "the limits that the profile set are recorded")
	require.Equal(t, 15, saved.Limits.MaxTokens/20000, "and the defaults of the rest")
	require.Equal(t, guidance, saved.InvestigationGuidance, "the guidance of the investigation that it was judged for")

	e := newEndpoint(t, describedThen(affected))
	out, code := replayCases(t, e, dir)
	require.Zero(t, code, out)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2, "one line for the case, and a total")
	var got, total result
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &got))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &total))
	require.Equal(t, "assessment-a", got.Case)
	require.Equal(t, "Affected", got.Outcome)
	require.Equal(t, 3, got.Steps)
	require.Equal(t, 30, got.PromptTokens)
	require.Equal(t, 15, got.CompletionTokens)
	require.Positive(t, got.PeakContextTokens)
	require.Zero(t, got.Rejections)
	require.Equal(t, "total", total.Case)
	require.Equal(t, 3, total.Steps)

	casefileJSON, err := os.ReadFile(filepath.Join(dir, "assessment-a", casefileFile))
	require.NoError(t, err)
	require.Contains(t, string(casefileJSON), `"purl": "pkg:deb/debian/libbrotli1@1.0.9-2"`)
	require.Contains(t, string(casefileJSON), `"distro": "debian-12"`)
	sent, err := json.Marshal(e.seen[0].Messages)
	require.NoError(t, err)
	require.Contains(t, string(sent), `purl\":\"pkg:deb/debian/libbrotli1@1.0.9-2\",\"distro\":\"debian-12`,
		"the replayed case file names the purl and distro, as the hub's does")
	require.Equal(t, "system", e.seen[0].Messages[0].Role)
	require.Equal(t, prompt.System(saved.Guidance, guidance), *e.seen[0].Messages[0].Content,
		"the prompt as the worker builds it, with the investigation's guidance")
}

// A case judged for an earlier object of the investigation's name was judged with that object's guidance, which the
// object that is there now doesn't hold: the export gives none, as for an investigation that is gone.
func TestAnExportGivesNoGuidanceForAnotherUID(t *testing.T) {
	api, name := theCluster(t)
	var a triagev1alpha1.Assessment
	require.NoError(t, api.Get(t.Context(), client.ObjectKey{Name: name}, &a))
	a.Status.InvestigationRef.UID = "uid-of-an-earlier-object"
	require.NoError(t, api.Update(t.Context(), &a))
	dir := t.TempDir()
	require.NoError(t, export(t.Context(), api, name, dir, "vexplain-system"))

	var saved savedProfile
	require.NoError(t, readJSON(filepath.Join(dir, name, profileFile), &saved))
	require.Empty(t, saved.InvestigationGuidance)
}

// Only the hub decides exposure, and the Assessment's queue holds what it decided, as the worker's case file takes it:
// an exported case keeps its exposure groups, in its case and its case file, and its replay shows them to the model.
func TestAnExportedCaseKeepsItsExposureGroups(t *testing.T) {
	api, name := theCluster(t)
	var a triagev1alpha1.Assessment
	require.NoError(t, api.Get(t.Context(), client.ObjectKey{Name: name}, &a))
	now := metav1.Now()
	a.Status.Queue = &triagev1alpha1.AssessmentQueue{Playbook: playbook, QueuedTime: &now,
		Order: triagev1alpha1.QueueOrder{UrgencyRank: ptr.To(int32(3)),
			KnownExploited: triagev1alpha1.KnownExploitedNotListed, Resources: ptr.To(int32(0))},
		RunsIn: &triagev1alpha1.QueueRunsIn{HighestExposure: ptr.To(triagev1alpha1.SSVCExposureSmall),
			HighestUrgency: ptr.To(triagev1alpha1.SSVCOutcomeScheduled), UrgentWorkloads: ptr.To(int32(0)),
			Exposure: []triagev1alpha1.ExposureGroup{{Exposure: triagev1alpha1.SSVCExposureSmall,
				Rules: []string{"own-namespace-only"}, Workloads: ptr.To(int32(1)),
				First: []string{"workload/cluster-a/team-a/StatefulSet.apps/batch"}}}}}
	require.NoError(t, api.Update(t.Context(), &a))
	dir := t.TempDir()
	require.NoError(t, export(t.Context(), api, name, dir, "vexplain-system"))

	var saved struct {
		Impact struct{ Exposure []map[string]any }
	}
	require.NoError(t, readJSON(filepath.Join(dir, name, caseFile), &saved))
	require.Len(t, saved.Impact.Exposure, 1, "the case keeps its groups")
	group := `{"exposure":"Small","rules":["own-namespace-only"],"workloads":1,` +
		`"first":["workload/cluster-a/team-a/StatefulSet.apps/batch"]}`
	casefileJSON, err := os.ReadFile(filepath.Join(dir, name, casefileFile))
	require.NoError(t, err)
	var shown struct {
		RunsIn struct {
			Exposure []json.RawMessage `json:"exposure"`
		} `json:"runsIn"`
	}
	require.NoError(t, json.Unmarshal(casefileJSON, &shown))
	require.Len(t, shown.RunsIn.Exposure, 1)
	require.JSONEq(t, group, string(shown.RunsIn.Exposure[0]), "and so does its case file")

	e := newEndpoint(t, describedThen(affected))
	out, code := replayCases(t, e, dir)
	require.Zero(t, code, out)
	sent, err := json.Marshal(e.seen[0].Messages)
	require.NoError(t, err)
	require.Contains(t, string(sent), `own-namespace-only`, "the replayed case file shows them to the model")
}

// The replay's validator checks the verdict against the investigation's guidance, as the worker's does.
func TestTheReplaysValidatorKnowsTheInvestigationsGuidance(t *testing.T) {
	dir := exported(t)
	leaning := strings.Replace(affected, "The image installs libbrotli1.", guidance, 1)
	e := newEndpoint(t, describedThen(leaning))
	out, code := replayCases(t, e, dir)
	require.Zero(t, code, out)
	var got result
	require.NoError(t, json.Unmarshal([]byte(strings.Split(out, "\n")[0]), &got))
	require.Equal(t, 2, got.Rejections, "the verdict and its repair repeat the guidance")
}

func TestAnUnrecordedCallIsAToolError(t *testing.T) {
	e := newEndpoint(t, func(n int) [2]string {
		switch n {
		case 1:
			return [2]string{"search_tools", `{"query":"describe a vulnerability"}`}
		case 2:
			return [2]string{describe, `{"vulnerabilityID":"CVE-2026-9999"}`}
		}
		return [2]string{"submit_no_verdict", `{"why":"no answer","established":"the lookup is not recorded (ev-2)",` +
			`"wouldSettle":"a lookup"}`}
	})
	out, code := replayCases(t, e, exported(t))
	require.Zero(t, code, out)
	require.Len(t, e.seen, 3)
	last := e.seen[2].Messages[len(e.seen[2].Messages)-1]
	require.Contains(t, *last.Content, "not recorded")
	require.Contains(t, out, `"outcome":"GaveUp"`)
}

func TestTheOutputNeverNamesTheEndpointOrPrintsTheKey(t *testing.T) {
	ok := newEndpoint(t, func(int) [2]string {
		return [2]string{"submit_no_verdict", `{"why":"w","established":"e (ev-1)","wouldSettle":"s"}`}
	})
	out, _ := replayCases(t, ok, exported(t))
	refusing := newEndpoint(t, func(int) [2]string { return [2]string{"fail", ""} })
	failed, code := replayCases(t, refusing, exported(t))
	require.NotZero(t, code, "a case that the model could not judge fails the run")
	for _, text := range []string{out, failed} {
		require.NotContains(t, text, apiKey)
		require.NotContains(t, text, ok.URL)
		require.NotContains(t, text, refusing.URL)
		require.NotContains(t, text, strings.TrimPrefix(ok.URL, "https://"))
		require.NotContains(t, text, strings.TrimPrefix(refusing.URL, "https://"))
	}
	require.Contains(t, failed, `"error"`)
}

func TestTheRunNeedsTheKeyFromTheEnvironment(t *testing.T) {
	var out bytes.Buffer
	code := run(context.Background(), []string{cmdRun, "--cases", t.TempDir(), "--endpoint", "https://llm.example/v1",
		"--model", "model-a"}, func(string) string { return "" }, &out)
	require.Equal(t, exitUsage, code)
	require.Contains(t, out.String(), keyEnv)
}
