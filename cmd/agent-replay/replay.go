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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/bedag/vexplain/internal/agent/casefile"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/prompt"
	"github.com/bedag/vexplain/internal/agent/runner"
	"github.com/bedag/vexplain/internal/agent/validator"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/llm"
	"github.com/bedag/vexplain/internal/setup"
)

// replayConfig is what a run judges the cases with. key is a Secret, so that no print of the config can show it.
type replayConfig struct {
	endpoint, model string
	key             llm.Secret
	// window is the model's context window for the fit check; zero switches the check off.
	window int
	opts   []llm.Option
	// hidden are the texts that no output may hold: the key, the endpoint and its host.
	hidden []string
}

// result is the line of a case, and of the total. The total's steps and tokens are sums, its peak the highest, and
// its outcome is empty.
type result struct {
	Case              string `json:"case"`
	Steps             int    `json:"steps"`
	PromptTokens      int    `json:"promptTokens"`
	CompletionTokens  int    `json:"completionTokens"`
	PeakContextTokens int    `json:"peakContextTokens"`
	Outcome           string `json:"outcome,omitempty"`
	Rejections        int    `json:"rejections"`
	Error             string `json:"error,omitempty"`
}

// replay judges every saved case in dir with the runner and prints one JSON line for each, then the total. It returns
// an error when a case could not be judged: the endpoint failed it, or a saved case can't be read.
func replay(ctx context.Context, dir string, cfg replayConfig, out io.Writer) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	total := result{Case: "total"}
	failed, n := 0, 0
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(dir, e.Name(), caseFile)); !e.IsDir() || err != nil {
			continue
		}
		n++
		r := judge(ctx, filepath.Join(dir, e.Name()), cfg)
		r.Case = e.Name()
		line, _ := json.Marshal(r)
		say(out, "%s\n", line)
		total.Steps += r.Steps
		total.PromptTokens += r.PromptTokens
		total.CompletionTokens += r.CompletionTokens
		total.PeakContextTokens = max(total.PeakContextTokens, r.PeakContextTokens)
		total.Rejections += r.Rejections
		if r.Error != "" {
			failed++
		}
	}
	if n == 0 {
		return fmt.Errorf("no saved case in %s", dir)
	}
	line, _ := json.Marshal(total)
	say(out, "%s\n", line)
	if failed > 0 {
		return fmt.Errorf("%d of %d cases could not be judged", failed, n)
	}
	return nil
}

// judge judges the saved case in dir, and returns its result. A failure is in Error, with the endpoint and the key
// taken out of it.
func judge(ctx context.Context, dir string, cfg replayConfig) result {
	res, err := judgeCase(ctx, dir, cfg)
	if err != nil {
		res.Error = hide(err.Error(), cfg)
	}
	return res
}

func judgeCase(ctx context.Context, dir string, cfg replayConfig) (result, error) {
	var (
		theCase cases.Case
		data    map[string][]json.RawMessage
		vc      validator.Case
		prof    savedProfile
		calls   []recorded
		// packages are absent from a case saved before the case file named purls.
		packages map[string]casefile.Package
	)
	prof.Limits, prof.Guidance = profile.LimitsOf(nil), prompt.Guidance()
	for file, v := range map[string]any{caseFile: &theCase, evidenceFile: &data, validatorFile: &vc, callsFile: &calls} {
		if err := readJSON(filepath.Join(dir, file), v); err != nil {
			return result{}, err
		}
	}
	if err := readJSON(filepath.Join(dir, profileFile), &prof); err != nil && !errors.Is(err, os.ErrNotExist) {
		return result{}, err
	}
	if err := readJSON(filepath.Join(dir, packagesFile), &packages); err != nil && !errors.Is(err, os.ErrNotExist) {
		return result{}, err
	}
	file, err := casefile.Build(theCase, data, packages, 4*prof.Limits.CaseFileMaxTokens)
	if err != nil {
		return result{}, err
	}
	scheme := runtime.NewScheme()
	if err := setup.AddToScheme(scheme); err != nil {
		return result{}, err
	}
	api := fake.NewClientBuilder().WithScheme(scheme).Build()
	store := evidence.NewCRDStore(api, nil, func() string { return "replay" })
	vc.Guidance = prof.InvestigationGuidance
	session := core.NewSession(core.Deps{Evidence: store, Validator: validator.New(vc), Forwarder: recordings(calls)},
		theCase, file, profile.Effective{Name: "replay", Limits: prof.Limits})

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server, err := session.Server().Connect(ctx, serverTransport, nil)
	if err != nil {
		return result{}, err
	}
	defer func() { _ = server.Close() }()
	clientSession, err := mcp.NewClient(&mcp.Implementation{Name: "agent-replay", Version: prompt.CoreVersion}, nil).
		Connect(ctx, clientTransport, nil)
	if err != nil {
		return result{}, err
	}
	defer func() { _ = clientSession.Close() }()

	model := llm.New(llm.Config{BaseURL: cfg.endpoint, Model: cfg.model, APIKey: cfg.key, Timeout: requestTimeout,
		MaxConcurrent: 1, TemperatureMilli: temperatureMilli}, cfg.opts...)
	system := prompt.System(prof.Guidance, prof.InvestigationGuidance)
	run := runner.Builtin{Client: model}.Run(ctx, clientSession, runner.Input{Prompt: system, CaseFile: file.JSON,
		Limits: prof.Limits, ContextWindowTokens: cfg.window})

	o := session.Outcome()
	r := result{Steps: run.Steps, PromptTokens: run.Usage.PromptTokens, CompletionTokens: run.Usage.CompletionTokens,
		PeakContextTokens: run.PeakContextTokens, Rejections: len(o.Rejections)}
	switch {
	case o.Verdict != nil:
		r.Outcome = o.Verdict.Status
	case o.NoVerdict != nil:
		r.Outcome = o.NoVerdict.Reason
	default:
		r.Outcome = run.Limit // the limit ended the case, and the final call gave no summary.
	}
	return r, run.Err
}

// The settings of the client: the defaults of a ModelConfig, as cmd/llm-smoke has them.
const (
	requestTimeout   = 60 * time.Second
	temperatureMilli = 200
)

// readJSON reads the file into v.
func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return nil
}

// hide takes the hidden texts out of text, so that nothing printed names the endpoint or holds the key.
func hide(text string, cfg replayConfig) string {
	for _, secret := range cfg.hidden {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[hidden]")
		}
	}
	return text
}

// recordings is the Forwarder of a replay: it answers a call of a tool with the same arguments as a recorded one with
// that call's output and trust, and any other call with the tool error "not recorded".
//
// shortcut: the recorded tools list a permissive schema, as the Ledger keeps no definitions, so a search shows the
// model less than the live tools do; export the definitions too if the replay's context turns out to be too low.
type recordings []recorded

func (r recordings) Tools(context.Context) ([]core.Tool, error) {
	var tools []core.Tool
	var seen []string
	for _, c := range r {
		if !slices.Contains(seen, c.Tool) {
			seen = append(seen, c.Tool)
			tools = append(tools, core.Tool{Name: c.Tool, Description: "Recorded tool " + c.Tool,
				InputSchema: json.RawMessage(`{"type":"object"}`)})
		}
	}
	return tools, nil
}

func (r recordings) Call(_ context.Context, tool string, args json.RawMessage) ([]byte, ledger.Trust, error) {
	for _, c := range r {
		if c.Tool == tool && canonical([]byte(c.Arguments)) == canonical(args) {
			return []byte(c.Output), c.Trust, nil
		}
	}
	return nil, "", errors.New("not recorded: this call was not made when the case was recorded")
}

// canonical returns JSON with its keys in order and no spaces, so that the same arguments compare equal however the
// model spelled them. Arguments that aren't JSON, such as ones that the ledger cut, compare as they are.
func canonical(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(bytes.TrimSpace(raw))
	}
	out, _ := json.Marshal(v)
	return string(out)
}
