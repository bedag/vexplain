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

// Command agent-replay measures the agent of phase 4 on saved cases, before anything goes live: the tokens, the steps
// and the peak context of each case, and how it ended, against a chosen model and without the cluster's tools.
//
// It has two steps. export reads a judged case from a cluster, through the kubeconfig of the person who runs it, and
// saves what a replay needs into a directory of its own: the case, its evidence, the validator's case, the profile's
// limits and guidance, and the forwarded tool calls with their recorded outputs and trust. run judges each saved case
// again with the runner and vexplain's MCP server, whose forwarded tools answer from the recordings.
//
//	agent-replay export --assessment NAME --out DIR [--kubeconfig FILE] [--namespace NAMESPACE]
//	VEXPLAIN_LLM_API_KEY=... agent-replay run --cases DIR --endpoint URL --model NAME [--context-window N]
//
// The key comes only from the environment, and is only ever sent to the endpoint. The output names neither.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/internal/llm"
	"github.com/bedag/vexplain/internal/setup"
)

// keyEnv is the environment variable that holds the API key. A flag would show in the list of processes.
// The commands.
const (
	cmdExport = "export"
	cmdRun    = "run"
)

const keyEnv = "VEXPLAIN_LLM_API_KEY"

// The exit codes.
const (
	exitOK           = 0
	exitFailed       = 1
	exitUsage        = 2
	defaultNamespace = "vexplain-system"
)

const usage = `Usage:
  agent-replay export --assessment NAME --out DIR [--kubeconfig FILE] [--namespace NAMESPACE]
  agent-replay run --cases DIR --endpoint URL --model NAME [--context-window N]

export saves the judged case of an Assessment into DIR/NAME, read through your kubeconfig (the default loading rules,
or --kubeconfig). --namespace is the operator's, where a guidance ConfigMap lives (default vexplain-system).

run judges every case in DIR again, and prints one JSON line for each: steps, promptTokens, completionTokens,
peakContextTokens, outcome (the verdict's status, or the reason of the no-verdict), rejections and, where the run
failed, error; then a line with the total. --context-window is the model's window in tokens for the fit check; without
it the check is off. The API key is read from the environment variable VEXPLAIN_LLM_API_KEY.

The exit code is 0, or 1 when a case could not be judged, or 2 for a usage error.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout)
	stop() // os.Exit doesn't run deferred calls.
	os.Exit(code)
}

// run is the tool. It takes what main takes from the process, so that a test can drive it, and returns the exit code.
// opts change how the client of the endpoint is built.
func run(ctx context.Context, args []string, getenv func(string) string, out io.Writer, opts ...llm.Option) int {
	if len(args) == 0 {
		say(out, "%s", usage)
		return exitUsage
	}
	var err error
	switch args[0] {
	case cmdExport:
		err = exportCommand(ctx, args[1:], out)
	case cmdRun:
		err = runCommand(ctx, args[1:], getenv, out, opts)
	case "-h", "--help", "help":
		say(out, "%s", usage)
		return exitOK
	default:
		err = usageError{fmt.Errorf("unknown command %q", args[0])}
	}
	var bad usageError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &bad):
		say(out, "agent-replay: %v\n\n%s", err, usage)
		return exitUsage
	}
	say(out, "agent-replay: %v\n", err)
	return exitFailed
}

// usageError is a mistake in the command line, as opposed to a failure of the work.
type usageError struct{ error }

// say prints to out. The tool can do nothing about a terminal that it can't write to.
func say(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

// exportCommand reads the flags of export, builds the client from the kubeconfig and exports the case.
func exportCommand(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	assessment := flags.String("assessment", "", "")
	dir := flags.String("out", "", "")
	kubeconfig := flags.String("kubeconfig", "", "")
	namespace := flags.String("namespace", defaultNamespace, "")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if *assessment == "" || *dir == "" || flags.NArg() > 0 {
		return usageError{errors.New("--assessment and --out are required")}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = *kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil).ClientConfig()
	if err != nil {
		return fmt.Errorf("load the kubeconfig: %w", err)
	}
	scheme := runtime.NewScheme()
	if err := setup.AddToScheme(scheme); err != nil {
		return err
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("connect to the cluster: %w", err)
	}
	if err := export(ctx, c, *assessment, *dir, *namespace); err != nil {
		return err
	}
	say(out, "exported %s to %s\n", *assessment, *dir)
	return nil
}

// runCommand reads the flags and the key of run, and replays the cases.
func runCommand(ctx context.Context, args []string, getenv func(string) string, out io.Writer,
	opts []llm.Option) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("cases", "", "")
	endpoint := flags.String("endpoint", "", "")
	model := flags.String("model", "", "")
	window := flags.Int("context-window", 0, "")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	key := strings.TrimSpace(getenv(keyEnv))
	switch {
	case flags.NArg() > 0:
		return usageError{errors.New("unexpected arguments")}
	case *dir == "", *endpoint == "", *model == "":
		return usageError{errors.New("--cases, --endpoint and --model are required")}
	case *window < 0:
		return usageError{errors.New("--context-window must not be negative")}
	case key == "":
		return usageError{fmt.Errorf("the API key is not set: put it in %s", keyEnv)}
	}
	hidden := []string{key, *endpoint}
	if u, err := url.Parse(*endpoint); err == nil {
		hidden = append(hidden, u.Host)
	}
	return replay(ctx, *dir, replayConfig{endpoint: *endpoint, model: *model, key: llm.NewSecret(key), window: *window,
		opts: opts, hidden: hidden}, out)
}
