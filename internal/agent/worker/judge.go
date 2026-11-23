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

package worker

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/casefile"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/prompt"
	"github.com/bedag/vexplain/internal/agent/runner"
	"github.com/bedag/vexplain/internal/agent/validator"
	"github.com/bedag/vexplain/internal/agent/verdict"
	"github.com/bedag/vexplain/internal/conditions"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/llm"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/text"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

const (
	// defaultSwitchPoll is how often a case in progress looks at the agent's switch.
	defaultSwitchPoll = 2 * time.Second
	// limitTimeout bounds the reads of the limit of cases judged at once.
	limitTimeout = 5 * time.Second
	// The bounds of what an Assessment holds of a verdict.
	maxSummaryChars = 2048
	maxStepChars    = 1024
	maxClaims       = 32
	maxClaimChars   = 1024
	maxClaimIDs     = 32
	// The reasons of the agent's events, and their action.
	reasonNoVerdict       = "NoVerdict"
	reasonVerdictRejected = "VerdictRejected"
	eventActionJudge      = "Judge"
	// noVerdictOutcome is the outcome of a case without a verdict in the metric of cases.
	noVerdictOutcome = "NoVerdict"
)

// osPackageTypes are the types of packages that a distribution ships, which describe reads in a release: the image's
// when the purl names none.
var osPackageTypes = []string{"deb", "rpm", "apk"}

// limitFields are the profile's names of the limits.
var limitFields = map[string]string{verdict.ReasonMaxSteps: "maxSteps", verdict.ReasonMaxTokens: "maxTokens",
	verdict.ReasonTimeout: "timeoutSeconds", verdict.ReasonContextLimit: "contextWindowTokens"}

// Agent judges the cases that a worker claims from the agent's queue, one at a time for each claim (design of the agent
// on image cases, 5.4 to 5.6 and 5.11, and decision 0057). For a case, it resolves the profile of the case-file
// playbook, builds the case file from that playbook's sheet, opens a session of vexplain's MCP server and runs the
// builtin runner through it, on the profile's ModelConfig. When the case ends, it writes the ledger and the
// Assessment's status once, and records the events and metrics.
//
// A case waits in the queue while it can't start: the agent is switched off, its profile or its ModelConfig isn't
// Ready, or what it needs can't be read. A case in progress goes back to the queue with nothing written when the agent
// is switched off, and so does one whose worker stops or loses its claim.
type Agent struct {
	// Client reads the configuration and writes the Assessments' status. APIReader reads an Assessment from the API
	// server, past the cache, before its case starts and before each write of its status, so that a write never rests
	// on a status that the cache doesn't show yet.
	Client    client.Client
	APIReader client.Reader
	// OperatorNamespace holds the ConfigMap of a profile's guidance.
	OperatorNamespace string
	// Verdicts holds the sheets, Evidence the case file's evidence and the tool outputs, and Ledgers the ledgers.
	Verdicts inventory.VerdictsStore
	Evidence evidence.Store
	Ledgers  inventory.LedgerStore
	// Pool and ClusterContext call the collectors' operations that a profile grants, and MCP the MCP collectors' tools.
	Pool           core.CollectorPool
	MCP            core.MCPPool
	ClusterContext func(context.Context) (*collectorv1alpha1.Context, error)
	// ClientConfig returns the client configuration of a ModelConfig, with its API key, which only the client reads.
	ClientConfig func(ctx context.Context, modelConfig string) (llm.Config, error)
	// HTTPClient is the HTTP client of the requests to the model. Nil means the llm package's default.
	HTTPClient *http.Client
	// Recorder records the events NoVerdict, VerdictRejected and AgentDisabled.
	Recorder events.EventRecorder
	// SwitchPoll is how often a case in progress looks at the agent's switch. Zero means 2 seconds.
	SwitchPoll time.Duration
	// GuidanceTimeout bounds the read of the guidance of a case's investigation. Zero means 30 seconds.
	GuidanceTimeout time.Duration
}

// The agent reads the configuration that a case runs with, and the guidance of the investigation that the case is
// charged to, writes the Assessments' status, and records its events.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=agentprofiles;modelconfigs;playbooks;operatorconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments;investigations,verbs=get;list;watch
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments/status,verbs=update
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
//
// A case reads its case file's evidence and writes the full output of each tool call as evidence of its own, which
// updates in place a record of another version, such as an earlier run's; it writes its ledger; it calls the
// operations of the Collectors that its profile grants; and its profile's guidance is a ConfigMap of the operator's
// namespace.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=evidences,verbs=get;create;update
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=ledgers,verbs=get;create;update
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch,namespace=vexplain-system
//
// The Secrets that the workers read are in the operator's namespace, so the rule is a Role there: the LLM keys, from
// their cache of the labelled Secrets, which the ModelConfig controller watches too; the MCP collectors' headers, which
// the MCP pool lists through the API reader, by their label; and the workers' client certificate, from a cache of its
// own. Markers generate no bindings: config/rbac/agent/role_binding.yaml binds the Role.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch,namespace=vexplain-system

// defaultWorkers is the default of a ModelConfig's maxConcurrentRequests, which the CRD applies.
const defaultWorkers = 2

// Workers returns how many cases may be judged at once: the maxConcurrentRequests of the default profile's
// ModelConfig, so that every worker has a request slot of the model. It is 1 while that can't be read.
func (a *Agent) Workers() int {
	ctx, cancel := context.WithTimeout(context.Background(), limitTimeout)
	defer cancel()
	var p configv1alpha1.AgentProfile
	var model configv1alpha1.ModelConfig
	if a.Client.Get(ctx, client.ObjectKey{Name: profile.DefaultName}, &p) != nil ||
		a.Client.Get(ctx, client.ObjectKey{Name: p.Spec.ModelRef.Name}, &model) != nil {
		return 1
	}
	return int(ptr.Deref(model.Spec.MaxConcurrentRequests, defaultWorkers))
}

// CanStart reports whether cases can start now, as prepare checks for every case: the agent is switched on, and the
// default profile's ModelConfig is Ready. It reads the cache, so the claim loop can ask before each round of claims.
// Once it knows the cluster's name, it starts the agent's counters for it at 0, whether or not cases can start.
func (a *Agent) CanStart() bool {
	ctx, cancel := context.WithTimeout(context.Background(), limitTimeout)
	defer cancel()
	cfg, err := settings.Load(ctx, a.Client)
	if err != nil {
		return false
	}
	startCounters(cfg.ClusterName)
	if cfg.AgentState != configv1alpha1.AgentStateEnabled {
		return false
	}
	var p configv1alpha1.AgentProfile
	var model configv1alpha1.ModelConfig
	return a.Client.Get(ctx, client.ObjectKey{Name: profile.DefaultName}, &p) == nil &&
		a.Client.Get(ctx, client.ObjectKey{Name: p.Spec.ModelRef.Name}, &model) == nil && modelReady(&model)
}

// startCounters creates each known label value of the agent's counters at 0 for the cluster, so that a rate sees the
// first count. Where a label value exists, it changes nothing. The manager never calls it: it judges no case.
func startCounters(cluster string) {
	for _, outcome := range []string{string(triagev1alpha1.VEXStatusAffected), string(triagev1alpha1.VEXStatusUnderInvestigation),
		string(triagev1alpha1.VEXStatusNotAffected), string(triagev1alpha1.VEXStatusFixed), noVerdictOutcome} {
		metrics.AgentCasesTotal.WithLabelValues(cluster, outcome)
	}
	for _, reason := range append([]string{verdict.ReasonGaveUp, verdict.ReasonValidatorRejected, verdict.ReasonModelError},
		verdict.Limits...) {
		metrics.AgentNoVerdictsTotal.WithLabelValues(cluster, reason)
	}
	for _, check := range validator.Checks {
		metrics.AgentRejectionsTotal.WithLabelValues(cluster, check)
	}
	for _, kind := range []string{"prompt", "completion"} {
		metrics.AgentTokensTotal.WithLabelValues(cluster, kind)
	}
}

// spendingOf creates at 0 the series of what the judgement of the Assessment spends for the investigation that its
// cap is charged to, the queue's investigationRef, so that a rate sees its first count, and returns what adds to them.
// That investigation may want the case no more: it was charged all the same. A case charged to none counts for none.
func spendingOf(cluster string, a *triagev1alpha1.Assessment) func(promptTokens, completionTokens int, took time.Duration) {
	if a.Status.Queue == nil || a.Status.Queue.InvestigationRef == nil {
		return func(int, int, time.Duration) {}
	}
	inv := a.Status.Queue.InvestigationRef
	read := metrics.InvestigationAgentTokensTotal.WithLabelValues(cluster, inv.Namespace, inv.Name, "prompt")
	written := metrics.InvestigationAgentTokensTotal.WithLabelValues(cluster, inv.Namespace, inv.Name, "completion")
	seconds := metrics.InvestigationAgentSecondsTotal.WithLabelValues(cluster, inv.Namespace, inv.Name)
	return func(p, c int, took time.Duration) {
		read.Add(float64(p))
		written.Add(float64(c))
		seconds.Add(took.Seconds())
	}
}

// modelReady reports whether the ModelConfig is Ready at its generation.
func modelReady(m *configv1alpha1.ModelConfig) bool {
	ready := meta.FindStatusCondition(m.Status.Conditions, configv1alpha1.ConditionReady)
	return ready != nil && ready.Status == metav1.ConditionTrue && ready.ObservedGeneration == m.Generation
}

// work is what a case runs with.
type work struct {
	c    cases.Case
	name string
	// playbook is the playbook whose case file the case gets.
	playbook string
	// cluster names this cluster in the metrics.
	cluster string
	profile profile.Effective
	// guidance is the guidance of the investigation that the case is charged to.
	guidance  string
	config    llm.Config
	file      casefile.CaseFile
	inputHash string
	validator validator.Case
}

// maxFailures is how many judgements of a case in a row may fail, at a request to the model after spending tokens or at
// the write of the outcome, before the case ends without a verdict: each attempt spends the tokens of its steps again.
const maxFailures = 5

// Judge judges the case c for the request r, and says what became of it. failures counts its judgements that failed
// after spending tokens, or at the write of the outcome, or whose worker stopped, since the case came into the queue: a
// wait for another reason doesn't start the count again. A case handed back waits in the queue with nothing written:
// its worker writes that it waits. The outcome is written only while the case's claim names the worker of ctx.
func (a *Agent) Judge(ctx context.Context, c cases.Case, r cases.Request, failures int) Result {
	name := cases.Name(c.VulnerabilityID, c.ManifestDigest)
	log := logf.FromContext(ctx).WithValues("assessment", name)
	// The cached Assessment names the playbooks that can give the case file.
	// A cache that lags may not show it yet: only the read past the cache below says that it is gone.
	var known triagev1alpha1.Assessment
	if err := a.Client.Get(ctx, client.ObjectKey{Name: name}, &known); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "Could not read the Assessment of the case; it waits in the queue")
		}
		return Wait
	}
	w, err := a.prepare(ctx, c, r, &known)
	if err != nil {
		log.V(1).Info("The case waits in the queue", "reason", err.Error())
		return Wait
	}
	// Just before the case starts, the Assessment is read past the cache: an outcome that was just written must not be
	// judged again.
	var current triagev1alpha1.Assessment
	if err := a.APIReader.Get(ctx, client.ObjectKey{Name: name}, &current); err != nil {
		if apierrors.IsNotFound(err) {
			return Done // the case went with its Assessment
		}
		log.Error(err, "Could not read the Assessment of the case; it waits in the queue")
		return Wait
	}
	if holdsOutcome(&current, w.inputHash, r.JudgedAfter) {
		log.V(1).Info("The Assessment holds the outcome of the case's current inputs already")
		// An investigation may have queued it again meanwhile: left Queued, it would stay held.
		if err := a.setReady(ctx, name, metav1.Condition{Status: metav1.ConditionTrue, Reason: triagev1alpha1.ReasonJudged,
			Message: outcomeMessage(&current)}, conditions.None, ""); client.IgnoreNotFound(err) != nil {
			log.Error(err, "Could not mark the case as judged; it waits in the queue")
			return Wait
		}
		return Done
	}
	if err := a.setReady(ctx, name, metav1.Condition{Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonJudging,
		Message: "The agent judges the case."}, conditions.Reconciling, w.playbook); err != nil {
		if apierrors.IsNotFound(err) {
			return Done
		}
		log.Error(err, "Could not mark the case as judged now; it waits in the queue")
		return Wait
	}
	if failures >= maxFailures {
		// The case's workers stopped while they judged it, as their leases that ran out say, as often as failed
		// requests may end a case: each attempt may have spent tokens.
		err := a.write(ctx, w, runner.Result{}, core.Outcome{NoVerdict: &verdict.NoVerdict{Reason: verdict.ReasonModelError,
			Why: fmt.Sprintf("The case's judgements failed %d times in a row.", failures)}}, 0)
		if err != nil {
			log.Error(err, "Could not write the outcome of the case; it is judged again later")
			return Failed
		}
		return Done
	}
	spend := spendingOf(w.cluster, &current)
	caseCtx, cancel := context.WithCancel(ctx)
	switchedOff := a.watchSwitch(caseCtx, cancel)
	start := time.Now()
	res, outcome := a.run(caseCtx, w)
	cancel()
	metrics.AgentTokensTotal.WithLabelValues(w.cluster, "prompt").Add(float64(res.Usage.PromptTokens))
	metrics.AgentTokensTotal.WithLabelValues(w.cluster, "completion").Add(float64(res.Usage.CompletionTokens))
	spend(res.Usage.PromptTokens, res.Usage.CompletionTokens, time.Since(start))
	// A limit whose final call a stop or the switch cut off is no outcome: the case goes back with nothing written.
	ended := outcome.Verdict != nil || outcome.NoVerdict != nil
	switch {
	case ctx.Err() != nil && !ended:
		return Wait // the worker stops, or its claim names another worker
	case switchedOff() && !ended:
		a.disabled(ctx, name)
		return Wait
	case !ended && res.Limit == "" && res.Err != nil && handedBack(res.Err):
		// An attempt that spent no token, as when the endpoint is down or refuses the key, waits with a backoff for as
		// long as that lasts. Only failures that may have spent tokens count.
		spent := spentTokens(res)
		if !spent || failures+1 < maxFailures {
			log.Info("A request to the model failed; the case is judged again later", "reason", res.Err.Error())
			if !spent {
				return Retry
			}
			return Failed
		}
		outcome.NoVerdict = &verdict.NoVerdict{Reason: verdict.ReasonModelError, Why: fmt.Sprintf("The case's "+
			"requests to the model failed %d times in a row, the last time with: %v.", maxFailures, res.Err)}
	}
	err = a.write(ctx, w, res, outcome, time.Since(start))
	if err != nil && failures+1 >= maxFailures {
		// An outcome that the API server refuses every time, such as one that the schema rejects, must not have the case
		// judged again without end.
		err = a.write(ctx, w, res, core.Outcome{Ledger: outcome.Ledger, NoVerdict: &verdict.NoVerdict{
			Reason: verdict.ReasonModelError, Why: fmt.Sprintf("The outcome of the case couldn't be written %d times "+
				"in a row, the last time with: %v.", maxFailures, err)}}, time.Since(start))
	}
	if err != nil {
		log.Error(err, "Could not write the outcome of the case; it is judged again later")
		return Failed
	}
	return Done
}

// spentTokens reports whether a failed attempt may have spent tokens: a request of it completed, or its first request
// timed out, got a 2xx answer that isn't a chat completion or broke off, or a gateway's timeout, which the endpoint
// behind it may have billed all the same.
func spentTokens(res runner.Result) bool {
	var refused *llm.StatusError
	return res.Steps > 0 || errors.Is(res.Err, context.DeadlineExceeded) || errors.As(res.Err, &refused) &&
		(refused.Code >= http.StatusOK && refused.Code < http.StatusMultipleChoices || refused.Code == http.StatusGatewayTimeout)
}

// outcomeMessage returns the message of the Ready condition of an Assessment that holds an outcome.
func outcomeMessage(a *triagev1alpha1.Assessment) string {
	if v := a.Status.Verdict; v != nil {
		return "The agent recorded a verdict: " + string(v.Status) + "."
	}
	return "The agent ended the case without a verdict: " + string(ptr.Deref(a.Status.NoVerdict.Reason, "")) + "."
}

// holdsOutcome reports whether the Assessment holds a verdict, or no verdict, on the inputs of the hash, recorded at
// or after judgedAfter when that isn't zero.
func holdsOutcome(a *triagev1alpha1.Assessment, inputHash string, judgedAfter time.Time) bool {
	return (a.Status.Verdict != nil || a.Status.NoVerdict != nil) && ptr.Deref(a.Status.InputHash, "") == inputHash &&
		(judgedAfter.IsZero() || a.Status.JudgedTime != nil && !a.Status.JudgedTime.Time.Before(judgedAfter))
}

// handedBack reports whether a failed request to the model says nothing about the case, so that the case goes back to
// the queue: the endpoint gave no answer, is busy or failing, or refused the key or the model, which the ModelConfig's
// probe reports, and the agent waits for its Ready. A refusal of any other client error is the request's own.
func handedBack(err error) bool {
	var refused *llm.StatusError
	if !errors.As(err, &refused) || errors.Is(err, llm.ErrUnreachable) || errors.Is(err, llm.ErrUnauthorized) {
		return true
	}
	switch refused.Code {
	case http.StatusNotFound, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	}
	return refused.Code < http.StatusBadRequest || refused.Code >= http.StatusInternalServerError
}

// prepare reads what the case runs with. Its errors say why the case can't start now.
func (a *Agent) prepare(ctx context.Context, c cases.Case, r cases.Request, known *triagev1alpha1.Assessment) (
	*work, error) {
	cfg, err := settings.Load(ctx, a.Client)
	if err != nil {
		return nil, err
	}
	if cfg.AgentState != configv1alpha1.AgentStateEnabled {
		return nil, errors.New("the agent is switched off")
	}
	playbook, sheet, err := a.caseFile(ctx, c, r, known)
	if err != nil {
		return nil, err
	}
	agent := playbook.Spec.Agent
	profileName := profile.DefaultName
	if agent.ProfileRef != nil {
		profileName = agent.ProfileRef.Name
	}
	eff, err := profile.Resolve(ctx, a.Client, a.OperatorNamespace, profileName)
	if err != nil {
		return nil, err
	}
	guidance, err := a.investigationGuidance(ctx, r.Investigation, r.InvestigationUID)
	if err != nil {
		return nil, err
	}
	if !modelReady(&eff.Model) {
		return nil, fmt.Errorf("the ModelConfig %q is not Ready", eff.Model.Name)
	}
	config, err := a.ClientConfig(ctx, eff.Model.Name)
	if err != nil {
		return nil, err
	}
	data, err := cases.EvidenceData(ctx, a.Evidence, sheet, agent.Evidence)
	if err != nil {
		return nil, err
	}
	sbom, err := a.sbomOf(ctx, sheet)
	if err != nil {
		return nil, err
	}
	file, err := casefile.Build(c, data, Packages(c, sbom), 4*eff.Limits.CaseFileMaxTokens)
	if err != nil {
		return nil, err
	}
	vc := ValidatorCase(c, sbom)
	vc.Guidance = guidance
	return &work{c: c, name: cases.Name(c.VulnerabilityID, c.ManifestDigest), playbook: playbook.Name,
		cluster: cfg.ClusterName, profile: eff, guidance: guidance, config: config, file: file,
		inputHash: cases.InputHash(c.Findings, cases.HashesOf(sheet, data)), validator: vc}, nil
}

// defaultGuidanceTimeout bounds the read of an investigation's guidance: a cache that can't list Investigations, as
// without the RBAC to, would block it for good.
const defaultGuidanceTimeout = 30 * time.Second

// investigationGuidance returns the guidance of the investigation of the uid, from the cache: none when the case is
// charged to no investigation, or to one that the API server says is gone, as an object of another uid is: it is
// another investigation, with guidance of its own. A cache may not show an investigation created just now.
func (a *Agent) investigationGuidance(ctx context.Context, investigation types.NamespacedName, uid types.UID) (string, error) {
	if investigation.Name == "" {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(a.GuidanceTimeout, defaultGuidanceTimeout))
	defer cancel()
	var inv triagev1alpha1.Investigation
	err := a.Client.Get(ctx, investigation, &inv)
	if apierrors.IsNotFound(err) || err == nil && inv.UID != uid {
		inv = triagev1alpha1.Investigation{}
		err = a.APIReader.Get(ctx, investigation, &inv)
	}
	if err != nil || inv.UID != uid {
		return "", client.IgnoreNotFound(err)
	}
	return ptr.Deref(inv.Spec.Agent.Guidance, ""), nil
}

// caseFile returns the playbook whose case file the case gets, and its sheet of the manifest: the Assessment's
// case-file playbook, or, when that is gone, has lost its agent section or has no sheet of the manifest, the first
// playbook of the request or of the investigations that selected the case that can serve it.
func (a *Agent) caseFile(ctx context.Context, c cases.Case, r cases.Request, known *triagev1alpha1.Assessment) (
	*configv1alpha1.Playbook, *inventoryv1alpha1.ImageVerdicts, error) {
	candidates := append([]string{ptr.Deref(known.Status.CaseFilePlaybook, r.Playbook), r.Playbook},
		known.Status.Playbooks...)
	for _, name := range slices.Compact(candidates) {
		var playbook configv1alpha1.Playbook
		if err := a.Client.Get(ctx, client.ObjectKey{Name: name}, &playbook); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, nil, err
		}
		if playbook.Spec.Agent == nil {
			continue
		}
		sheet, err := a.Verdicts.Get(ctx, c.ManifestDigest, name)
		if err != nil {
			return nil, nil, err
		}
		if sheet != nil {
			return &playbook, sheet, nil
		}
	}
	return nil, nil, fmt.Errorf("no playbook of the case, %s, can give its case file", strings.Join(candidates, ", "))
}

// sbomOf returns the SBOM that the sheet rests on, from which the validator learns each package's purl and release,
// as describe reads them, or nil when it rests on none.
func (a *Agent) sbomOf(ctx context.Context, sheet *inventoryv1alpha1.ImageVerdicts) (*sdkevidence.SBOM, error) {
	for _, e := range sheet.Status.Evidence {
		if e.Type != sdkevidence.TypeSBOM || e.Version == nil {
			continue
		}
		record, err := a.Evidence.Get(ctx, evidence.Key{Subject: subjects.Manifest(sheet.Spec.ManifestDigest),
			Type: e.Type, Source: e.Source})
		if err != nil || record == nil {
			return nil, err
		}
		var sbom sdkevidence.SBOM
		if err := json.Unmarshal(record.Event.Data(), &sbom); err != nil {
			return nil, fmt.Errorf("read the SBOM of the manifest: %w", err)
		}
		return &sbom, nil
	}
	return nil, nil
}

// packageOf returns the purl of the package as the SBOM has it, and the release that describe reads for it: the purl's
// distro qualifier, else the SBOM's distribution for an OS package. Both are empty where there is no SBOM.
func packageOf(p inventoryv1alpha1.PackageReference, sbom *sdkevidence.SBOM) (purl, distro string) {
	if sbom == nil {
		return "", ""
	}
	if i := slices.IndexFunc(sbom.Packages, func(s sdkevidence.SBOMPackage) bool { return s.ID == p.ID }); i >= 0 {
		purl = sbom.Packages[i].PURL
	}
	distro = validator.PURLDistro(purl)
	if distro == "" && sbom.Distro != nil && slices.Contains(osPackageTypes, p.Type) {
		distro = sbom.Distro.ID + "-" + sbom.Distro.Version
	}
	return purl, distro
}

// Packages returns the purl and distribution of each finding's package, keyed by the package's ID, for the case file.
func Packages(c cases.Case, sbom *sdkevidence.SBOM) map[string]casefile.Package {
	packages := map[string]casefile.Package{}
	for _, f := range c.Findings {
		purl, distro := packageOf(f.Package, sbom)
		packages[f.Package.ID] = casefile.Package{PURL: purl, Distro: distro}
	}
	return packages
}

// ValidatorCase returns what the validator knows of the case: its vulnerability, the aliases and the agent holds that
// its findings name, and each package as the SBOM has it, with its purl and the release that describe reads for it.
func ValidatorCase(c cases.Case, sbom *sdkevidence.SBOM) validator.Case {
	vc := validator.Case{VulnerabilityID: c.VulnerabilityID}
	for _, f := range c.Findings {
		vc.Aliases = append(vc.Aliases, f.Aliases...)
		vc.AgentHolds = append(vc.AgentHolds, f.AgentHolds...)
		p := validator.Package{Name: f.Package.Name, Version: ptr.Deref(f.Package.Version, ""), Type: f.Package.Type}
		p.PURL, p.Distro = packageOf(f.Package, sbom)
		vc.Packages = append(vc.Packages, p)
	}
	slices.Sort(vc.Aliases)
	slices.Sort(vc.AgentHolds)
	vc.Aliases, vc.AgentHolds = slices.Compact(vc.Aliases), slices.Compact(vc.AgentHolds)
	return vc
}

// run judges the case through a session of vexplain's MCP server, connected over the SDK's in-memory transport.
func (a *Agent) run(ctx context.Context, w *work) (runner.Result, core.Outcome) {
	session := core.NewSession(core.Deps{Evidence: a.Evidence, Validator: validator.New(w.validator),
		Forwarder: &core.CollectorTools{Reader: a.Client, Pool: a.Pool, MCP: a.MCP, Context: a.ClusterContext,
			Grants: w.profile.Tools, Subject: subjects.Manifest(w.c.ManifestDigest)}, Cluster: w.cluster},
		w.c, w.file, w.profile)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server, err := session.Server().Connect(ctx, serverTransport, nil)
	if err != nil {
		return runner.Result{Err: err}, session.Outcome()
	}
	defer func() { _ = server.Close() }()
	clientSession, err := mcp.NewClient(&mcp.Implementation{Name: "vexplain-runner", Version: prompt.CoreVersion}, nil).
		Connect(ctx, clientTransport, nil)
	if err != nil {
		return runner.Result{Err: err}, session.Outcome()
	}
	defer func() { _ = clientSession.Close() }()
	model := llm.New(w.config, llm.WithHTTPClient(a.HTTPClient),
		llm.WithObserver(llm.PrometheusObserver(func() string { return w.cluster })))
	res := runner.Builtin{Client: model}.Run(ctx, clientSession, runner.Input{
		Prompt: prompt.System(w.profile.Guidance, w.guidance), CaseFile: w.file.JSON, Limits: w.profile.Limits,
		ContextWindowTokens: int(ptr.Deref(w.profile.Model.Spec.ContextWindowTokens, 0))})
	return res, session.Outcome()
}

// watchSwitch cancels the case when the agent is switched off, and returns whether it did. A failed read of the switch
// leaves the case running.
func (a *Agent) watchSwitch(ctx context.Context, cancel context.CancelFunc) func() bool {
	var off atomic.Bool
	poll := a.SwitchPoll
	if poll == 0 {
		poll = defaultSwitchPoll
	}
	go func() {
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if cfg, err := settings.Load(ctx, a.Client); err == nil && cfg.AgentState != configv1alpha1.AgentStateEnabled {
					off.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	return off.Load
}

// disabled records that a case in progress went back to the queue because the agent was switched off, on the
// OperatorConfig that switched it off.
func (a *Agent) disabled(ctx context.Context, name string) {
	var cfg configv1alpha1.OperatorConfig
	if err := a.Client.Get(ctx, client.ObjectKey{Name: settings.ConfigName}, &cfg); err != nil {
		logf.FromContext(ctx).Error(err, "Could not read the OperatorConfig for the event AgentDisabled")
		return
	}
	a.Recorder.Eventf(&cfg, nil, corev1.EventTypeNormal, triagev1alpha1.ReasonAgentDisabled, eventActionJudge,
		"The agent is switched off: the case %s went back to the queue, with nothing written.", name)
}

// write records the outcome of a case that ended: its ledger, and then the Assessment's status, so that a status never
// names a ledger that isn't there. A ledger that can't be written leaves the status without ledgerRef, and the outcome
// is recorded all the same. The status's update clears the case's queue and claim, and carries the version that it
// read. The writes go ahead when ctx ends meanwhile, within writeTimeout, so that nothing is written half. Neither is
// written once the case's claim names another worker than that of ctx, which judges the case now.
func (a *Agent) write(ctx context.Context, w *work, res runner.Result, o core.Outcome, took time.Duration) error {
	log := logf.FromContext(ctx).WithValues("assessment", w.name)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	claimant := Claimant(ctx)
	claimed := func(obj *triagev1alpha1.Assessment) bool {
		return obj.Status.Claim != nil && obj.Status.Claim.Worker == claimant
	}
	var before triagev1alpha1.Assessment
	if err := a.APIReader.Get(ctx, client.ObjectKey{Name: w.name}, &before); err != nil {
		return client.IgnoreNotFound(err) // a case that went with its Assessment has no outcome to write
	}
	if !claimed(&before) {
		log.Info("Another worker judges the case now; this judgement's outcome is dropped")
		return nil
	}
	var ledgerRef *triagev1alpha1.LedgerReference
	if o.Ledger != nil {
		ledgerRef = &triagev1alpha1.LedgerReference{Name: w.name}
		if err := a.Ledgers.Put(ctx, o.Ledger.Object()); err != nil {
			log.Error(err, "Could not write the ledger of the case; its Assessment names none")
			ledgerRef = nil
		}
	}
	nv := o.NoVerdict
	if o.Verdict == nil && nv == nil {
		nv = noOutcome(res)
	}
	status := triagev1alpha1.AssessmentStatus{
		InputHash: ptr.To(w.inputHash), LedgerRef: ledgerRef,
		Runner: &triagev1alpha1.AssessmentRunner{Type: triagev1alpha1.RunnerBuiltin},
		Model: &triagev1alpha1.AssessmentModel{AgentProfile: w.profile.Name, ModelConfig: w.profile.Model.Name,
			Endpoint: ptr.To(w.profile.Model.Spec.Endpoint), Model: w.config.Model, PromptCore: prompt.CoreVersion,
			GuidanceSHA256: w.profile.GuidanceSHA256, GuidanceResourceVersion: nonEmpty(w.profile.GuidanceResourceVersion)},
		Usage: &triagev1alpha1.AssessmentUsage{Steps: ptr.To(int32(res.Steps)),
			PromptTokens: ptr.To(int64(res.Usage.PromptTokens)), CompletionTokens: ptr.To(int64(res.Usage.CompletionTokens)),
			PeakContextTokens: ptr.To(int64(res.PeakContextTokens)), DurationSeconds: ptr.To(int32(took.Seconds()))},
		Validation: validationOf(o),
	}
	ready := metav1.Condition{Status: metav1.ConditionTrue, Reason: triagev1alpha1.ReasonJudged}
	outcome := noVerdictOutcome
	if o.Verdict != nil {
		status.Verdict = assessmentVerdict(o.Verdict)
		outcome = string(status.Verdict.Status)
		if candidate := (&triagev1alpha1.Assessment{ObjectMeta: metav1.ObjectMeta{Name: w.name}, Status: status}); cases.Silences(candidate) {
			status.Verdict.Statement = ptr.To(cases.StatementNameOf(candidate))
		}
	} else {
		status.NoVerdict = &triagev1alpha1.AssessmentNoVerdict{Reason: ptr.To(triagev1alpha1.NoVerdictReason(nv.Reason)),
			Summary: noVerdictSummary(nv)}
	}
	ready.Message = outcomeMessage(&triagev1alpha1.Assessment{Status: status})
	dropped := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var obj triagev1alpha1.Assessment
		if err := a.APIReader.Get(ctx, client.ObjectKey{Name: w.name}, &obj); err != nil {
			return err
		}
		if dropped = !claimed(&obj); dropped {
			return nil
		}
		status.Conditions, status.ObservedGeneration = obj.Status.Conditions, obj.Status.ObservedGeneration
		status.CaseFilePlaybook, status.Playbooks = obj.Status.CaseFilePlaybook, obj.Status.Playbooks
		// The outcome is charged to the investigation that queued the judgement.
		status.InvestigationRef = obj.Status.InvestigationRef
		if obj.Status.Queue != nil && obj.Status.Queue.InvestigationRef != nil {
			status.InvestigationRef = obj.Status.Queue.InvestigationRef
		}
		status.JudgedTime = ptr.To(metav1.Now())
		ready.ObservedGeneration = obj.Generation
		conditions.SetReady(&status.Conditions, ready, conditions.None)
		conditions.Observe(&status.ObservedGeneration, obj.Generation)
		obj.Status = status
		if err := a.Client.Status().Update(ctx, &obj); err != nil {
			return err
		}
		switch {
		case nv == nil:
		case nv.Reason == verdict.ReasonValidatorRejected:
			a.Recorder.Eventf(&obj, nil, corev1.EventTypeWarning, reasonVerdictRejected, eventActionJudge,
				"The validator rejected the agent's verdict twice: %s.", strings.Join(o.Rejections[len(o.Rejections)-1], ", "))
		default:
			a.Recorder.Eventf(&obj, nil, corev1.EventTypeNormal, reasonNoVerdict, eventActionJudge,
				"The agent ended the case without a verdict: %s.", nv.Reason)
		}
		return nil
	})
	if apierrors.IsNotFound(err) {
		return nil // the case went with its Assessment
	}
	if err != nil {
		return err
	}
	if dropped {
		log.Info("Another worker judges the case now; this judgement's outcome is dropped")
		return nil
	}
	metrics.AgentCasesTotal.WithLabelValues(w.cluster, outcome).Inc()
	metrics.AgentCaseDurationSeconds.WithLabelValues(w.cluster).Observe(took.Seconds())
	if nv != nil {
		metrics.AgentNoVerdictsTotal.WithLabelValues(w.cluster, nv.Reason).Inc()
	}
	for _, checks := range o.Rejections {
		for _, check := range checks {
			metrics.AgentRejectionsTotal.WithLabelValues(w.cluster, check).Inc()
		}
	}
	return nil
}

// noOutcome is the no-verdict of a case that ended without an outcome of its own: at a limit whose final call failed,
// or at a request that the endpoint refused as such.
func noOutcome(res runner.Result) *verdict.NoVerdict {
	if res.Limit != "" {
		return &verdict.NoVerdict{Reason: res.Limit, Why: fmt.Sprintf("The case reached its limit %s, and the call "+
			"for its summary failed, so it has none.", limitFields[res.Limit])}
	}
	return &verdict.NoVerdict{Reason: verdict.ReasonModelError, Why: fmt.Sprintf("The model's endpoint refused a "+
		"request of the case: %v.", res.Err)}
}

// validationOf returns what the validator made of the case's verdicts, or nil when the agent submitted none.
func validationOf(o core.Outcome) *triagev1alpha1.AssessmentValidation {
	rejected := int32(len(o.Rejections))
	switch {
	case o.Verdict != nil:
		return &triagev1alpha1.AssessmentValidation{Result: triagev1alpha1.ValidationPassed, Repairs: ptr.To(rejected)}
	case rejected > 0:
		return &triagev1alpha1.AssessmentValidation{Result: triagev1alpha1.ValidationRejected,
			Repairs: ptr.To(rejected - 1)}
	}
	return nil
}

// assessmentVerdict returns the verdict as an Assessment holds it, within its bounds.
func assessmentVerdict(v *verdict.Verdict) *triagev1alpha1.AssessmentVerdict {
	out := &triagev1alpha1.AssessmentVerdict{Status: triagev1alpha1.VEXStatus(v.Status),
		Summary: text.CutChars(v.Summary, maxSummaryChars)}
	if v.Justification != "" {
		out.Justification = ptr.To(triagev1alpha1.VEXJustification(v.Justification))
	}
	if v.Step != "" {
		out.NextStep = ptr.To(text.CutChars(v.Step, maxStepChars))
	}
	for _, c := range v.Claims[:min(len(v.Claims), maxClaims)] {
		out.Claims = append(out.Claims, triagev1alpha1.AssessmentClaim{Text: text.CutChars(c.Text, maxClaimChars),
			Evidence: slices.Clone(c.Evidence[:min(len(c.Evidence), maxClaimIDs)])})
	}
	return out
}

// noVerdictSummary returns the summary of a no-verdict: why, what the agent established, and what would settle the case. A
// verdict that the validator rejected is the agent's proposal, never what was established: its summary says what the
// agent proposed, and then why the validator rejected it.
func noVerdictSummary(nv *verdict.NoVerdict) string {
	var s string
	switch {
	case nv.Reason == verdict.ReasonValidatorRejected:
		s = nv.Established + "\n\n" + strings.TrimSpace(nv.Why) + "\n\nWould settle: " + nv.WouldSettle
	case nv.Established == "":
		s = nv.Why
	default:
		s = nv.Why + "\n\nEstablished: " + nv.Established + "\n\nWould settle: " + nv.WouldSettle
	}
	return text.CutChars(s, maxSummaryChars)
}

// nonEmpty returns nil for an empty string, which an optional field leaves out.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// setReady sets the Ready condition of the case's Assessment, with the progress that goes with it, and its case-file
// playbook unless that is empty. It reads past the cache: a cache that still shows the condition that it sets would
// keep it from writing.
func (a *Agent) setReady(ctx context.Context, name string, ready metav1.Condition, progress conditions.Progress,
	caseFilePlaybook string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var obj triagev1alpha1.Assessment
		if err := a.APIReader.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
			return err
		}
		ready.ObservedGeneration = obj.Generation
		changed := conditions.SetReady(&obj.Status.Conditions, ready, progress)
		if caseFilePlaybook != "" && ptr.Deref(obj.Status.CaseFilePlaybook, "") != caseFilePlaybook {
			obj.Status.CaseFilePlaybook, changed = ptr.To(caseFilePlaybook), true
		}
		if !changed {
			return nil
		}
		conditions.Observe(&obj.Status.ObservedGeneration, obj.Generation)
		return a.Client.Status().Update(ctx, &obj)
	})
}
