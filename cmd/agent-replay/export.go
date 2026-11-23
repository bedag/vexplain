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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/casefile"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/worker"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// The files of a saved case, in a directory of its own.
const (
	caseFile       = "case.json"
	casefileFile   = "casefile.json"
	evidenceFile   = "evidence.json"
	validatorFile  = "validator.json"
	profileFile    = "profile.json"
	callsFile      = "calls.json"
	packagesFile   = "packages.json"
	forwardedMark  = "__"
	filePermission = 0o600
)

// savedProfile is what a case ran with that a replay needs: the limits, and the texts of the guidance after the core
// prompt: the profile's, and its investigation's.
type savedProfile struct {
	Limits   profile.Limits `json:"limits"`
	Guidance string         `json:"guidance"`
	// InvestigationGuidance is the guidance of the investigation that the case is charged to.
	InvestigationGuidance string `json:"investigationGuidance,omitempty"`
}

// recorded is a forwarded tool call of the case, with the output that the model got and how far it counted as evidence.
type recorded struct {
	Tool      string       `json:"tool"`
	Arguments string       `json:"arguments"`
	Trust     ledger.Trust `json:"trust"`
	Output    string       `json:"output"`
}

// export saves the judged case of the Assessment into out/<name>: the case with its evidence, as the agent got it, the
// validator's case, the profile's limits and guidance, the guidance of the investigation that the case is charged to,
// and the forwarded tool calls of its Ledger with their outputs from the evidence store. Core tools aren't recorded,
// since a replay runs them again on the case file. The case's owner values are left out. It only reads from the
// cluster.
//
// shortcut: the profile's limits and guidance, and the investigation's guidance, are those of now, and an output that
// the evidence store cut is recorded cut; re-export a case after changing its profile or its investigation.
func export(ctx context.Context, c client.Client, name, out, operatorNamespace string) error {
	var a triagev1alpha1.Assessment
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &a); err != nil {
		return fmt.Errorf("read the Assessment %q: %w", name, err)
	}
	if a.Spec.Subject.ContainerImage == nil {
		return fmt.Errorf("the Assessment %q has no container image subject", name)
	}
	digest, id := a.Spec.Subject.ContainerImage.Digest, a.Spec.VulnerabilityID

	cfg, err := settings.Load(ctx, c)
	if err != nil {
		return err
	}
	local := func() string { return cfg.ClusterName }
	store, sheets := evidence.NewCRDStore(c, nil, local), inventory.NewCRDVerdictsStore(c, local)
	pb, sheet, err := caseFileOf(ctx, c, sheets, &a)
	if err != nil {
		return err
	}
	selected, _, err := cases.Select(ctx, sheets, inventory.NewCRDStore(c, nil, local),
		cases.Selection{Playbook: pb.Name, Vulnerabilities: []string{id}, Overrides: cfg.Urgency.Overrides})
	if err != nil {
		return err
	}
	i := slices.IndexFunc(selected, func(k cases.Case) bool {
		return k.ManifestDigest == digest && k.VulnerabilityID == id
	})
	if i < 0 {
		return fmt.Errorf("the sheet of the playbook %q holds no finding of %s in %s", pb.Name, id, digest)
	}
	theCase := selected[i]
	theCase.Impact.Owners = nil // owner values are not part of what a replay needs, and stay in the cluster.
	// shortcut: only the hub decides exposure, and a judged case's queue is gone with what it decided, so the export of
	// a judged case counts the workloads by the inventory's exposure; keep runsIn past the judgement if a replay needs it.
	if a.Status.Queue != nil {
		theCase.Impact.LayRunsIn(a.Status.Queue.RunsIn)
	}

	data, err := cases.EvidenceData(ctx, store, sheet, pb.Spec.Agent.Evidence)
	if err != nil {
		return err
	}
	prof, err := profileOf(ctx, c, &a, operatorNamespace)
	if err != nil {
		return err
	}
	if prof.InvestigationGuidance, err = investigationGuidance(ctx, c, &a); err != nil {
		return err
	}
	sbom, err := sbomOf(ctx, store, sheet)
	if err != nil {
		return err
	}
	packages := worker.Packages(theCase, sbom)
	file, err := casefile.Build(theCase, data, packages, 4*prof.Limits.CaseFileMaxTokens)
	if err != nil {
		return err
	}
	calls, err := recordedCalls(ctx, c, store, name)
	if err != nil {
		return err
	}

	dir := filepath.Join(out, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := map[string]any{caseFile: theCase, evidenceFile: data, validatorFile: worker.ValidatorCase(theCase, sbom),
		profileFile: prof, callsFile: calls, casefileFile: json.RawMessage(file.JSON), packagesFile: packages}
	for file, v := range files {
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, file), raw, filePermission); err != nil {
			return err
		}
	}
	return nil
}

// caseFileOf returns the playbook whose case file the case got, and its sheet of the manifest: the Assessment's
// case-file playbook, or the first of its playbooks that has a sheet.
func caseFileOf(ctx context.Context, c client.Reader, sheets inventory.VerdictsStore, a *triagev1alpha1.Assessment) (
	*configv1alpha1.Playbook, *inventoryv1alpha1.ImageVerdicts, error) {
	candidates := slices.Compact(append([]string{ptr.Deref(a.Status.CaseFilePlaybook, "")}, a.Status.Playbooks...))
	for _, name := range candidates {
		if name == "" {
			continue
		}
		var pb configv1alpha1.Playbook
		if err := c.Get(ctx, client.ObjectKey{Name: name}, &pb); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, nil, err
		}
		if pb.Spec.Agent == nil {
			continue
		}
		sheet, err := sheets.Get(ctx, a.Spec.Subject.ContainerImage.Digest, name)
		if err != nil {
			return nil, nil, err
		}
		if sheet != nil {
			return &pb, sheet, nil
		}
	}
	return nil, nil, fmt.Errorf("no playbook of the Assessment %q can give its case file", a.Name)
}

// profileOf returns the limits and the guidance of the AgentProfile that judged the case, or the defaults of the
// default profile when it recorded none.
func profileOf(ctx context.Context, c client.Reader, a *triagev1alpha1.Assessment, namespace string) (
	savedProfile, error) {
	name := profile.DefaultName
	if a.Status.Model != nil && a.Status.Model.AgentProfile != "" {
		name = a.Status.Model.AgentProfile
	}
	var p configv1alpha1.AgentProfile
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &p); err != nil {
		return savedProfile{}, fmt.Errorf("read the AgentProfile %q: %w", name, err)
	}
	guidance, _, err := profile.GuidanceOf(ctx, c, namespace, p.Spec.Guidance)
	if err != nil {
		return savedProfile{}, fmt.Errorf("read the guidance of the AgentProfile %q: %w", name, err)
	}
	return savedProfile{Limits: profile.LimitsOf(p.Spec.Limits), Guidance: guidance}, nil
}

// investigationGuidance returns the guidance of the investigation that the Assessment was judged for: none when it
// names none, or one that is gone, as an object of another uid is: it is another investigation.
func investigationGuidance(ctx context.Context, c client.Reader, a *triagev1alpha1.Assessment) (string, error) {
	to := a.Status.InvestigationRef
	if to == nil {
		return "", nil
	}
	var inv triagev1alpha1.Investigation
	if err := c.Get(ctx, client.ObjectKey{Namespace: to.Namespace, Name: to.Name}, &inv); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("read the Investigation %s/%s: %w", to.Namespace, to.Name, err)
	}
	if inv.UID != to.UID {
		return "", nil
	}
	return ptr.Deref(inv.Spec.Agent.Guidance, ""), nil
}

// sbomOf returns the SBOM that the sheet rests on, or nil when it rests on none.
func sbomOf(ctx context.Context, store evidence.Store, sheet *inventoryv1alpha1.ImageVerdicts) (
	*sdkevidence.SBOM, error) {
	for _, e := range sheet.Status.Evidence {
		if e.Type != sdkevidence.TypeSBOM || e.Version == nil {
			continue
		}
		record, err := store.Get(ctx, evidence.Key{Subject: subjects.Manifest(sheet.Spec.ManifestDigest), Type: e.Type,
			Source: e.Source})
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

// recordedCalls returns the forwarded tool calls of the case's Ledger, in order, with their outputs.
func recordedCalls(ctx context.Context, c client.Reader, store evidence.Store, name string) ([]recorded, error) {
	var l inventoryv1alpha1.Ledger
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &l); err != nil {
		return nil, fmt.Errorf("read the Ledger %q: %w", name, err)
	}
	calls := []recorded{}
	for _, e := range l.Spec.Entries {
		if !strings.Contains(e.Tool, forwardedMark) {
			continue
		}
		ref := e.OutputRef
		record, err := store.Get(ctx, evidence.Key{Subject: ref.Subject, Type: ref.Type, Source: ref.Source})
		if err != nil {
			return nil, err
		}
		if record == nil {
			return nil, fmt.Errorf("the output of %s (%s) is gone from the evidence store", e.ID, e.Tool)
		}
		var output sdkevidence.ToolOutput
		if err := json.Unmarshal(record.Event.Data(), &output); err != nil {
			return nil, fmt.Errorf("read the output of %s: %w", e.ID, err)
		}
		calls = append(calls, recorded{Tool: e.Tool, Arguments: ptr.Deref(e.Arguments, ""), Trust: e.Trust,
			Output: output.Output})
	}
	return calls, nil
}
