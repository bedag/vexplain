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

// Package cases finds the cases of a playbook that an investigation selects, and what the hub knows of each without the
// agent: where its subject runs, whom to contact, and how urgent it is (decisions 0051 and 0052). A case is one
// vulnerability in one subject: for images, one vulnerability in one platform manifest, with every finding of it there.
//
// It also names a case, orders cases by the tiers of urgency, and hashes what a verdict on a case rests on. It is hub
// code: it reads the sheets and the inventory through their stores, and no spoke.
package cases

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/types"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/rules/engine"
)

// Case is one vulnerability in one platform manifest, with every finding of it in the playbook's sheet.
type Case struct {
	// ManifestDigest is the digest of the platform manifest, and VulnerabilityID the findings' own ID of the
	// vulnerability, which may be an alias of the one that an investigation names.
	ManifestDigest, VulnerabilityID string
	// Findings are the findings of the vulnerability in the manifest, one for each package, sorted by package ID.
	Findings []inventoryv1alpha1.Finding
	Subject  Subject
	Impact   Impact
}

// Subject is what the hub knows of a case's platform manifest: its digest, the repositories it was pulled from,
// sorted, and its platform, which is empty where no facts name it.
type Subject struct {
	ManifestDigest string
	Repositories   []string
	Platform       string
}

// Impact is where a case's subject runs, from the hub's inventory, and how urgent the case is there.
type Impact struct {
	// Clusters, Namespaces and Resources count the clusters, namespaces and workloads that run the subject, as the
	// inventory counts them. A workload that runs it under two reported digests counts twice.
	Clusters, Namespaces, Resources int32
	// UrgentResources counts the workloads for which the case is Immediate or OutOfCycle, by each one's exposure.
	UrgentResources int32
	// HighestExposure is the highest exposure of the workloads, Open before Unknown, Controlled and Small, and empty
	// when no workload is known to run the subject.
	HighestExposure configv1alpha1.SSVCExposure
	// HighestUrgency is the case's most urgent outcome over the exposures of the workloads, and empty when none is
	// known.
	HighestUrgency configv1alpha1.SSVCOutcome
	// WorkloadsByExposure counts the workloads that run the subject by their exposure. With the exposure rules, it
	// counts once each workload that presence names, and as Unknown the rest of what the inventory counts.
	WorkloadsByExposure map[configv1alpha1.SSVCExposure]int32
	// Exposure groups the workloads by their exposure and the rules that decided it, in the order of ExposureGroup. It
	// is empty without the exposure rules.
	Exposure []ExposureGroup
	// Owners are the first 5 namespaces that run the subject, by cluster and name, with their owner values.
	Owners []NamespaceOwners
	// ClusterNames are the names of the clusters that run the subject, sorted.
	ClusterNames []string
}

// The caps of the groups of a case's workloads by exposure, which its Assessment and its case file hold.
const (
	// MaxExposureGroups is how many groups a case keeps: the first, the most exposed.
	MaxExposureGroups = 16
	// MaxGroupNames is how many rules, and how many missing inputs, a group names.
	MaxGroupNames = 8
	// MaxGroupFirst is how many workloads a group names by their subject.
	MaxGroupFirst = 5
)

// ExposureGroup is a group of the workloads that run a case's subject: those of one exposure that the same rules
// decided, or that are Unknown for the same reasons. A case orders its groups by exposure, Open first, then Unknown,
// Controlled and Small, then by their rules, and then by their missing inputs.
type ExposureGroup struct {
	Exposure configv1alpha1.SSVCExposure
	// Rules are the rules that concluded the exposure, or, of an Unknown group, those that couldn't be evaluated, and
	// Missing the inputs that an Unknown group's rules lacked: each sorted, at most MaxGroupNames.
	Rules, Missing []string
	// Workloads counts the workloads of the group.
	Workloads int32
	// First are the subjects of the group's first MaxGroupFirst workloads, sorted. A workload that the inventory counts
	// and that presence doesn't name has none.
	First []string
}

// WorkloadExposure is the exposure of a workload, by its subject, as a playbook's exposure rules decide it.
type WorkloadExposure struct {
	Subject string
	engine.WorkloadExposure
}

// Place is where the inventory says that a manifest runs: in a cluster, under one of the digests that its nodes report.
type Place struct{ Digest, Cluster string }

// Exposures decides, with a playbook's exposure rules, the exposure of the workloads that run a manifest.
type Exposures interface {
	// Of returns the workloads that presence names in each place where the manifest runs, each with its exposure. A
	// place of which no presence is known, as in a cluster whose presence hasn't reached the hub, has no entry. It
	// returns an error when what the rules need can't be read.
	Of(ctx context.Context, playbook, manifest string, places []Place) (map[Place][]WorkloadExposure, error)
}

// NamespaceOwners is a namespace that runs a subject, and the owner values that owner attribution copied from it.
type NamespaceOwners struct {
	Cluster, Namespace string
	Owner              []inventoryv1alpha1.OwnerValue
}

// Skipped is a case that the investigation's scope holds and that a condition doesn't select, and why.
type Skipped struct {
	ManifestDigest, VulnerabilityID, Reason string
	// Failed says that a condition failed on a finding of the case, as Reason says, rather than not holding.
	Failed bool
}

// Request is an investigation's request that the agent judge a case.
type Request struct {
	// Investigation names the investigation, InvestigationUID is its metadata.uid, Playbook is the playbook whose case
	// file goes with the case, and InvestigationPlaybook the investigation's own, whose exposure rules decided where
	// the case runs.
	Investigation         types.NamespacedName
	InvestigationUID      types.UID
	Playbook              string
	InvestigationPlaybook string
	// Trigger is the investigation's trigger: a case that an investigation that runs Once wants, which a person asked
	// for, goes first within its tier.
	Trigger triagev1alpha1.InvestigationTriggerType
	// JudgedAfter is the oldest outcome that the investigation reuses: the oldest that verdictMaxAgeSeconds allows, or
	// a second past a fresh verdict that its judgePolicy declines. An outcome on the case's current inputs that was
	// recorded before it doesn't count. Zero takes any.
	JudgedAfter time.Time
}

// Queue is the hub's one queue of cases for the agent. It judges a case that two investigations want once.
type Queue interface {
	// Add queues the case for the request, unless it is queued or in progress already, whoever queued it. It reports
	// whether it queued the case.
	Add(c Case, r Request) bool
	// Pending returns how many of the cases of the investigation, of that uid, wait in the queue, and how many the
	// agent judges now.
	Pending(investigation types.NamespacedName, uid types.UID) (queued, inProgress int)
	// Keep says which cases the investigation still wants judged, by name: the queue forgets that it wants any other,
	// and drops a waiting case that no investigation wants. A case in progress finishes.
	Keep(investigation types.NamespacedName, names []string)
}
