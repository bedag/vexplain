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

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/bedag/vexplain/internal/matchapi"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// Findings is where the assessor gets the findings of a subject: the findings collector that a playbook
// names. The findings aren't stored as evidence: the sheet holds what the rules made of them.
type Findings interface {
	// Find matches one manifest's evidence. The event is of a type the findings collector consumes.
	// An error means that there is no answer, and never that there are no findings.
	Find(ctx context.Context, collector string, input cloudevents.Event) (sdkevidence.Findings, error)
	// Changed delivers the subjects to match again; an empty list means every subject. A subject comes
	// as a request named by it, such as manifest/ and its digest, and every subject as one request with
	// an empty name.
	Changed() source.Source
	// Consumes returns the types of evidence that the findings collector of the name consumes, of which
	// Find takes one. It is empty for a collector that the Findings doesn't serve.
	Consumes(collector string) []string
}

// Matcher matches the packages of an SBOM against a vulnerability database: phase 2a's HTTP matcher
// (decision 0022). *matchapi.Client implements it.
type Matcher interface {
	// Match returns the matches of the packages of the SBOM. An error means that there is no answer,
	// and never that there are no matches.
	Match(ctx context.Context, sbom json.RawMessage) (matchapi.MatchResponse, error)
	// Database returns the version of the database that the matcher uses.
	Database(ctx context.Context) (matchapi.Database, error)
}

var _ Matcher = (*matchapi.Client)(nil)

// MatcherFindings is phase 2a's HTTP matcher as the findings collector of a playbook, until the matcher
// runs from its own package. It stands for the Collector named Collector, and consumes the evidence of
// type Consumed, the scanner's: it matches the SBOM in the evidence's data, which is where the
// scanner's evidence holds it. It is a manager.Runnable: it reads the version of the matcher's
// database at once and then every Interval, as phase 2a's poller did. The first read that succeeds says
// that every subject changed, since a manifest matched before it may have been matched against
// another database, and so does every change of the version. A read that fails keeps the version that
// it read last.
type MatcherFindings struct {
	// Matcher is the matcher's client.
	Matcher Matcher
	// Collector is the name of the Collector that the matcher stands for, as a playbook names it.
	Collector string
	// Consumed is the type of the evidence whose SBOM the matcher matches.
	Consumed string
	// Interval is the time from the end of one read to the start of the next. It must be positive.
	Interval time.Duration

	mu sync.Mutex
	// version is the version of the database at the last read, or "" before the first.
	version string
	// queue is the queue that Changed delivers into, once the assessor has started it.
	queue workqueue.TypedRateLimitingInterface[reconcile.Request]
}

var _ Findings = (*MatcherFindings)(nil)

// errNoSBOM is the error of evidence whose data holds no SBOM to match. Its text is fixed: the data
// comes from an image's scan, which a crafted image can influence.
var errNoSBOM = errors.New("the evidence holds no SBOM to match")

// Find matches the SBOM of the evidence of a manifest. It refuses a collector other than the one that
// it stands for, and evidence of another type than the one that it consumes.
func (f *MatcherFindings) Find(ctx context.Context, collector string, input cloudevents.Event) (sdkevidence.Findings, error) {
	if collector != f.Collector {
		return sdkevidence.Findings{}, fmt.Errorf("the matcher stands for Collector %q, and not for %q", f.Collector, collector)
	}
	if input.Type() != f.Consumed {
		return sdkevidence.Findings{}, fmt.Errorf("the matcher matches evidence of type %s, and not of type %s", f.Consumed, input.Type())
	}
	var data struct {
		SBOM json.RawMessage `json:"sbom"`
	}
	if json.Unmarshal(input.Data(), &data) != nil || len(data.SBOM) == 0 || string(data.SBOM) == "null" {
		return sdkevidence.Findings{}, errNoSBOM
	}
	answer, err := f.Matcher.Match(ctx, data.SBOM)
	if err != nil {
		return sdkevidence.Findings{}, fmt.Errorf("match the packages of %s: %w", input.Subject(), err)
	}
	found := sdkevidence.Findings{Version: answer.DatabaseVersion, Matches: make([]sdkevidence.Match, 0, len(answer.Matches))}
	for _, m := range answer.Matches {
		found.Matches = append(found.Matches, sdkevidence.Match{
			VulnerabilityID: m.VulnerabilityID,
			PackageID:       m.PackageID,
			PackageName:     m.PackageName,
			PackageVersion:  m.PackageVersion,
			PackageType:     m.PackageType,
			Severity:        m.Severity,
			FixState:        m.FixState,
			FixedVersions:   slices.Clone(m.FixedVersions),
			KnownExploited:  m.KnownExploited,
		})
	}
	return found, nil
}

// Consumes returns the type that the matcher consumes, for the Collector that it stands for.
func (f *MatcherFindings) Consumes(collector string) []string {
	if collector != f.Collector {
		return nil
	}
	return []string{f.Consumed}
}

// Changed is the source through which the assessor learns that every subject is to be matched again.
func (f *MatcherFindings) Changed() source.Source {
	return source.Func(func(_ context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.queue = queue
		return nil
	})
}

// Start reads the version of the matcher's database at once, and then every Interval, until ctx is
// done.
func (f *MatcherFindings) Start(ctx context.Context) error {
	if f.Interval <= 0 {
		return errors.New("the findings of the matcher need a positive interval between two reads of its database")
	}
	wait.UntilWithContext(ctx, f.poll, f.Interval)
	return nil
}

// poll reads the version of the matcher's database, and says that every subject changed at the first
// read that succeeds, and whenever the version has changed since the last one. Before the assessor has
// started the source there is no queue: the assessor matches every manifest when it starts.
func (f *MatcherFindings) poll(ctx context.Context) {
	log := logf.FromContext(ctx).WithName("matcher-findings")
	database, err := f.Matcher.Database(ctx)
	if err != nil {
		// The errors of the matcher's client are fixed texts.
		log.Error(err, "Could not read the version of the matcher's database; the next read tries again")
		return
	}
	f.mu.Lock()
	last, queue := f.version, f.queue
	f.version = database.Version
	f.mu.Unlock()
	if database.Version == last {
		return
	}
	if last == "" {
		log.Info("Read the version of the matcher's database: matching again what another version may have matched",
			"version", database.Version)
	} else {
		log.Info("The matcher's database changed: matching every manifest again", "from", last, "to", database.Version)
	}
	if queue != nil {
		queue.Add(reconcile.Request{})
	}
}
