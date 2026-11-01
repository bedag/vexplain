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
	"errors"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// Janitor deletes the evidence about the platform manifests that no digest refers to any more, with
// their sheets. It is a manager.Runnable: at once and then every Interval, it lists the subjects of
// the evidence, and asks the inventory for the digests whose facts name each manifest. It deletes
// the evidence about a manifest that none names, of every type and source, and its sheet, once three
// things hold:
//   - each round for at least Grace has found the manifest unreferenced
//   - its newest evidence was seen more than Grace ago
//   - no digest names the manifest when the janitor looks once more, just before the delete
//
// A spoke stores the evidence of a scan before the facts that refer to it, so evidence is
// unreferenced for a moment after every scan, and a scan by another scanner image stores a
// manifest's evidence anew. These checks keep the janitor from deleting such evidence. Evidence about
// anything but a manifest is left alone.
//
// The janitor remembers in memory since when each manifest is unreferenced. A restart starts every
// grace again, which errs towards keeping the evidence.
//
// The sheet goes first, then the evidence: while the sheet can't be deleted, the evidence stays, so
// that the next round tries again. A match that was under way can put the sheet back after the
// delete. The verdicts controller then deletes it again, when it sees the evidence gone.
type Janitor struct {
	// Store finds the digests whose facts name a manifest.
	Store inventory.Store
	// Evidence keeps the evidence about the manifests, and Verdicts their sheets.
	Evidence evidence.Store
	Verdicts inventory.VerdictsStore
	// Interval is the time from the end of one round to the start of the next. It must be positive.
	Interval time.Duration
	// Grace is how long a manifest must be unreferenced, and its evidence stored, before both go. It
	// must be positive.
	Grace time.Duration
	// Clock tells the time. Nil means the real clock.
	Clock clock.PassiveClock

	// unreferencedSince holds, for each manifest that no digest referred to at the last round, the
	// time of the round that first found it so. Only the goroutine of Start uses it.
	unreferencedSince map[string]time.Time
}

// Start runs a round at once, and then every Interval, until ctx is done.
func (j *Janitor) Start(ctx context.Context) error {
	if j.Interval <= 0 || j.Grace <= 0 {
		return errors.New("the janitor of the evidence needs a positive interval and a positive grace")
	}
	wait.UntilWithContext(ctx, j.sweep, j.Interval)
	return nil
}

// sweep runs one round: it notes the manifests that no digest refers to, and deletes the evidence
// and the sheets of those that have been unreferenced for the whole grace.
func (j *Janitor) sweep(ctx context.Context) {
	log := logf.FromContext(ctx).WithName("janitor")
	manifests, err := manifestsWithEvidence(ctx, j.Evidence)
	if err != nil {
		log.Error(err, "Could not list the evidence; the next round tries again")
		return
	}
	if j.unreferencedSince == nil {
		j.unreferencedSince = map[string]time.Time{}
	}
	now := j.now()
	listed := make(map[string]bool, len(manifests))
	for _, manifest := range manifests {
		listed[manifest] = true
		referenced, err := j.referenced(ctx, manifest)
		if err != nil {
			log.Error(err, "Could not find the digests that refer to a manifest; the next round tries again",
				"manifest", manifest)
			continue
		}
		if referenced {
			delete(j.unreferencedSince, manifest)
			continue
		}
		since, known := j.unreferencedSince[manifest]
		if !known {
			since = now
			j.unreferencedSince[manifest] = since
		}
		if now.Sub(since) < j.Grace {
			continue
		}
		if err := j.remove(ctx, manifest, now); err != nil {
			log.Error(err, "Could not delete the evidence of a manifest that no digest refers to; the next round tries again",
				"manifest", manifest)
		}
	}
	// Evidence that is gone is forgotten: should it come back, it is unreferenced from then on.
	for manifest := range j.unreferencedSince {
		if !listed[manifest] {
			delete(j.unreferencedSince, manifest)
		}
	}
}

// remove deletes the sheet and then the evidence of manifest, which no digest has referred to for
// the whole grace, unless its newest evidence was seen within the grace, or a digest refers to it now.
func (j *Janitor) remove(ctx context.Context, manifest string, now time.Time) error {
	subject := subjects.Manifest(manifest)
	records, err := j.Evidence.ListBySubject(ctx, subject)
	if err != nil {
		// Evidence that can't be read may come from a newer operator. It says nothing of when it was
		// seen, so it stays.
		return err
	}
	if len(records) == 0 {
		delete(j.unreferencedSince, manifest)
		return nil
	}
	// A scan stores its evidence as soon as it has finished, so the time of the scan is when the
	// evidence was stored, to a few seconds.
	if now.Sub(newestTime(records)) < j.Grace {
		return nil
	}
	referenced, err := j.referenced(ctx, manifest)
	if err != nil {
		return err
	}
	if referenced {
		delete(j.unreferencedSince, manifest)
		return nil
	}
	if err := j.Verdicts.Delete(ctx, manifest); err != nil {
		return err
	}
	if err := j.Evidence.DeleteSubject(ctx, subject); err != nil {
		return err
	}
	delete(j.unreferencedSince, manifest)
	logf.FromContext(ctx).WithName("janitor").Info("Deleted the evidence and the sheet of a manifest that no digest refers to",
		"manifest", manifest)
	return nil
}

// newestTime returns the latest time of the events of records.
func newestTime(records []evidence.Record) time.Time {
	var newest time.Time
	for _, record := range records {
		if at := record.Event.Time(); at.After(newest) {
			newest = at
		}
	}
	return newest
}

// referenced reports whether the facts of a digest name manifest.
func (j *Janitor) referenced(ctx context.Context, manifest string) (bool, error) {
	digests, err := j.Store.ManifestReferences(ctx, manifest)
	return len(digests) > 0, err
}

// now returns the time of the janitor's clock.
func (j *Janitor) now() time.Time {
	if j.Clock == nil {
		return time.Now()
	}
	return j.Clock.Now()
}
