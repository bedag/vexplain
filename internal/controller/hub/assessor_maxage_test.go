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

package hub_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// limitAge makes the Collector of the name override the maxAge of the types that the scanner produces with limit.
func (f *assessorFixture) limitAge(t *testing.T, name string, limit time.Duration) {
	t.Helper()
	var c configv1alpha1.Collector
	require.NoError(t, f.client.Get(t.Context(), client.ObjectKey{Name: name}, &c))
	for _, eventType := range []string{sdkevidence.TypeSBOM, imagecontents.Type} {
		c.Spec.Produces = append(c.Spec.Produces,
			configv1alpha1.ProducedTypeOverride{Type: eventType, MaxAgeSeconds: int64(limit.Seconds())})
	}
	require.NoError(t, f.client.Update(t.Context(), &c))
}

// Evidence that is older than the maxAge of its type is missing for the rules, and the sheet doesn't claim it.
func TestEvidenceOlderThanItsMaxAgeIsMissingForTheRules(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, manifest := digestOf(1), digestOf(101)
	f.scanned(t, digest, manifest, evidenceOf(manifest))
	f.limitAge(t, scanner, time.Hour)

	f.clock.SetTime(t0.Add(30 * time.Minute))
	f.assess(t, manifest)
	require.Equal(t, f.restedOn(t, manifest), f.statusOf(t, manifest).Evidence, "within its maxAge, the evidence is read")
	require.NotEqual(t, missingEvidence, f.statusOf(t, manifest).Evidence)

	f.clock.SetTime(t0.Add(2 * time.Hour))
	f.assess(t, manifest)
	require.Equal(t, missingEvidence, f.statusOf(t, manifest).Evidence, "past its maxAge, the evidence is missing")
}

// The assessor asks the producer again for evidence that is past its maxAge, and for nothing while it is within it.
func TestTheAssessorAsksAgainForEvidenceOlderThanItsMaxAge(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest := digestOf(1)
	observe(t, f.store, digest, localCluster, repository)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, digestOf(101)))
	f.storeScans(t, scannerVersion, digestOf(101))
	f.limitAge(t, scanner, time.Hour)

	f.clock.SetTime(t0.Add(30 * time.Minute))
	_, err := f.request(t, digest)
	require.NoError(t, err)
	require.Empty(t, f.asked())

	f.clock.SetTime(t0.Add(2 * time.Hour))
	_, err = f.request(t, digest)
	require.NoError(t, err)
	require.Equal(t, []tasks.Request{
		requestOf(sdkevidence.TypeSBOM, digest, []string{repository}, scanner),
		requestOf(imagecontents.Type, digest, []string{repository}, scanner),
	}, f.asked())
}
