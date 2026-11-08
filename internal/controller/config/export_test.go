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

package config

import (
	"context"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// HealthGrace is how long after a start of the operator, or after a collector's certificate was issued again, a
// failing health check leaves the collector NoData.
const HealthGrace = healthGrace

// EnsureDefaultRuntimeConfig is what the deployer runs at its start: it creates the runtime config named default,
// empty, when it is missing.
var EnsureDefaultRuntimeConfig = ensureDefaultRuntimeConfig

// CapabilitiesOf returns what the deployer records of a collector's answer to GetCapabilities, or why the answer is
// malformed.
func CapabilitiesOf(answer *collectorv1alpha1.GetCapabilitiesResponse) (*configv1alpha1.CollectorCapabilities, error) {
	capabilities, _, err := capabilitiesOf(answer, "vexplain-system")
	return capabilities, err
}

// CheckInfo returns the version of a collector's answer to GetInfo, or the reason and the message of a Ready
// condition that refuses it.
func CheckInfo(answer *collectorv1alpha1.GetInfoResponse) (version, reason, message string) {
	version, refused := checkInfo(answer)
	if refused != nil {
		return "", refused.reason, refused.message
	}
	return version, "", ""
}

// SourcesOf returns what the deployer records of the sources in a collector's answer to GetInfo, or the reason and the
// message of a Ready condition that refuses it.
func SourcesOf(answer *collectorv1alpha1.GetInfoResponse) (sources []configv1alpha1.CollectorSource, reason, message string) {
	sources, refused := sourcesOf(answer)
	if refused != nil {
		return nil, refused.reason, refused.message
	}
	return sources, "", ""
}

// DefaultDeployment returns the Deployment that the deployer wants for the collector of obj when no template shapes
// it: the defaults, with the contract set.
func DefaultDeployment(obj *configv1alpha1.Collector, namespace string) *appsv1.Deployment {
	d := defaultDeployment(obj, namespace)
	setContract(d, obj, namespace)
	return d
}

// WritesSpec says whether the deployer writes the spec of desired over live, the Deployment as the API server holds
// it.
func WritesSpec(desired, live *appsv1.Deployment) bool {
	hash, err := specHash(&desired.Spec)
	if err != nil {
		panic(err)
	}
	return specWanted(desired, hash, live)
}

// RolloutOf says how far the rollout of a collector's Deployment has got: still in progress, or done, and then why
// the collector can't be reached, if it can't.
func RolloutOf(d *appsv1.Deployment) (inProgress bool, failure error) {
	return rolloutOf(d)
}

// CollectorChanged passes the changes of a Collector that the deployer reconciles.
var CollectorChanged = collectorChanged

// RetryLimiter is the rate limiter of the deployer's retries, for a resync of resync.
func RetryLimiter(resync time.Duration) workqueue.TypedRateLimiter[reconcile.Request] {
	return retryLimiter(resync)
}

// Round fires what is due at the time of the scheduler's clock, as each round of its Start does, and returns once it
// has started the fires, which run on.
func (s *Scheduler) Round(ctx context.Context) {
	s.round(ctx)
}

// WaitFires returns once no fire runs.
func (s *Scheduler) WaitFires() {
	s.fires.Wait()
}

// Fire is what the scheduler recorded of the last fire of a schedule: when it fired, and why the fire failed, or ""
// when it succeeded.
type Fire struct {
	Time    time.Time
	Failure string
}

// Fired returns what the scheduler recorded of the fires of the Collector c: the last fire of each schedule, by
// name, and the run-now value that it handled last, or "" for none.
func (s *Scheduler) Fired(c *configv1alpha1.Collector) (map[string]Fire, string) {
	recorded, handled := s.fired(c)
	fires := make(map[string]Fire, len(recorded))
	for name, f := range recorded {
		fires[name] = Fire{Time: f.at, Failure: f.failure}
	}
	return fires, handled
}
