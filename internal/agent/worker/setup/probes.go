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

package setup

import (
	"cmp"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

// The timings of the election of the replica that probes the models: those of controller-runtime's leader election.
const (
	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second
)

// The workers elect the replica that probes with a Lease of the operator's namespace, agent.vexplain.bedag.ch, which
// cmd/agent names. They create it, and read and renew it by its name alone, since the manager's Lease is in that
// namespace too; a create can't be narrowed by name. They record its changes as events there.
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=create,namespace=vexplain-system
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;update,resourceNames=agent.vexplain.bedag.ch,namespace=vexplain-system
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch,namespace=vexplain-system

// probes runs the ModelConfig controller. With a lock, it runs it only while this replica holds the lock's Lease, and
// campaigns again once it lost it: losing the Lease stops the probes and never the worker, whose claim loop and
// judgements need no leader. Without a lock, it runs the controller for as long as it runs. A controller can't start
// twice, so each term builds its own.
type probes struct {
	build func() (controller.Controller, error)
	lock  resourcelock.Interface
	log   logr.Logger
	// leaseDuration, renewDeadline and retryPeriod time the election. Zero means the constants above.
	leaseDuration, renewDeadline, retryPeriod time.Duration
	// term is held while a term's controller runs, so that the next term's starts once it has stopped.
	term sync.Mutex
}

// NeedLeaderElection says that every replica runs probes: it holds an election of its own.
func (*probes) NeedLeaderElection() bool { return false }

// Start runs the probes until ctx ends, and returns once the last term's controller has stopped. A controller that
// fails while this replica leads fails the worker, as a controller of the manager would.
func (p *probes) Start(ctx context.Context) error {
	if p.lock == nil {
		return p.run(ctx)
	}
	ctx, fail := context.WithCancelCause(ctx)
	defer fail(nil)
	for ctx.Err() == nil {
		elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{Lock: p.lock,
			LeaseDuration: cmp.Or(p.leaseDuration, leaseDuration), RenewDeadline: cmp.Or(p.renewDeadline, renewDeadline),
			RetryPeriod: cmp.Or(p.retryPeriod, retryPeriod),
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(leading context.Context) {
					p.term.Lock()
					defer p.term.Unlock()
					if leading.Err() != nil {
						return
					}
					p.log.Info("This worker leads, and probes the models")
					if err := p.run(leading); err != nil && leading.Err() == nil {
						fail(err)
						return
					}
					p.log.Info("This worker leads no more, and stops probing the models")
				},
				OnStoppedLeading: func() {},
			}})
		if err != nil {
			return err
		}
		elector.Run(ctx)
	}
	p.term.Lock()
	defer p.term.Unlock()
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// run builds a controller and runs it until ctx ends.
func (p *probes) run(ctx context.Context) error {
	c, err := p.build()
	if err != nil {
		return err
	}
	return c.Start(ctx)
}
