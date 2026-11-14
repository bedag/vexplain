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

package collectorclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"google.golang.org/protobuf/proto"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
)

// Failure says why an operation returned no evidence for its subject. Reason comes from vexplain's open vocabulary,
// such as Unauthorized, NotFound or TooLarge, and Message says more. Both are the collector's text. A failure is about
// one subject: it goes to the facts of that subject, and never counts against the collector's health.
type Failure struct{ Reason, Message string }

// InvokeOption changes how Invoke takes an answer.
type InvokeOption func(*invokeOptions)

type invokeOptions struct{ maxEvents int }

// MaxEvents bounds the events of the answer below the contract's 64, as for an operation that answers with one
// event: an answer with more breaks the contract, and Invoke reads nothing past the first event too many.
func MaxEvents(n int) InvokeOption {
	return func(o *invokeOptions) { o.maxEvents = n }
}

// EventsBound returns how many events an answer may hold under the options: the contract's 64, or fewer, as MaxEvents
// says.
func EventsBound(opts ...InvokeOption) int {
	o := invokeOptions{maxEvents: maxAnswerEvents}
	for _, opt := range opts {
		opt(&o)
	}
	return min(o.maxEvents, maxAnswerEvents)
}

// ErrContract means that a collector's answer breaks the API's contract, as Invoke found: the error says how, in
// fixed texts that repeat nothing of the answer. Asking again gets the same answer from the same collector, so a
// caller records it as a failure, and never takes it for a call that failed on its way.
var ErrContract = errors.New("the answer breaks the API's contract")

// Invoke runs one operation of the collector for one subject, as req says, and returns the collector's answer: the
// events, a failure, or both, the events first.
//
// Each event is valid evidence: Invoke checks it again with evidence.Validate, as the SDK's server checked it before
// it sent it, because a collector needn't be built with the SDK. An answer that breaks the API's contract gives an
// error, ErrContract, and none of the answer: an event that isn't valid evidence, a failure without a reason, a
// second failure, an item after the failure, or an item that the API doesn't know. A call that ends with an error
// before the answer is complete gives that error, and none of the answer either. A caller then never takes part of
// an answer for all of it, as the SDK's server, which sends none of an answer that breaks the contract, never lets it
// either. An error about the answer repeats nothing that the answer holds. The error of a call that failed keeps the
// status that the collector answered with, as with every call of the pool.
//
// An answer is bounded (design 5.9): it holds at most 64 events, or fewer as MaxEvents says, and its messages hold at
// most 128 MiB. Invoke ends the call at the first message past a bound, reads nothing more, and returns ErrContract;
// the log names the collector and the bound, and the metric of contract breaks counts it.
//
// Invoke doesn't check that the events are of the types that the operation produces: the caller knows the
// operation's capabilities, and the pool doesn't.
func (p *Pool) Invoke(ctx context.Context, collector string, req *collectorv1alpha1.InvokeRequest, opts ...InvokeOption) (
	[]cloudevents.Event, *Failure, error) {
	conn, err := p.conn(collector)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	// An answer that breaks the contract ends the call here, without reading the rest.
	defer cancel()
	call, err := collectorv1alpha1.NewEvidenceClient(conn).Invoke(ctx, req)
	if err != nil {
		return nil, nil, callError("Invoke", collector, err)
	}
	answer := answer{maxEvents: min(EventsBound(opts...), p.answerEvents), maxBytes: p.answerBytes}
	for {
		resp, err := call.Recv()
		if errors.Is(err, io.EOF) {
			return answer.events, answer.failure, nil
		}
		if err != nil {
			return nil, nil, callError("Invoke", collector, err)
		}
		if err := answer.add(resp); err != nil {
			var passed boundError
			if errors.As(err, &passed) {
				CountBreak(req.GetContext().GetCluster(), collector, passed.bound)
				logf.FromContext(ctx).Info("The collector passed a bound of what it may send, which breaks the contract of "+
					"its answer: the call ends", "collector", collector, "bound", passed.bound, "problem", passed.Error())
			}
			return nil, nil, fmt.Errorf("collector %s, Invoke: %w: %w", collector, ErrContract, err)
		}
	}
}

// fireTimeout bounds a Fire, as the collector API's contract says: a collector starts the work of a schedule, and
// answers within 10 seconds.
const fireTimeout = 10 * time.Second

// Fire runs one of the collector's schedules now, as req says, and returns when the collector answers. The call ends
// after 10 seconds at the latest, or sooner when ctx ends. The error of a failed call keeps the status that the
// collector answered with, as with every call of the pool.
func (p *Pool) Fire(ctx context.Context, collector string, req *collectorv1alpha1.FireRequest) error {
	conn, err := p.conn(collector)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, fireTimeout)
	defer cancel()
	if _, err := collectorv1alpha1.NewEvidenceClient(conn).Fire(ctx, req); err != nil {
		return callError("Fire", collector, err)
	}
	return nil
}

// answer is what a collector answered to Invoke so far, with how much its messages held, and its bounds.
type answer struct {
	events    []cloudevents.Event
	failure   *Failure
	bytes     int
	maxEvents int
	maxBytes  int
}

// add takes the next item of the answer, or says how it breaks the contract, as a bound that it passes. Its errors
// repeat nothing that the item holds: evidence.Validate's and evidence.FromProto's don't either.
func (a *answer) add(resp *collectorv1alpha1.InvokeResponse) error {
	if a.bytes += proto.Size(resp); a.bytes > a.maxBytes {
		return boundError{bound: BoundAnswerSize, why: fmt.Sprintf("the messages of the answer hold more than %d bytes",
			a.maxBytes)}
	}
	if a.failure != nil {
		return errors.New("an item came after the failure, which comes last")
	}
	switch item := resp.GetItem().(type) {
	case *collectorv1alpha1.InvokeResponse_Event:
		if len(a.events) == a.maxEvents {
			return boundError{bound: BoundAnswerEvents, why: fmt.Sprintf("the answer holds more than %d events", a.maxEvents)}
		}
		e, err := evidence.FromProto(item.Event)
		if err == nil {
			err = evidence.Validate(e)
		}
		if err != nil {
			return fmt.Errorf("event %d is not valid evidence: %w", len(a.events)+1, err)
		}
		a.events = append(a.events, e)
	case *collectorv1alpha1.InvokeResponse_Failure:
		if item.Failure.GetReason() == "" {
			return errors.New("the failure has no reason")
		}
		a.failure = &Failure{Reason: item.Failure.GetReason(), Message: item.Failure.GetMessage()}
	default:
		return errors.New("an item is of a kind that the API doesn't know")
	}
	return nil
}
