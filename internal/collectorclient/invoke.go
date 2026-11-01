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

	cloudevents "github.com/cloudevents/sdk-go/v2"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
)

// Failure says why an operation returned no evidence for its subject. Reason comes from vexplain's open vocabulary,
// such as Unauthorized, NotFound or TooLarge, and Message says more. Both are the collector's text. A failure is about
// one subject: it goes to the facts of that subject, and never counts against the collector's health.
type Failure struct{ Reason, Message string }

// Invoke runs one operation of the collector for one subject, as req says, and returns the collector's answer: the
// events, a failure, or both, the events first.
//
// Each event is valid evidence: Invoke checks it again with evidence.Validate, as the SDK's server checked it before
// it sent it, because a collector needn't be built with the SDK. An answer that breaks the API's contract gives an
// error, and none of the answer: an event that isn't valid evidence, a failure without a reason, a second failure, an
// item after the failure, or an item that the API doesn't know. So does a call that ends with an error before the
// answer is complete. A caller then never takes part of an answer for all of it, as the SDK's server, which sends
// none of an answer that breaks the contract, never lets it either. An error about the answer repeats nothing that the
// answer holds. The error of a call that failed keeps the status that the collector answered with, as with every call
// of the pool.
//
// Invoke doesn't check that the events are of the types that the operation produces: the caller knows the
// operation's capabilities, and the pool doesn't.
func (p *Pool) Invoke(ctx context.Context, collector string, req *collectorv1alpha1.InvokeRequest) (
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
	var answer answer
	for {
		resp, err := call.Recv()
		if errors.Is(err, io.EOF) {
			return answer.events, answer.failure, nil
		}
		if err != nil {
			return nil, nil, callError("Invoke", collector, err)
		}
		if err := answer.add(resp); err != nil {
			return nil, nil, fmt.Errorf("the answer of collector %s to Invoke breaks the API's contract: %w",
				collector, err)
		}
	}
}

// answer is what a collector answered to Invoke so far.
type answer struct {
	events  []cloudevents.Event
	failure *Failure
}

// add takes the next item of the answer, or says how it breaks the contract. Its errors repeat nothing that the item
// holds: evidence.Validate's and evidence.FromProto's don't either.
func (a *answer) add(resp *collectorv1alpha1.InvokeResponse) error {
	if a.failure != nil {
		return errors.New("an item came after the failure, which comes last")
	}
	switch item := resp.GetItem().(type) {
	case *collectorv1alpha1.InvokeResponse_Event:
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
