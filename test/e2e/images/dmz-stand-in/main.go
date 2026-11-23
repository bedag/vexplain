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

// Command dmz-stand-in is the source of the e2e tests: a collector on the SDK that answers, in the hub role, whether
// the internet reaches an entry point, as a DMZ's source would (design of entry points, section 5.5).
//
// Its settings are {"published": {"<subject>": "Internet" | "Internal"}}, and every other entry point is None. Its
// source's version is a hash of the settings that it last saw, so that the hub asks again once they change. Its
// source is part of the operator's module, so that it is vetted and linted with it, and its Dockerfile builds it in
// a module of its own, beside the SDK.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"sync/atomic"
	"syscall"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// version is the version that GetInfo reports. The build sets it.
var version = "0.1.0"

const (
	// eventType is the type of the answers, which the hub keeps for maxAge.
	eventType = "ch.example.dmz.publication.v1alpha1"
	maxAge    = time.Hour
	// dataSchema is the JSON Schema of an answer.
	dataSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["publishedTo"],
  "properties": {"publishedTo": {"enum": ["Internet", "Internal", "None"]}}
}`
	// settingsSchema is the JSON Schema of the settings.
	settingsSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "published": {"type": "object", "additionalProperties": {"enum": ["Internet", "Internal"]}}
  }
}`
)

// settings are the stand-in's settings: what each subject is published to.
type settings struct {
	Published map[string]string `json:"published,omitempty"`
}

// standIn answers from the settings of each call, and keeps the version of the settings that it saw last.
type standIn struct {
	name string
	seen atomic.Pointer[string]
}

// Serve finds what the stand-in does beyond describing itself through these interfaces.
var (
	_ collector.Invoker           = (*standIn)(nil)
	_ collector.Sourcer           = (*standIn)(nil)
	_ collector.SettingsValidator = (*standIn)(nil)
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	s := &standIn{name: os.Getenv("VEXPLAIN_COLLECTOR_NAME")}
	s.ValidateSettings(json.RawMessage("{}"))
	err := collector.Serve(ctx, s, collector.OptionsFromEnv())
	stop() // os.Exit doesn't run deferred calls.
	if err != nil {
		slog.Error("The stand-in failed", "error", err)
		os.Exit(1)
	}
}

// Info names the stand-in by its Collector.
func (s *standIn) Info() collector.Info {
	return collector.Info{Name: s.name, Version: version}
}

// Capabilities say that the stand-in answers about entry points with the operation lookup, in the hub role.
func (s *standIn) Capabilities() collector.Capabilities {
	return collector.Capabilities{
		Roles: []collector.Role{collector.RoleHub},
		Produces: []collector.EvidenceType{
			{Type: eventType, Scope: collector.ScopeHub, Schema: []byte(dataSchema), MaxAge: maxAge},
		},
		Operations: []collector.Operation{{
			Name: "lookup", Description: "Says whether the internet reaches each entry point.", Role: collector.RoleHub,
			Produces: []string{eventType}, ParameterSchema: []byte(collector.EntryPointParameterSchema),
		}},
		SettingsSchema: []byte(settingsSchema),
	}
}

// ValidateSettings notes the version of the settings, which their schema has checked. The operator sends them
// whenever it checks the Collector, and GetInfo can't carry them.
func (s *standIn) ValidateSettings(raw json.RawMessage) []string {
	var set settings
	_ = json.Unmarshal(raw, &set)
	// Marshalled again, the settings have their keys sorted, so that only a change of what they say changes the hash.
	canonical, _ := json.Marshal(set)
	sum := sha256.Sum256(canonical)
	v := hex.EncodeToString(sum[:8])
	s.seen.Store(&v)
	return nil
}

// Sources report the version of the settings that the stand-in saw last.
func (s *standIn) Sources() []collector.Source {
	return []collector.Source{{Name: "publications", Version: *s.seen.Load()}}
}

// Invoke answers each distinct entry point of the call with one event about its subject, and fails the whole call
// with InvalidInput when it can't read one.
func (s *standIn) Invoke(_ context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure,
	error) {
	var set settings
	var params collector.EntryPointParameters
	if json.Unmarshal(req.Settings, &set) != nil || json.Unmarshal(req.Parameters, &params) != nil {
		return nil, &collector.Failure{Reason: collector.ReasonInvalidInput, Message: "the call can't be read"}, nil
	}
	subjects := make([]string, 0, len(params.Hosts)+len(params.Addresses))
	for _, h := range params.Hosts {
		subjects = append(subjects, hostSubject(h))
	}
	for _, a := range params.Addresses {
		subjects = append(subjects, addressSubject(a))
	}
	if slices.Contains(subjects, "") {
		return nil, &collector.Failure{Reason: collector.ReasonInvalidInput, Message: "a point can't be read"}, nil
	}
	slices.Sort(subjects)
	subjects = slices.Compact(subjects)
	events := make([]cloudevents.Event, 0, len(subjects))
	for _, sub := range subjects {
		publishedTo := set.Published[sub]
		if publishedTo == "" {
			publishedTo = "None"
		}
		e, err := evidence.New(eventType, sub, map[string]string{"publishedTo": publishedTo},
			evidence.WithSource("/hub/collectors/"+s.name))
		if err != nil {
			return nil, nil, err
		}
		events = append(events, e)
	}
	slog.Info("Answered a lookup", "points", len(subjects))
	return events, nil, nil
}

// hostSubject returns the subject of a host name, or "" when it isn't one.
func hostSubject(h string) string {
	s, _ := subject.Host(h)
	return s
}

// addressSubject returns the subject of an address, with its port when it has one, or "" when it isn't one.
func addressSubject(a string) string {
	var s string
	if ap, err := netip.ParseAddrPort(a); err == nil {
		s, _ = subject.Address(ap.Addr().String(), ap.Port())
	} else if addr, err := netip.ParseAddr(a); err == nil {
		s, _ = subject.Address(addr.String(), 0)
	}
	return s
}
