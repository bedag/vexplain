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

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	// eventType is the type of the evidence that this collector produces. It is named in reverse-DNS by whoever
	// defines it, which is you: use a domain of your own, and a version. A change that breaks the shape of the
	// data needs a new version, such as v1alpha2.
	eventType = "com.example.hello.v1alpha1"
	// defaultGreeting and defaultWorkload are what the collector says, and to whom, when its settings don't say
	// otherwise.
	defaultGreeting = "Hello"
	defaultWorkload = "web"
)

// helloSchema is the JSON Schema of the data of a hello event. Whoever writes a rule about the type reads it, and
// the conformance suite checks every event against it. Say in each description what the field means, and what the
// coverage of the evidence counts.
const helloSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["greeting"],
  "properties": {
    "greeting": {
      "description": "What the collector says about the workload.",
      "type": "string",
      "minLength": 1
    }
  }
}`

// settingsSchema is the JSON Schema of the collector's settings, which the admin who installs the collector writes
// in the spec of its Collector. The SDK checks every setting against it before the collector sees it. The schema
// stands alone: it refers to nothing outside itself.
const settingsSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "greeting": {
      "description": "What the collector says. It is Hello when the settings don't say.",
      "type": "string",
      "minLength": 1,
      "maxLength": 64
    },
    "workload": {
      "description": "The Deployment in team-a that the collector greets. It is web when the settings don't say.",
      "type": "string",
      "maxLength": 63,
      "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
    }
  }
}`

// version is the version of the collector, which GetInfo reports. vexplain stores evidence at it, so that a new
// version replaces what an old one delivered. The build sets it: see the Makefile.
var version = "0.1.0"

// settings are the collector's settings, as the schema above describes them.
type settings struct {
	Greeting string `json:"greeting"`
	Workload string `json:"workload"`
}

// helloData is the data of a hello event, as helloSchema describes it.
type helloData struct {
	Greeting string `json:"greeting"`
}

// hello is the collector. Every collector implements collector.Collector, which describes it: Info and
// Capabilities. One that streams evidence also implements collector.Watcher, as this one does. One with operations
// would implement collector.Invoker, and one that checks its settings beyond their schema
// collector.SettingsValidator.
type hello struct{}

func (h *hello) Info() collector.Info {
	return collector.Info{Name: "hello", Version: version}
}

// Capabilities say what the collector does. The SDK reads them once, when it starts, and holds the collector to
// them: it refuses to start a collector whose capabilities contradict themselves, and it ends a stream that sends
// evidence of a type that they don't list.
func (h *hello) Capabilities() collector.Capabilities {
	return collector.Capabilities{
		// Roles say where the collector runs: in a cluster, next to its workloads (the spoke), or on the hub.
		Roles: []collector.Role{collector.RoleSpoke},
		// Produces lists the types of evidence, each with its scope, and the schema of its data. Spoke evidence
		// stays in its cluster, and hub evidence goes to the hub, which collects it across clusters.
		Produces: []collector.EvidenceType{{Type: eventType, Scope: collector.ScopeSpoke, Schema: []byte(helloSchema)}},
		Watches:  true,
		// Permissions list what the collector needs from the Kubernetes API, as RBAC rules. This one needs none.
		SettingsSchema: []byte(settingsSchema),
	}
}

// Watch sends a snapshot of the collector's evidence, and then each change, until ctx ends. Every Watch has a
// stream of its own, and starts with a snapshot of its own, so that vexplain can reconnect at any time.
func (h *hello) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	var s settings
	if err := json.Unmarshal(req.Settings, &s); err != nil {
		return fmt.Errorf("reading the settings: %w", err)
	}
	if s.Greeting == "" {
		s.Greeting = defaultGreeting
	}
	if s.Workload == "" {
		s.Workload = defaultWorkload
	}

	// The evidence is about a workload. Its subject is workload/<cluster>/<namespace>/<Kind>[.<group>]/<name>,
	// and the cluster is the one that vexplain's context names.
	about := subject.ForWorkload(subject.Workload{
		Cluster: req.Context.Cluster, Namespace: "team-a", Group: "apps", Kind: "Deployment", Name: s.Workload,
	})
	greeting, err := evidence.New(eventType, about, helloData{Greeting: s.Greeting},
		evidence.WithSource("/clusters/"+req.Context.Cluster+"/collectors/hello"),
		// The coverage says how much of the subject the evidence covers, as a percentage that the type's
		// documentation explains. This collector looks at all of what it says something about.
		evidence.WithCoverage(100))
	if err != nil {
		return err
	}

	// A snapshot is everything that the collector has now: SnapshotStart, an event for each piece of evidence,
	// and SnapshotEnd. Only a snapshot that ended is complete, so vexplain takes nothing of it before.
	if err := sink.SnapshotStart(); err != nil {
		return err
	}
	if err := sink.Event(greeting); err != nil {
		return err
	}
	if err := sink.SnapshotEnd(); err != nil {
		return err
	}

	// Changes come after the snapshot: sink.Event for evidence that is new or changed, and sink.Tombstone for
	// evidence that is gone. This collector has nothing to watch, so it waits until vexplain ends the stream.
	<-ctx.Done()
	return ctx.Err()
}
