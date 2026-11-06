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

// Package attribution reads the allowlists of owner attribution that vexplain passes its collectors, in the context
// of every Watch and Invoke: the keys of the labels and annotations of namespaces and workloads that their evidence
// copies, so that whoever acts on a finding knows whom to inform (decision 0020). Owner data is copied, and never
// interpreted, and nothing is copied that an allowlist doesn't name.
package attribution

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Allowlists are the allowlists of owner attribution: OperatorConfig's spec.ownerAttribution, with the same fields and
// JSON names. vexplain's API lives in the operator's module, which the SDK doesn't import, so the SDK has this type.
type Allowlists struct {
	// NamespaceLabels are the keys of the namespace labels to copy.
	NamespaceLabels []string `json:"namespaceLabels,omitempty"`
	// NamespaceAnnotations are the keys of the namespace annotations to copy.
	NamespaceAnnotations []string `json:"namespaceAnnotations,omitempty"`
	// WorkloadLabels are the keys of the workload labels to copy.
	WorkloadLabels []string `json:"workloadLabels,omitempty"`
}

// Parse reads the allowlists from their JSON, as the context of a Watch or an Invoke carries it. Empty JSON, null and
// {} are no allowlists, which copy nothing.
//
// Parse refuses JSON that it can't read fully: JSON that is no object, or that holds a field that Allowlists lacks,
// or more than one value. A field that it doesn't know, such as one whose name the API changed, would copy nothing
// that an admin allowlisted there, and nobody would notice.
func Parse(raw []byte) (Allowlists, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Allowlists{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var allowlists *Allowlists
	if err := decoder.Decode(&allowlists); err != nil {
		return Allowlists{}, fmt.Errorf("read the allowlists of owner attribution: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Allowlists{}, errors.New("read the allowlists of owner attribution: more JSON follows them")
	}
	if allowlists == nil {
		return Allowlists{}, nil
	}
	return *allowlists, nil
}
