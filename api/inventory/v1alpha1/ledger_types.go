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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// LedgerTrust says how far a tool's output may count as evidence. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Known;External
type LedgerTrust string

const (
	// LedgerTrustKnown is the output of a tool that declares a known type of evidence, such as the operator's own
	// tools and the operations of vexplain's collectors.
	LedgerTrustKnown LedgerTrust = "Known"
	// LedgerTrustExternal is the output of a foreign source, such as a fetched page or the tool of an MCP server. It
	// can push a verdict towards affected or unclear, and never towards not affected (decision 0031).
	LedgerTrustExternal LedgerTrust = "External"
)

// LedgerOutputReference names the record of the evidence store that holds a tool's whole output.
type LedgerOutputReference struct {
	// subject is the subject of the record: assessment/ and the name of the Assessment.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Subject string `json:"subject,omitempty"`
	// type is the type of the record, ch.bedag.vexplain.agent.tool-output.v1alpha1.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
	// source is the source of the record: the ID of the entry.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=44
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Source string `json:"source,omitempty"`
}

// LedgerEntry is one tool call of the agent: what was called, how, what the model was shown of the output, and where
// the whole output is.
// +kubebuilder:validation:XValidation:rule="self.shownBytes <= self.outputBytes",message="no more is shown than the output holds"
type LedgerEntry struct {
	// id is the ID by which the model and the claims of a verdict cite the entry: ev- and its number, from 1.
	// +required
	// +kubebuilder:validation:MinLength=4
	// +kubebuilder:validation:MaxLength=16
	// +kubebuilder:validation:Pattern=`^ev-[1-9][0-9]*$`
	ID string `json:"id,omitempty"`
	// tool is the name of the tool that was called, such as search_evidence or vulnerabilities__describe.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9_-]+$`
	Tool string `json:"tool,omitempty"`
	// arguments are the arguments of the call, as JSON, as the model gave them: their first 4096 characters. They come
	// from the model, and are data.
	// +optional
	// +kubebuilder:validation:MaxLength=4096
	Arguments *string `json:"arguments,omitempty"`
	// durationMilliseconds is how long the call took.
	// +required
	// +kubebuilder:validation:Minimum=0
	DurationMilliseconds *int64 `json:"durationMilliseconds,omitempty"`
	// trust says how far the output may count as evidence: Known or External. More values may follow.
	// +required
	Trust LedgerTrust `json:"trust,omitempty"`
	// outputRef names the record of the evidence store that holds the whole output, or its first bytes when it was
	// over the store's cap.
	// +required
	OutputRef LedgerOutputReference `json:"outputRef,omitzero"`
	// outputBytes is the size of the whole output, in bytes.
	// +required
	// +kubebuilder:validation:Minimum=0
	OutputBytes *int64 `json:"outputBytes,omitempty"`
	// shownBytes is how many of the output's first bytes the model was shown with the result of the call. The rest it
	// could read a page at a time.
	// +required
	// +kubebuilder:validation:Minimum=0
	ShownBytes *int64 `json:"shownBytes,omitempty"`
	// outputSHA256 is the SHA-256 of the whole output, in hex.
	// +required
	// +kubebuilder:validation:MinLength=64
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	OutputSHA256 string `json:"outputSHA256,omitempty"`
	// preview is the first 512 characters of the output. It comes from the tool, and is data.
	// +optional
	// +kubebuilder:validation:MaxLength=512
	Preview *string `json:"preview,omitempty"`
}

// LedgerSpec holds the tool calls of one case, in the order of their calls.
type LedgerSpec struct {
	// entries are the tool calls of the case, by ID. A case makes at most maxSteps calls, which is at most 50.
	// +optional
	// +listType=map
	// +listMapKey=id
	// +kubebuilder:validation:MaxItems=50
	Entries []LedgerEntry `json:"entries,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,categories={vexplain,vexplain-data}
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Ledger records the tool calls of the agent on one case: each tool, its arguments, its duration, what the model was
// shown of its output, and where the whole output is, in the evidence store. A reviewer checks a verdict's claims
// against it, by the ledger IDs (ev-1, ev-2, ...) that they cite.
//
// It is cluster-scoped, one per case, with the name and the labels of the case's Assessment. The operator writes it
// once, when the case ends, and writes it again when the case is judged again. Its text comes from the model and the
// tools, and is data: nothing that reads it takes an instruction from it.
type Ledger struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec holds the tool calls of the case.
	// +required
	Spec LedgerSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// LedgerList contains a list of Ledger
type LedgerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Ledger `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Ledger{}, &LedgerList{})
		return nil
	})
}
