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

package collector

// MaxPointsPerCall is how many entry points a call to a source holds, in Hosts and Addresses together.
const MaxPointsPerCall = 64

// The reasons that a source fails a whole call with.
const (
	// ReasonInvalidInput says that the source can't read a point of the call. The message carries no values.
	ReasonInvalidInput = "InvalidInput"
	// ReasonNotReady says that the source's own data is stale or being rebuilt.
	ReasonNotReady = "NotReady"
)

// EntryPointParameters are the parameters of an operation that answers about entry points, which is
// how the hub knows a source: the operation consumes nothing.
type EntryPointParameters struct {
	// Hosts are host names, a leading "*." allowed.
	Hosts []string `json:"hosts,omitempty"`
	// Addresses are IP addresses, each with or without a port, such as 192.0.2.10, 192.0.2.10:443 or
	// [2001:db8::1]:443.
	Addresses []string `json:"addresses,omitempty"`
}

// EntryPointParameterSchema is the JSON Schema of EntryPointParameters. JSON Schema can't limit two
// lists together, so each holds at most 64 here, and the caller sends at most MaxPointsPerCall in all.
const EntryPointParameterSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "hosts": {
      "type": "array",
      "maxItems": 64,
      "items": { "type": "string", "minLength": 1 }
    },
    "addresses": {
      "type": "array",
      "maxItems": 64,
      "items": { "type": "string", "minLength": 1 }
    }
  },
  "anyOf": [{ "required": ["hosts"] }, { "required": ["addresses"] }]
}`
