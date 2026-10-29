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

// This file holds the condition types and reasons that every kind of the config group shares.
// A kind that needs a reason of its own adds it here, so the vocabulary stays in one place.

// Condition types.
const (
	// ConditionReady says whether the operator has accepted the object and can use it.
	ConditionReady = "Ready"
)

// Reasons of the Ready condition. The set is open: more reasons may follow, so code that reads
// them must not assume it knows them all.
const (
	// ReasonValid means the object passed validation. Ready is True.
	ReasonValid = "Valid"
	// ReasonInvalid means the object holds a value the operator cannot use, for example a label
	// selector with a malformed expression. Ready is False, and the message names the field.
	ReasonInvalid = "Invalid"
	// ReasonUnknownValue means a field holds a value of an open enum that this version of the
	// operator does not know. Ready is False. The operator reports it and never panics.
	ReasonUnknownValue = "UnknownValue"
	// ReasonHealthy means the last report of a collector was a success. Ready is True.
	ReasonHealthy = "Healthy"
	// ReasonCollectorFailing means the last report of a collector was a failure. Ready is False,
	// and the message holds the error that the collector reported.
	ReasonCollectorFailing = "CollectorFailing"
	// ReasonNoData means the collector has not reported since the operator started, so its health
	// is not known. Ready is Unknown.
	ReasonNoData = "NoData"
)
