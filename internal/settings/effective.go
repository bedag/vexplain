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

// Package settings gives the rest of the operator one view of its configuration.
//
// The OperatorConfig singleton is optional: with no object, or with an empty spec, the operator
// runs on the defaults. Load applies those defaults, so no caller sees a half-filled
// configuration or needs to know where a value came from.
package settings

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

const (
	// ConfigName is the name of the OperatorConfig singleton. The CRD rejects every other name.
	ConfigName = "default"
	// DefaultClusterName is the cluster name when the OperatorConfig doesn't set one. It must
	// equal the default of spec.clusterName in the CRD schema, which the API server applies.
	DefaultClusterName = "local"
	// DefaultMinCompletenessPercent is the completeness that the guard of the rules demands when
	// the OperatorConfig doesn't set one. It must equal the default of
	// spec.rules.minCompletenessPercent in the CRD schema, which the API server applies.
	DefaultMinCompletenessPercent int32 = 90
)

// Rules holds the settings of the hub's rules, with the defaults filled in.
type Rules struct {
	// MinCompletenessPercent is the share of an image's ELF files that packages must account for
	// before any rule may settle a finding in it as not affected. It is from 0 to 100: the CRD
	// schema sees to that, and Load doesn't check it again.
	MinCompletenessPercent int32
}

// Effective is the configuration the operator runs with.
type Effective struct {
	// ClusterName names this cluster in metrics and in inventory entries. It is never empty.
	ClusterName string
	// Scope selects which pods are analysed. Nil means every pod. Load doesn't check that the
	// selectors parse: whoever builds a matcher from them gets that error.
	Scope *configv1alpha1.Scope
	// Rules holds the settings of the hub's rules.
	Rules Rules
}

// defaults returns the settings of an operator that has no OperatorConfig.
func defaults() Effective {
	return Effective{
		ClusterName: DefaultClusterName,
		Rules:       Rules{MinCompletenessPercent: DefaultMinCompletenessPercent},
	}
}

// Load returns the settings of the OperatorConfig named default, with the defaults filled in.
// When the object is absent it returns the defaults. Any other error is returned, so a failed
// read is never mistaken for an unconfigured operator.
func Load(ctx context.Context, r client.Reader) (Effective, error) {
	var operatorConfig configv1alpha1.OperatorConfig
	if err := r.Get(ctx, client.ObjectKey{Name: ConfigName}, &operatorConfig); err != nil {
		if apierrors.IsNotFound(err) {
			return defaults(), nil
		}
		return Effective{}, fmt.Errorf("read OperatorConfig %q: %w", ConfigName, err)
	}

	effective := defaults()
	effective.Scope = operatorConfig.Spec.Scope
	// The API server defaults an absent clusterName, and its schema rejects an empty one. A
	// client that skips the schema, such as a fake client, can return either.
	if name := ptr.Deref(operatorConfig.Spec.ClusterName, ""); name != "" {
		effective.ClusterName = name
	}
	// The API server defaults an absent threshold in rules that exist, and a client that skips the
	// schema can return it unset. A threshold of 0 is a threshold: only a nil one is unset.
	if rules := operatorConfig.Spec.Rules; rules != nil {
		effective.Rules.MinCompletenessPercent = ptr.Deref(rules.MinCompletenessPercent, DefaultMinCompletenessPercent)
	}
	return effective, nil
}
