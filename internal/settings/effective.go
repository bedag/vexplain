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
)

// Effective is the configuration the operator runs with.
type Effective struct {
	// ClusterName names this cluster in metrics and in inventory entries. It is never empty.
	ClusterName string
	// Scope selects which pods are analysed. Nil means every pod. Load doesn't check that the
	// selectors parse: whoever builds a matcher from them gets that error.
	Scope *configv1alpha1.Scope
	// OwnerAttribution holds the allowlists of the labels and annotations that are copied to say whom
	// to inform about a workload. They are empty unless the OperatorConfig names keys: nothing is
	// copied by default. Load doesn't check the keys again: the CRD schema sees to their form.
	OwnerAttribution configv1alpha1.OwnerAttribution
	// Urgency holds the admin's overrides of SSVC's deployer table. It has none unless the
	// OperatorConfig lists some. Load doesn't check them again: the CRD schema sees to their values
	// and to the one override of each combination.
	Urgency configv1alpha1.Urgency
	// ClusterLabels describe this cluster, for the playbooks that match clusters by labels. They are
	// the operator's own: they are never passed to collectors. Load doesn't check them again: the
	// CRD schema sees to their keys and values.
	ClusterLabels map[string]string
	// PermissionsMode says whether the operator grants the permissions that collectors declare, or
	// only checks them. It is never empty.
	PermissionsMode configv1alpha1.PermissionsMode
	// DeniedPermissions are the permissions that no collector gets. It is DefaultDeniedPermissions
	// when the OperatorConfig sets no list, and an empty, non-nil list when the admin sets one that
	// is empty, which denies nothing.
	DeniedPermissions []configv1alpha1.PermissionRule
}

// DefaultDeniedPermissions is the deny list when the OperatorConfig sets none: no collector may list
// or watch secrets, whatever it declares. Load returns a copy, so a caller may change what it gets.
var DefaultDeniedPermissions = []configv1alpha1.PermissionRule{
	{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list", "watch"}},
}

// defaults returns the settings of an operator that has no OperatorConfig.
func defaults() Effective {
	denied := make([]configv1alpha1.PermissionRule, len(DefaultDeniedPermissions))
	for i := range DefaultDeniedPermissions {
		DefaultDeniedPermissions[i].DeepCopyInto(&denied[i])
	}
	return Effective{
		ClusterName:       DefaultClusterName,
		PermissionsMode:   configv1alpha1.PermissionsModeGrant,
		DeniedPermissions: denied,
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
	if attribution := operatorConfig.Spec.OwnerAttribution; attribution != nil {
		effective.OwnerAttribution = *attribution
	}
	if urgency := operatorConfig.Spec.Urgency; urgency != nil {
		effective.Urgency = *urgency
	}
	if len(operatorConfig.Spec.ClusterLabels) > 0 {
		effective.ClusterLabels = make(map[string]string, len(operatorConfig.Spec.ClusterLabels))
		for key, value := range operatorConfig.Spec.ClusterLabels {
			effective.ClusterLabels[key] = string(value)
		}
	}
	if policy := operatorConfig.Spec.Collectors; policy != nil {
		if mode := ptr.Deref(policy.Permissions, ""); mode != "" {
			effective.PermissionsMode = mode
		}
		// A nil list is absent and keeps the default. An empty one is the admin's choice to deny
		// nothing, and the copy stays non-nil.
		if policy.DeniedPermissions != nil {
			denied := make([]configv1alpha1.PermissionRule, len(policy.DeniedPermissions))
			for i := range policy.DeniedPermissions {
				policy.DeniedPermissions[i].DeepCopyInto(&denied[i])
			}
			effective.DeniedPermissions = denied
		}
	}
	return effective, nil
}
