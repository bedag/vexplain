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

package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	sigsjson "sigs.k8s.io/json"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// The deployer reads the runtime configs, and watches them, so that a change of one shapes the collectors again. It
// creates the one named default at its start, when it is missing, and never writes it again.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectorruntimeconfigs,verbs=get;list;watch;create

const (
	// defaultRuntimeConfig is the runtime config of a Collector that names none.
	defaultRuntimeConfig = "default"
	// defaultRuntimeConfigRetry is how long the start of the deployer waits before it tries again to create the
	// default runtime config, after the API server failed it.
	defaultRuntimeConfigRetry = 10 * time.Second
)

// shape is what the runtime config of a collector makes of the defaults: the Deployment, with the collector's
// contract set again, and the labels and annotations of the service account.
type shape struct {
	deployment         *appsv1.Deployment
	accountLabels      map[string]string
	accountAnnotations map[string]string
}

// shapeOf reads the runtime config of obj, and returns what its templates make of the defaults. A config that a
// Collector names and that doesn't exist, and a template that doesn't decode, is a refusal for RuntimeConfigInvalid,
// with what is wrong. A Collector that names no config is shaped by default, or by nothing while default is missing,
// which equals the empty default that the operator creates at its start.
func (r *CollectorReconciler) shapeOf(ctx context.Context, obj *configv1alpha1.Collector) (*shape, *refusal, error) {
	name := defaultRuntimeConfig
	if obj.Spec.RuntimeConfigRef != nil {
		name = obj.Spec.RuntimeConfigRef.Name
	}
	var config configv1alpha1.CollectorRuntimeConfig
	switch err := r.Get(ctx, client.ObjectKey{Name: name}, &config); {
	case apierrors.IsNotFound(err) && obj.Spec.RuntimeConfigRef == nil:
		// Nothing shapes the collector, as the empty default wouldn't.
	case apierrors.IsNotFound(err):
		return nil, refuse(configv1alpha1.ReasonRuntimeConfigInvalid,
			"The CollectorRuntimeConfig %q, which the Collector names, doesn't exist.", name), nil
	case err != nil:
		return nil, nil, fmt.Errorf("read the CollectorRuntimeConfig %q: %w", name, err)
	}

	deployment, err := mergeDeployment(defaultDeployment(obj, r.OperatorNamespace, r.ProxyEnv), config.Spec.DeploymentTemplate)
	if err != nil {
		return nil, refuse(configv1alpha1.ReasonRuntimeConfigInvalid,
			"The deployment template of the CollectorRuntimeConfig %q doesn't decode as a Deployment: %v", name, err), nil
	}
	setContract(deployment, obj, r.OperatorNamespace)
	var account accountTemplate
	if template := config.Spec.ServiceAccountTemplate; template != nil && len(template.Raw) > 0 {
		if err := decodeStrict(template.Raw, &account); err != nil {
			return nil, refuse(configv1alpha1.ReasonRuntimeConfigInvalid,
				"The service account template of the CollectorRuntimeConfig %q doesn't decode as the labels and the "+
					"annotations of a service account: %v", name, err), nil
		}
	}
	return &shape{deployment: deployment, accountLabels: account.Metadata.Labels, accountAnnotations: account.Metadata.Annotations}, nil, nil
}

// accountTemplate is what a service account template shapes: the labels and the annotations of the service account,
// such as an annotation for a cloud identity. Its name and the rest of it are the deployer's.
type accountTemplate struct {
	Metadata struct {
		Labels      map[string]string `json:"labels,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
	} `json:"metadata"`
}

// mergeDeployment merges template onto defaults as a strategic merge patch, as kubectl patches a Deployment, and
// returns the labels, the annotations and the spec of the result. The result must decode as a Deployment, strictly:
// a field that a Deployment doesn't have is an error, so that a misspelt field doesn't go unnoticed.
func mergeDeployment(defaults *appsv1.Deployment, template *runtime.RawExtension) (*appsv1.Deployment, error) {
	if template == nil || len(template.Raw) == 0 {
		return defaults, nil
	}
	original, err := json.Marshal(defaults)
	if err != nil {
		return nil, fmt.Errorf("encode the defaults: %w", err)
	}
	merged, err := strategicpatch.StrategicMergePatch(original, template.Raw, appsv1.Deployment{})
	if err != nil {
		return nil, fmt.Errorf("it can't be merged onto the defaults: %w", err)
	}
	var shaped appsv1.Deployment
	if err := decodeStrict(merged, &shaped); err != nil {
		return nil, err
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Labels: shaped.Labels, Annotations: shaped.Annotations},
		Spec:       shaped.Spec,
	}, nil
}

// decodeStrict decodes raw into v, and fails for a field that v doesn't have, and for a field given twice.
func decodeStrict(raw []byte, v any) error {
	strict, err := sigsjson.UnmarshalStrict(raw, v)
	if err != nil {
		return err
	}
	return errors.Join(strict...)
}

// collectorsShapedBy maps a runtime config to the Collectors that it shapes: those that name it, and, for default,
// those that name none.
func (r *CollectorReconciler) collectorsShapedBy(ctx context.Context, config client.Object) []reconcile.Request {
	var collectors configv1alpha1.CollectorList
	if err := r.List(ctx, &collectors); err != nil {
		logf.FromContext(ctx).Error(err, "Could not list the Collectors that a runtime config shapes; the resync shapes them")
		return nil
	}
	var requests []reconcile.Request
	for i := range collectors.Items {
		ref := collectors.Items[i].Spec.RuntimeConfigRef
		if (ref == nil && config.GetName() == defaultRuntimeConfig) || (ref != nil && ref.Name == config.GetName()) {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: collectors.Items[i].Name}})
		}
	}
	return requests
}

// ensureDefaultRuntimeConfig creates the runtime config named default, empty, when it is missing, and leaves one
// that exists as it is, whatever an admin made of it.
func ensureDefaultRuntimeConfig(ctx context.Context, c client.Client) error {
	err := c.Create(ctx, &configv1alpha1.CollectorRuntimeConfig{ObjectMeta: metav1.ObjectMeta{Name: defaultRuntimeConfig}})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// createDefaultRuntimeConfig runs ensureDefaultRuntimeConfig until it succeeds, or until ctx ends.
func createDefaultRuntimeConfig(ctx context.Context, c client.Client) error {
	log := logf.FromContext(ctx).WithName("collector-runtime-config")
	// The condition never fails, so the poll ends with an error only when ctx ends, as the manager stops.
	_ = wait.PollUntilContextCancel(ctx, defaultRuntimeConfigRetry, true, func(ctx context.Context) (bool, error) {
		if err := ensureDefaultRuntimeConfig(ctx, c); err != nil {
			log.Error(err, "Could not create the default runtime config; trying again")
			return false, nil
		}
		return true, nil
	})
	return nil
}
