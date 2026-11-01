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

package config_test

import (
	"fmt"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// The specs of the config kinds' schemas share these helpers. The kinds are cluster-scoped, so every
// object shares one namespace, and the manager of the suite reconciles whatever the specs create.
// A spec names its objects with apiName and deletes them when it ends, so that no spec sees another's.

const (
	// The types of evidence that the example collectors of the specs produce.
	presenceType = "ch.bedag.vexplain.presence.v1alpha1"
	contentsType = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"
	exposureType = "ch.bedag.vexplain.exposure.v1alpha1"
	findingsType = "ch.bedag.vexplain.findings.v1alpha1"
	// examplePackage is an image that a Collector may name.
	examplePackage = "artifacts.example/vexplain/hello:0.1.0"

	// The names that the playbook of the design gives its collectors and evidence. The matcher
	// produces the findings, and the exposure collector and the evidence it delivers share a name.
	matcherName  = "matcher"
	contentsName = "contents"
	exposureName = "exposure"

	// celTrue is the CEL expression that holds for every finding.
	celTrue = "true"

	// The names of the fields that the specs write as raw content.
	specField      = "spec"
	typeField      = "type"
	nameField      = "name"
	collectorField = "collector"
	packageField   = "package"
	outcomeField   = "outcome"
	conditionField = "condition"
	subjectsField  = "subjects"
	pipelineField  = "pipeline"
	overridesField = "overrides"
)

// nameCounter numbers the objects that the specs create.
var nameCounter atomic.Int64

// apiName returns a name that no other spec of the suite uses, and that every kind accepts: a DNS-1123
// label that starts with prefix.
func apiName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, nameCounter.Add(1))
}

// createObject creates obj, and deletes it when the spec ends.
func createObject(obj client.Object) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, obj)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
	})
}

// refusedWith matches the error of a request that the API server refused as invalid, and whose message
// holds each of parts: the field that it names, or the message of the rule that refused it.
func refusedWith(parts ...string) types.GomegaMatcher {
	matchers := make([]types.GomegaMatcher, 0, 1+len(parts))
	matchers = append(matchers, Satisfy(apierrors.IsInvalid))
	for _, part := range parts {
		matchers = append(matchers, MatchError(ContainSubstring(part)))
	}
	return And(matchers...)
}

// rawObject builds an object of a kind of the config group from raw spec content. A Go struct can't
// say a value that its field leaves out, such as an empty string or an empty list, and some specs need
// exactly that on the wire.
func rawObject(kind, name string, spec map[string]any) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{specField: spec}}
	obj.SetGroupVersionKind(configv1alpha1.GroupVersion.WithKind(kind))
	obj.SetName(name)
	return obj
}
