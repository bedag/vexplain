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

package podtemplate_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/bedag/vexplain/sdk/podtemplate"
)

const (
	// worker is the container that a template shapes, and sidecar another one, which it leaves alone.
	worker  = "worker"
	sidecar = "sidecar"
	// ownLabel is a label that the collector sets on its pods itself, and teamLabel one that a template adds.
	ownLabel  = "vexplain.bedag.ch/task"
	teamLabel = "team"
	// taintKey and taintValue are the key and the value of the taint that the templates' tolerations tolerate.
	taintKey   = "dedicated"
	taintValue = "scans"
	// gpu is an extended resource.
	gpu corev1.ResourceName = "example.com/gpu"
)

// fullTemplate sets every field of a template.
func fullTemplate() podtemplate.PodTemplate {
	return podtemplate.PodTemplate{
		ImagePullPolicy: corev1.PullAlways,
		Resources: &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("4Gi")},
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("3Gi"), corev1.ResourceCPU: resource.MustParse("500m"),
			},
		},
		NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
		Tolerations: []corev1.Toleration{{
			Key: taintKey, Operator: corev1.TolerationOpEqual, Value: taintValue, Effect: corev1.TaintEffectNoSchedule,
		}},
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
				MatchExpressions: []corev1.NodeSelectorRequirement{{
					Key: "kubernetes.io/arch", Operator: corev1.NodeSelectorOpIn, Values: []string{"amd64", "arm64"},
				}},
			}}},
		}},
		PriorityClassName: "batch-low",
		RuntimeClassName:  ptr.To("gvisor"),
		Labels:            map[string]string{teamLabel: "team-a", ownLabel: "from-the-template"},
		Annotations:       map[string]string{"cluster-autoscaler.kubernetes.io/safe-to-evict": "true"},
	}
}

// pod returns the metadata and the spec of a pod that a collector made, before a template shapes it.
func pod() (*metav1.ObjectMeta, *corev1.PodSpec) {
	meta := &metav1.ObjectMeta{Labels: map[string]string{ownLabel: "scan"}}
	spec := &corev1.PodSpec{Containers: []corev1.Container{
		{Name: sidecar, Image: "artifacts.example/sidecar:1.0", ImagePullPolicy: corev1.PullNever},
		{Name: worker, Image: "artifacts.example/worker:1.0"},
	}}
	return meta, spec
}

func TestApplyShapesThePodAndTheNamedContainer(t *testing.T) {
	meta, spec := pod()
	template := fullTemplate()

	template.Apply(meta, spec, worker)

	require.Equal(t, corev1.PullAlways, spec.Containers[1].ImagePullPolicy)
	require.Equal(t, *template.Resources, spec.Containers[1].Resources)
	require.Equal(t, template.NodeSelector, spec.NodeSelector)
	require.Equal(t, template.Tolerations, spec.Tolerations)
	require.Equal(t, template.Affinity, spec.Affinity)
	require.Equal(t, "batch-low", spec.PriorityClassName)
	require.Equal(t, ptr.To("gvisor"), spec.RuntimeClassName)

	require.Equal(t, corev1.PullNever, spec.Containers[0].ImagePullPolicy, "the other container keeps what it had")
	require.Empty(t, spec.Containers[0].Resources, "the other container keeps what it had")
}

// The labels and annotations of a template add to the pod's, and never replace one that the collector set: the
// collector's own labels say which pods are its own.
func TestApplyAddsLabelsAndAnnotationsWithoutReplacingThePodsOwn(t *testing.T) {
	meta, spec := pod()

	fullTemplate().Apply(meta, spec, worker)

	require.Equal(t, map[string]string{ownLabel: "scan", teamLabel: "team-a"}, meta.Labels)
	require.Equal(t, map[string]string{"cluster-autoscaler.kubernetes.io/safe-to-evict": "true"}, meta.Annotations)
}

func TestApplyOfAnEmptyTemplatePullsIfNotPresentAndChangesNothingElse(t *testing.T) {
	meta, spec := pod()
	wantMeta, wantSpec := pod()
	wantSpec.Containers[1].ImagePullPolicy = corev1.PullIfNotPresent

	podtemplate.PodTemplate{}.Apply(meta, spec, worker)

	require.Equal(t, wantMeta, meta)
	require.Equal(t, wantSpec, spec)
}

// What Apply gives the pod is its own: a change to the template afterwards doesn't reach the pod.
func TestApplyCopiesWhatItGivesThePod(t *testing.T) {
	meta, spec := pod()
	template := fullTemplate()

	template.Apply(meta, spec, worker)
	template.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("1Gi")
	template.NodeSelector["kubernetes.io/os"] = "windows"
	template.Tolerations[0].Value = renamed
	template.Affinity.NodeAffinity = nil
	*template.RuntimeClassName = "changed"

	require.Equal(t, fullTemplate().Resources.Limits, spec.Containers[1].Resources.Limits)
	require.Equal(t, fullTemplate().NodeSelector, spec.NodeSelector)
	require.Equal(t, fullTemplate().Tolerations, spec.Tolerations)
	require.Equal(t, fullTemplate().Affinity, spec.Affinity)
	require.Equal(t, ptr.To("gvisor"), spec.RuntimeClassName)
}

// A container that the pod doesn't have takes nothing, and the pod still gets the rest of the template.
func TestApplyToAContainerThatThePodLacksShapesThePodAlone(t *testing.T) {
	meta, spec := pod()

	fullTemplate().Apply(meta, spec, "missing")

	require.Equal(t, corev1.PullNever, spec.Containers[0].ImagePullPolicy)
	require.Empty(t, spec.Containers[1].ImagePullPolicy)
	require.Equal(t, "batch-low", spec.PriorityClassName)
}

// compileSchema compiles the schema as a collector's settings schema embeds it, as a property of its own.
func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	settings := `{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", ` +
		`"properties": {"pod": ` + string(podtemplate.Schema()) + `}}`
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(settings))
	require.NoError(t, err, "the schema is JSON")
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	require.NoError(t, compiler.AddResource("urn:test:settings", doc))
	schema, err := compiler.Compile("urn:test:settings")
	require.NoError(t, err, "the schema compiles, and refers to nothing outside itself")
	return schema
}

// validate validates a template, as JSON, against the schema.
func validate(t *testing.T, schema *jsonschema.Schema, template string) error {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"pod": ` + template + `}`))
	require.NoError(t, err)
	return schema.Validate(doc)
}

func TestTheSchemaAcceptsEveryFieldOfATemplate(t *testing.T) {
	schema := compileSchema(t)
	raw, err := json.Marshal(fullTemplate())
	require.NoError(t, err)

	require.NoError(t, validate(t, schema, string(raw)))
	require.NoError(t, validate(t, schema, `{}`))
	require.NoError(t, validate(t, schema, `{"resources": {"limits": {"memory": 2147483648, "cpu": "2"}}}`),
		"a quantity is a string or a number, as Kubernetes reads it")
}

func TestTheSchemaRefusesWhatNoTemplateHolds(t *testing.T) {
	schema := compileSchema(t)
	for name, template := range map[string]string{
		"an unknown field":              `{"securityContext": {"privileged": true}}`,
		"a pull policy that isn't one":  `{"imagePullPolicy": "Sometimes"}`,
		"a toleration's unknown field":  `{"tolerations": [{"key": "a", "operatr": "Exists"}]}`,
		"a toleration's operator":       `{"tolerations": [{"key": "a", "operator": "Within"}]}`,
		"a label that isn't a string":   `{"labels": {"team": 1}}`,
		"resources of an unknown field": `{"resources": {"limit": {"memory": "1Gi"}}}`,
		"a quantity that is an object":  `{"resources": {"limits": {"memory": {"value": 1}}}}`,
		"a runtime class that is empty": `{"runtimeClassName": ""}`,
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validate(t, schema, template))
		})
	}
}

// The schema describes the fields of PodTemplate, each under its JSON name, and no other, so that the two can't
// drift apart.
func TestTheSchemaHasAPropertyForEachFieldOfATemplate(t *testing.T) {
	var schema struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	}
	decoder := json.NewDecoder(bytes.NewReader(podtemplate.Schema()))
	require.NoError(t, decoder.Decode(&schema))
	require.Equal(t, ptr.To(false), schema.AdditionalProperties)

	var fields []string
	for field := range reflect.TypeFor[podtemplate.PodTemplate]().Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		fields = append(fields, name)
	}
	properties := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		properties = append(properties, name)
	}
	slices.Sort(fields)
	slices.Sort(properties)
	require.Equal(t, fields, properties)
}

// The annotations that set AppArmor's and seccomp's profiles of a pod, or of a container, would loosen the pod's
// confinement: the collector sets no profile of its own, so unconfined would take effect.
var confinementAnnotations = []string{
	"container.apparmor.security.beta.kubernetes.io/" + worker,
	"seccomp.security.alpha.kubernetes.io/pod",
	"container.seccomp.security.alpha.kubernetes.io/" + worker,
}

func TestValidateAcceptsATemplateThatKubernetesTakes(t *testing.T) {
	require.Empty(t, fullTemplate().Validate())
	require.Empty(t, podtemplate.PodTemplate{}.Validate())
	extended := podtemplate.PodTemplate{Resources: &corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			gpu: resource.MustParse("1"), "hugepages-2Mi": resource.MustParse("64Mi"),
			corev1.ResourceMemory: resource.MustParse("1Gi"),
		},
		Requests: corev1.ResourceList{
			gpu: resource.MustParse("1"), corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
		},
	}}
	require.Empty(t, extended.Validate())
	tolerant := podtemplate.PodTemplate{Tolerations: []corev1.Toleration{
		{Operator: corev1.TolerationOpExists},
		{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute,
			TolerationSeconds: ptr.To(int64(60))},
		{Key: taintKey, Value: taintValue},
	}}
	require.Empty(t, tolerant.Validate())
}

// What would make the API server refuse the pod, or the kubelet run it with less confinement, is a problem of the
// template, which a collector reports as a problem of its settings: every pod would fail as it is created, or run
// unconfined.
func TestValidateRefusesWhatWouldLoosenOrBreakAPod(t *testing.T) {
	cases := map[string]func(*podtemplate.PodTemplate){
		"a label key that is no qualified name": func(p *podtemplate.PodTemplate) {
			p.Labels = map[string]string{"team a": "x"}
		},
		"a label value that is no label value": func(p *podtemplate.PodTemplate) {
			p.Labels = map[string]string{teamLabel: "team a"}
		},
		"an annotation key that is no qualified name": func(p *podtemplate.PodTemplate) {
			p.Annotations = map[string]string{"Team A": "x"}
		},
		"a node selector value that is no label value": func(p *podtemplate.PodTemplate) {
			p.NodeSelector = map[string]string{"kubernetes.io/os": "linux os"}
		},
		"a resource that is none": func(p *podtemplate.PodTemplate) {
			p.Resources = &corev1.ResourceRequirements{Limits: corev1.ResourceList{"gpu": resource.MustParse("1")}}
		},
		"a resource of the kubernetes.io domain": func(p *podtemplate.PodTemplate) {
			p.Resources = &corev1.ResourceRequirements{Limits: corev1.ResourceList{"kubernetes.io/gpu": resource.MustParse("1")}}
		},
		"a negative quantity": func(p *podtemplate.PodTemplate) {
			p.Resources = &corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("-1")},
			}
		},
		"a request above its limit": func(p *podtemplate.PodTemplate) {
			p.Resources = &corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("4Gi")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
			}
		},
		"an extended resource whose request isn't its limit": func(p *podtemplate.PodTemplate) {
			p.Resources = &corev1.ResourceRequirements{
				Requests: corev1.ResourceList{gpu: resource.MustParse("1")},
				Limits:   corev1.ResourceList{gpu: resource.MustParse("2")},
			}
		},
		"an extended resource that is requested without a limit": func(p *podtemplate.PodTemplate) {
			p.Resources.Requests[gpu] = resource.MustParse("1")
		},
		"a fraction of an extended resource": func(p *podtemplate.PodTemplate) {
			p.Resources.Limits[gpu] = resource.MustParse("500m")
		},
		"huge pages of a size that is no quantity": func(p *podtemplate.PodTemplate) {
			p.Resources.Limits["hugepages-large"] = resource.MustParse("64Mi")
		},
		"huge pages that are no whole number of pages": func(p *podtemplate.PodTemplate) {
			p.Resources.Limits["hugepages-2Mi"] = resource.MustParse("3Mi")
		},
		"huge pages without cpu or memory": func(p *podtemplate.PodTemplate) {
			p.Resources = &corev1.ResourceRequirements{Limits: corev1.ResourceList{"hugepages-2Mi": resource.MustParse("64Mi")}}
		},
		"a claim, which no pod's resources declare": func(p *podtemplate.PodTemplate) {
			p.Resources.Claims = []corev1.ResourceClaim{{Name: "gpu"}}
		},
		"a toleration key that is no qualified name": func(p *podtemplate.PodTemplate) {
			p.Tolerations = []corev1.Toleration{{Key: "dedicated pool", Operator: corev1.TolerationOpExists}}
		},
		"a toleration of every key that isn't Exists": func(p *podtemplate.PodTemplate) {
			p.Tolerations = []corev1.Toleration{{Operator: corev1.TolerationOpEqual, Value: taintValue}}
		},
		"a toleration that is Exists with a value": func(p *podtemplate.PodTemplate) {
			p.Tolerations = []corev1.Toleration{{Key: taintKey, Operator: corev1.TolerationOpExists, Value: taintValue}}
		},
		"a toleration value that is no label value": func(p *podtemplate.PodTemplate) {
			p.Tolerations = []corev1.Toleration{{Key: taintKey, Operator: corev1.TolerationOpEqual, Value: "scan pool"}}
		},
		"toleration seconds of an effect other than NoExecute": func(p *podtemplate.PodTemplate) {
			p.Tolerations = []corev1.Toleration{{
				Key: taintKey, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule,
				TolerationSeconds: ptr.To(int64(60)),
			}}
		},
		"a priority class that is no name": func(p *podtemplate.PodTemplate) { p.PriorityClassName = "Batch Low" },
		"a runtime class that is no name":  func(p *podtemplate.PodTemplate) { p.RuntimeClassName = ptr.To("g visor") },
	}
	for _, key := range confinementAnnotations {
		cases["the annotation "+key] = func(p *podtemplate.PodTemplate) {
			p.Annotations = map[string]string{key: "unconfined"}
		}
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			template := fullTemplate()
			change(&template)

			require.NotEmpty(t, template.Validate())
		})
	}
}

// A collector that doesn't validate its template still never loosens its pods with it.
func TestApplyNeverSetsAnAnnotationThatLoosensThePod(t *testing.T) {
	meta, spec := pod()
	template := fullTemplate()
	for _, key := range confinementAnnotations {
		template.Annotations[key] = "unconfined"
	}

	template.Apply(meta, spec, worker)

	for _, key := range confinementAnnotations {
		require.NotContains(t, meta.Annotations, key)
	}
	require.Contains(t, meta.Annotations, "cluster-autoscaler.kubernetes.io/safe-to-evict", "the other annotations stay")
}

func TestTheSchemaRefusesAnAnnotationThatLoosensThePod(t *testing.T) {
	schema := compileSchema(t)
	for _, key := range confinementAnnotations {
		require.Error(t, validate(t, schema, `{"annotations": {"`+key+`": "unconfined"}}`), key)
	}
	require.NoError(t, validate(t, schema, `{"annotations": {"example.com/apparmor-note": "x"}}`))
}
