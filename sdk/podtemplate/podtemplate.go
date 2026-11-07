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

// Package podtemplate is the standard template of the pods that a collector creates itself, such as the scanner's
// scan Jobs or the sandbox's pods: one shape, which a collector takes in its settings, so that an admin sets the pull
// policy, the resources, where the pods run and their metadata the same way for every collector. The design of
// collectors, evidence and rules gives the reasons, in docs/design/2026-10-31-collectors-evidence-rules.md, sections
// 5.4 and 5.8.
//
// A template shapes what may differ between clusters, and nothing that keeps a pod isolated: it has no security
// context, no volumes and no service account, which stay the collector's, and it never sets the annotations that
// would set an AppArmor or seccomp profile. Validate checks a template as a collector checks its settings.
package podtemplate

import (
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// PodTemplate shapes the pods that a collector creates. Its fields are those of a pod, as Kubernetes names them, and
// each is left as the collector made it when the template leaves it out.
type PodTemplate struct {
	// ImagePullPolicy is the pull policy of the collector's container: IfNotPresent when it is empty.
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"` // IfNotPresent by default
	// Resources are the resources of the collector's container.
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// NodeSelector, Tolerations and Affinity say where the pods run.
	NodeSelector map[string]string   `json:"nodeSelector,omitempty"`
	Tolerations  []corev1.Toleration `json:"tolerations,omitempty"`
	Affinity     *corev1.Affinity    `json:"affinity,omitempty"`
	// PriorityClassName names the pods' PriorityClass, and RuntimeClassName their RuntimeClass, such as one that runs
	// them in a sandbox.
	PriorityClassName string  `json:"priorityClassName,omitempty"`
	RuntimeClassName  *string `json:"runtimeClassName,omitempty"`
	// Env holds environment variables for the collector's container, such as a proxy: at most 32, each with a value or
	// from a key of a Secret in the pod's namespace (decision 0037).
	Env []corev1.EnvVar `json:"env,omitempty"`
	// Labels and Annotations are added to the pods'.
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Apply shapes a pod that a collector made, with its metadata in meta and its spec in spec, as the template says. The
// container named container gets the pull policy, IfNotPresent when the template names none, the resources and the
// environment variables, none of which replaces a variable that the container has; a pod
// without such a container gets the rest. The template's labels and annotations are added, and never replace one that
// meta has: the collector's own labels say which pods are its own, and how it finds them again. An annotation that
// would set the AppArmor or seccomp profile of the pod or of a container is left out, as Validate refuses it, so that
// a template that wasn't validated still never loosens the pod. The pod gets copies, so a later change to the template
// doesn't reach it.
func (t PodTemplate) Apply(meta *metav1.ObjectMeta, spec *corev1.PodSpec, container string) {
	for i := range spec.Containers {
		if spec.Containers[i].Name != container {
			continue
		}
		c := &spec.Containers[i]
		c.ImagePullPolicy = t.ImagePullPolicy
		if c.ImagePullPolicy == "" {
			c.ImagePullPolicy = corev1.PullIfNotPresent
		}
		if t.Resources != nil {
			c.Resources = *t.Resources.DeepCopy()
		}
		c.Env = withEnv(c.Env, t.Env)
	}
	if len(t.NodeSelector) > 0 {
		spec.NodeSelector = maps.Clone(t.NodeSelector)
	}
	for _, toleration := range t.Tolerations {
		spec.Tolerations = append(spec.Tolerations, *toleration.DeepCopy())
	}
	if t.Affinity != nil {
		spec.Affinity = t.Affinity.DeepCopy()
	}
	if t.PriorityClassName != "" {
		spec.PriorityClassName = t.PriorityClassName
	}
	if t.RuntimeClassName != nil {
		spec.RuntimeClassName = ptr.To(*t.RuntimeClassName)
	}
	meta.Labels = withoutReplacing(meta.Labels, t.Labels)
	annotations := maps.Clone(t.Annotations)
	maps.DeleteFunc(annotations, func(key, _ string) bool { return loosens(key) })
	meta.Annotations = withoutReplacing(meta.Annotations, annotations)
}

// withEnv returns env with the variables of add whose names env doesn't have, as copies: the collector's own variables
// stay as they are, whether or not the template was validated.
func withEnv(env, add []corev1.EnvVar) []corev1.EnvVar {
	for _, variable := range add {
		if !slices.ContainsFunc(env, func(e corev1.EnvVar) bool { return e.Name == variable.Name }) {
			env = append(env, *variable.DeepCopy())
		}
	}
	return env
}

// withoutReplacing returns m with the entries of add whose keys m doesn't have. It returns m as it is when add is
// empty.
func withoutReplacing(m, add map[string]string) map[string]string {
	if len(add) == 0 {
		return m
	}
	if m == nil {
		m = make(map[string]string, len(add))
	}
	for key, value := range add {
		if _, set := m[key]; !set {
			m[key] = value
		}
	}
	return m
}

// Schema returns the JSON Schema of a PodTemplate, as a fragment that a collector puts into the schema of its
// settings, as the schema of one of their properties. It stands alone: it refers to nothing, not even to a part of
// itself, since a reference would resolve against the settings schema that holds it. It describes every field of
// PodTemplate under its JSON name, and refuses any other.
//
// It checks the shape and the values that a schema can check, such as the pattern of an environment variable's name
// and that it has a value or a Secret's key, not both, and refuses the annotations that would set an AppArmor
// or seccomp profile. A quantity of the resources is a string or a number, as Kubernetes reads one, and whether a
// string is a quantity is for the collector's own check of its settings, which decodes them: a decoding that fails
// names the field. Validate checks the rest.
func Schema() []byte {
	return []byte(schema)
}

// schema is what Schema returns.
const schema = `{
  "description": "The pods that the collector creates: pull policy, resources, placement, labels and annotations.",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "imagePullPolicy": {
      "description": "The pull policy of the pods' container. IfNotPresent when it is left out.",
      "enum": ["Always", "IfNotPresent", "Never"]
    },
    "resources": {
      "description": "The resources of the pods' container, as Kubernetes names them.",
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "limits": { "type": "object", "additionalProperties": { "type": ["string", "number"] } },
        "requests": { "type": "object", "additionalProperties": { "type": ["string", "number"] } },
        "claims": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["name"],
            "properties": {
              "name": { "type": "string", "minLength": 1 },
              "request": { "type": "string" }
            }
          }
        }
      }
    },
    "env": {
      "description": "Environment variables of the pods' container, such as a proxy: a value, or a key of a Secret.",
      "type": "array",
      "maxItems": 32,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["name"],
        "properties": {
          "name": { "type": "string", "minLength": 1, "maxLength": 253, "pattern": "^[-._a-zA-Z][-._a-zA-Z0-9]*$" },
          "value": { "type": "string" },
          "valueFrom": {
            "type": "object",
            "additionalProperties": false,
            "required": ["secretKeyRef"],
            "properties": {
              "secretKeyRef": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "key"],
                "properties": {
                  "name": { "type": "string", "minLength": 1, "maxLength": 253 },
                  "key": { "type": "string", "minLength": 1, "maxLength": 253 }
                }
              }
            }
          }
        },
        "oneOf": [{ "required": ["value"] }, { "required": ["valueFrom"] }]
      }
    },
    "nodeSelector": {
      "description": "The labels of the nodes that the pods run on.",
      "type": "object",
      "additionalProperties": { "type": "string" }
    },
    "tolerations": {
      "description": "The taints that the pods tolerate.",
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "key": { "type": "string" },
          "operator": { "enum": ["Exists", "Equal"] },
          "value": { "type": "string" },
          "effect": { "enum": ["NoSchedule", "PreferNoSchedule", "NoExecute"] },
          "tolerationSeconds": { "type": "integer" }
        }
      }
    },
    "affinity": {
      "description": "The pods' affinity, as Kubernetes defines it: nodeAffinity, podAffinity and podAntiAffinity.",
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "nodeAffinity": { "type": "object" },
        "podAffinity": { "type": "object" },
        "podAntiAffinity": { "type": "object" }
      }
    },
    "priorityClassName": {
      "description": "The PriorityClass of the pods.",
      "type": "string",
      "minLength": 1,
      "maxLength": 253
    },
    "runtimeClassName": {
      "description": "The RuntimeClass of the pods, such as one that runs them in a sandbox.",
      "type": "string",
      "minLength": 1,
      "maxLength": 253
    },
    "labels": {
      "description": "Labels to add to the pods'. A label that the collector sets itself stays as it is.",
      "type": "object",
      "additionalProperties": { "type": "string" }
    },
    "annotations": {
      "description": "Annotations to add to the pods'. An annotation that the collector sets itself stays as it is.",
      "type": "object",
      "propertyNames": {
        "description": "No annotation sets an AppArmor or seccomp profile: the confinement is the collector's.",
        "not": { "pattern": "^([^/]*\\.)?(apparmor\\.security\\.beta|seccomp\\.security\\.alpha)\\.kubernetes\\.io/" }
      },
      "additionalProperties": { "type": "string" }
    }
  }
}`
