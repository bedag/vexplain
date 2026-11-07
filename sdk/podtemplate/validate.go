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

package podtemplate

import (
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// confinementDomains are the domains of the annotations that set the AppArmor or seccomp profile of a pod or of one of
// its containers, such as container.apparmor.security.beta.kubernetes.io/<container> and
// seccomp.security.alpha.kubernetes.io/pod. Kubernetes still takes such an annotation for a profile that the pod's
// fields leave out, as a collector's pods leave out AppArmor's: unconfined would then take effect.
var confinementDomains = []string{"apparmor.security.beta.kubernetes.io", "seccomp.security.alpha.kubernetes.io"}

// loosens reports whether an annotation of the key can set the AppArmor or seccomp profile of a pod or of one of its
// containers: whether its prefix is one of confinementDomains, or a subdomain of one, in any case.
func loosens(key string) bool {
	prefix, _, found := strings.Cut(strings.ToLower(key), "/")
	if !found {
		return false
	}
	for _, domain := range confinementDomains {
		if prefix == domain || strings.HasSuffix(prefix, "."+domain) {
			return true
		}
	}
	return false
}

// Validate returns what is wrong with the template, each problem as a text that names its field, in a stable order,
// and none when nothing is. A collector checks its template with it when it checks its settings, so that a template
// that no pod could take is a problem of the settings, reported once, and not a failure of each pod as it is created.
//
// It refuses an annotation that would set the AppArmor or seccomp profile of the pod or of a container, which would
// loosen the pod's confinement. And it refuses what Kubernetes would refuse in a pod, and a schema can't check: keys
// and values of the labels, the annotations and the node selector; a resource that a container can't have, a negative
// quantity, a part of a resource that is counted whole, a request above its limit, and a claim, since a template
// declares no claim for a container to use; a toleration that Kubernetes refuses; and the names of the PriorityClass
// and the RuntimeClass. It doesn't check the affinity, whose rules are many: a pod whose affinity Kubernetes refuses
// fails as it is created.
//
// The environment is checked too: at most 32 variables, with names that are environment-variable names, each once,
// none that the collector sets itself, which the collector passes as reserved, and each with a value or a key of a
// Secret and nothing else. A problem names the variable's place and never a value.
func (t PodTemplate) Validate(reserved ...string) []string {
	errs := metav1validation.ValidateLabels(t.Labels, field.NewPath("labels"))
	annotations := field.NewPath("annotations")
	errs = append(errs, apivalidation.ValidateAnnotations(t.Annotations, annotations)...)
	for key := range t.Annotations {
		if loosens(key) {
			errs = append(errs, field.Forbidden(annotations.Key(key),
				"sets an AppArmor or seccomp profile: the confinement of the pods is the collector's"))
		}
	}
	errs = append(errs, metav1validation.ValidateLabels(t.NodeSelector, field.NewPath("nodeSelector"))...)
	errs = append(errs, validateEnv(t.Env, reserved, field.NewPath("env"))...)
	errs = append(errs, validateResources(t.Resources, field.NewPath("resources"))...)
	errs = append(errs, validateTolerations(t.Tolerations, field.NewPath("tolerations"))...)
	if t.PriorityClassName != "" {
		errs = append(errs, validateName(t.PriorityClassName, field.NewPath("priorityClassName"))...)
	}
	if t.RuntimeClassName != nil {
		errs = append(errs, validateName(*t.RuntimeClassName, field.NewPath("runtimeClassName"))...)
	}
	problems := make([]string, 0, len(errs))
	for _, err := range errs {
		problems = append(problems, err.Error())
	}
	slices.Sort(problems)
	return problems
}

// maxEnv is how many environment variables a template holds.
const maxEnv = 32

// validateEnv returns what is wrong with env, the environment of a template, at path. A problem never repeats a
// value: it may be a credential.
func validateEnv(env []corev1.EnvVar, reserved []string, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	if len(env) > maxEnv {
		errs = append(errs, field.TooMany(path, len(env), maxEnv))
	}
	seen := make(map[string]bool, len(env))
	for i, variable := range env {
		at := path.Index(i)
		name := at.Child("name")
		for _, msg := range validation.IsEnvVarName(variable.Name) {
			errs = append(errs, field.Invalid(name, variable.Name, msg))
		}
		switch {
		case variable.Name == "":
			errs = append(errs, field.Required(name, "a variable has a name"))
		case seen[variable.Name]:
			errs = append(errs, field.Duplicate(name, variable.Name))
		case slices.Contains(reserved, variable.Name):
			errs = append(errs, field.Forbidden(name, "the collector sets "+variable.Name+" itself"))
		}
		seen[variable.Name] = true
		if variable.ValueFrom == nil {
			continue
		}
		if variable.Value != "" {
			errs = append(errs, field.Forbidden(at, "has a value and valueFrom: only one"))
		}
		errs = append(errs, validateEnvSource(variable.ValueFrom, at.Child("valueFrom"))...)
	}
	return errs
}

// validateEnvSource returns what is wrong with source, where a variable comes from, at path: anything other than a
// key of a Secret, which names the Secret as a DNS-1123 subdomain and the key as a Secret's key.
func validateEnvSource(source *corev1.EnvVarSource, path *field.Path) field.ErrorList {
	if source.SecretKeyRef == nil {
		return field.ErrorList{field.Required(path.Child("secretKeyRef"), "the only source is a key of a Secret")}
	}
	var errs field.ErrorList
	if source.FieldRef != nil || source.ResourceFieldRef != nil || source.ConfigMapKeyRef != nil ||
		source.FileKeyRef != nil {
		errs = append(errs, field.Forbidden(path, "the only source is a key of a Secret"))
	}
	ref, at := source.SecretKeyRef, path.Child("secretKeyRef")
	if ref.Optional != nil {
		errs = append(errs, field.Forbidden(at.Child("optional"), "a missing Secret fails the pod"))
	}
	if ref.Name == "" {
		errs = append(errs, field.Required(at.Child("name"), "names the Secret"))
	} else {
		errs = append(errs, validateName(ref.Name, at.Child("name"))...)
	}
	if ref.Key == "" {
		errs = append(errs, field.Required(at.Child("key"), "names the key of the Secret"))
	}
	for _, msg := range validation.IsConfigMapKey(ref.Key) {
		if ref.Key != "" {
			errs = append(errs, field.Invalid(at.Child("key"), ref.Key, msg))
		}
	}
	return errs
}

// validateName returns why name, at path, isn't the name of an object that Kubernetes names with a DNS-1123
// subdomain, as it names a PriorityClass or a RuntimeClass.
func validateName(name string, path *field.Path) field.ErrorList {
	msgs := validation.IsDNS1123Subdomain(name)
	errs := make(field.ErrorList, 0, len(msgs))
	for _, msg := range msgs {
		errs = append(errs, field.Invalid(path, name, msg))
	}
	return errs
}

// validateResources returns what Kubernetes would refuse in r, the resources of a container, at path: a resource that
// a container can't have, a quantity that it can't have of one, a request above its limit, or of a resource that
// can't be overcommitted, a request that isn't its limit; huge pages without cpu or memory; and a claim.
func validateResources(r *corev1.ResourceRequirements, path *field.Path) field.ErrorList {
	if r == nil {
		return nil
	}
	var errs field.ErrorList
	limits, requests := path.Child("limits"), path.Child("requests")
	for name, quantity := range r.Limits {
		errs = append(errs, validateQuantity(name, quantity, limits.Key(string(name)))...)
	}
	for name, quantity := range r.Requests {
		at := requests.Key(string(name))
		errs = append(errs, validateQuantity(name, quantity, at)...)
		limit, limited := r.Limits[name]
		switch {
		case !limited && !overcommitted(name):
			errs = append(errs, field.Required(limits.Key(string(name)),
				"a resource that can't be overcommitted needs a limit"))
		case limited && !overcommitted(name) && quantity.Cmp(limit) != 0:
			errs = append(errs, field.Invalid(at, quantity.String(),
				"must be the limit, "+limit.String()+": the resource can't be overcommitted"))
		case limited && quantity.Cmp(limit) > 0:
			errs = append(errs, field.Invalid(at, quantity.String(), "must be at most the limit, "+limit.String()))
		}
	}
	if (hugePages(r.Limits) || hugePages(r.Requests)) && !cpuOrMemory(r.Limits) && !cpuOrMemory(r.Requests) {
		errs = append(errs, field.Forbidden(path, "huge pages need cpu or memory"))
	}
	if len(r.Claims) > 0 {
		errs = append(errs, field.Forbidden(path.Child("claims"), "a template declares no claim for a container to use"))
	}
	return errs
}

// validateQuantity returns what Kubernetes would refuse in quantity of the resource name of a container, at path: a
// name that is no resource of a container, a negative quantity, a part of an extended resource, and huge pages that
// are no whole number of pages of the size that their name gives.
func validateQuantity(name corev1.ResourceName, quantity resource.Quantity, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	if quantity.Sign() < 0 {
		errs = append(errs, field.Invalid(path, quantity.String(), "must not be negative"))
	}
	switch {
	case name == corev1.ResourceCPU || name == corev1.ResourceMemory || name == corev1.ResourceEphemeralStorage:
	case strings.HasPrefix(string(name), corev1.ResourceHugePagesPrefix):
		size, err := resource.ParseQuantity(strings.TrimPrefix(string(name), corev1.ResourceHugePagesPrefix))
		if err != nil || size.Sign() <= 0 || size.MilliValue()%1000 != 0 || quantity.Value()%size.Value() != 0 {
			errs = append(errs, field.Invalid(path, quantity.String(),
				"must be a whole number of pages, of the size that the resource's name gives"))
		}
	case extended(name):
		if quantity.MilliValue()%1000 != 0 {
			errs = append(errs, field.Invalid(path, quantity.String(), "must be whole: an extended resource counts units"))
		}
	default:
		errs = append(errs, field.Invalid(path, string(name), "is no resource of a container: cpu, memory, "+
			"ephemeral-storage, hugepages-<size>, or an extended resource, a qualified name outside kubernetes.io"))
	}
	return errs
}

// extended reports whether name is that of an extended resource, as Kubernetes defines one: a qualified name with a
// domain outside kubernetes.io, which a quota can name with the prefix requests.
func extended(name corev1.ResourceName) bool {
	s := string(name)
	return strings.Contains(s, "/") && !strings.Contains(s, "kubernetes.io/") &&
		!strings.HasPrefix(s, corev1.DefaultResourceRequestsPrefix) &&
		len(validation.IsQualifiedName(corev1.DefaultResourceRequestsPrefix+s)) == 0
}

// overcommitted reports whether a request of the resource name may be less than its limit: whether it is cpu, memory
// or ephemeral storage, and not huge pages or an extended resource.
func overcommitted(name corev1.ResourceName) bool {
	return name == corev1.ResourceCPU || name == corev1.ResourceMemory || name == corev1.ResourceEphemeralStorage
}

// hugePages reports whether list has huge pages, and cpuOrMemory whether it has cpu or memory.
func hugePages(list corev1.ResourceList) bool {
	for name := range list {
		if strings.HasPrefix(string(name), corev1.ResourceHugePagesPrefix) {
			return true
		}
	}
	return false
}

func cpuOrMemory(list corev1.ResourceList) bool {
	_, cpu := list[corev1.ResourceCPU]
	_, memory := list[corev1.ResourceMemory]
	return cpu || memory
}

// validateTolerations returns what Kubernetes would refuse in the tolerations at path: a key that is no label name, a
// toleration of every key whose operator isn't Exists, a value with Exists, a value that is no label value, and
// tolerationSeconds of an effect other than NoExecute. The schema checks the operators and the effects.
func validateTolerations(tolerations []corev1.Toleration, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	for i, toleration := range tolerations {
		at := path.Index(i)
		if toleration.Key != "" {
			errs = append(errs, metav1validation.ValidateLabelName(toleration.Key, at.Child("key"))...)
		}
		if toleration.Operator == corev1.TolerationOpExists {
			if toleration.Value != "" {
				errs = append(errs, field.Invalid(at.Child("value"), toleration.Value, "must be empty with the operator Exists"))
			}
		} else {
			if toleration.Key == "" {
				errs = append(errs, field.Invalid(at.Child("operator"), toleration.Operator,
					"must be Exists for a toleration of every key"))
			}
			for _, msg := range validation.IsValidLabelValue(toleration.Value) {
				errs = append(errs, field.Invalid(at.Child("value"), toleration.Value, msg))
			}
		}
		if toleration.TolerationSeconds != nil && toleration.Effect != corev1.TaintEffectNoExecute {
			errs = append(errs, field.Invalid(at.Child("effect"), toleration.Effect,
				"must be NoExecute with tolerationSeconds"))
		}
	}
	return errs
}
