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

package scan

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/bedag/vexplain/collectors/scanner/internal/pull"
	"github.com/bedag/vexplain/sdk/podtemplate"
)

// settings are the collector's settings, with the defaults filled in.
type settings struct {
	MaxConcurrentScans int32            `json:"maxConcurrentScans,omitempty"`
	ScanTimeoutSeconds int32            `json:"scanTimeoutSeconds,omitempty"`
	WorkspaceMebibytes int32            `json:"workspaceMebibytes,omitempty"`
	RegistryMirrors    []registryMirror `json:"registryMirrors,omitempty"`
	// AdminPullSecrets names the Secrets in the operator's namespace whose logins a scan tries after the workload's.
	AdminPullSecrets []string                 `json:"adminPullSecrets,omitempty"`
	ScanPod          *podtemplate.PodTemplate `json:"scanPod,omitempty"`
}

// registryMirror is a mirror to pull the images of a registry from.
type registryMirror struct {
	Host string `json:"host"`
	URL  string `json:"url"`
}

// defaultScanMemory is the memory that a scan pod requests, and its limit, when the settings name no memory.
var defaultScanMemory = resource.MustParse("2Gi")

// ValidateSettings checks what the settings' schema can't: that they decode, quantities included, that each mirror is
// a registry and a URL that a scan pulls from, for a registry of its own, and that the scan pod's template, with the
// default memory, is one that Kubernetes takes and that loosens nothing, as podtemplate's Validate checks it. A
// template that every scan Job would fail with is a problem of the settings, and not a failure of each image. And it
// refuses a memory request or limit of 0, which would leave a scan pod with no memory limit.
func (s *Scanner) ValidateSettings(raw json.RawMessage) []string {
	_, problems := s.settingsOf(raw)
	return problems
}

// settingsOf reads the settings, which passed their schema, with the defaults for what they leave out, and returns
// what is wrong with them. A variable in scanPod's env that the collector sets itself is one of the problems.
func (s *Scanner) settingsOf(raw json.RawMessage) (settings, []string) {
	set := settings{MaxConcurrentScans: 4, ScanTimeoutSeconds: 1800, WorkspaceMebibytes: 10240}
	if len(bytes.TrimSpace(raw)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&set); err != nil {
			// The settings are the admin's own, so the decoder's error may name what it couldn't read.
			return settings{}, []string{"the settings can't be read: " + err.Error()}
		}
	}
	var problems []string
	hosts := map[string]bool{}
	for i, mirror := range set.RegistryMirrors {
		from, _, err := pull.ParseMirror(mirror.Host, mirror.URL)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("registryMirrors[%d]: %v", i, err))
		case hosts[from.RegistryStr()]:
			problems = append(problems, fmt.Sprintf("registryMirrors[%d]: a registry has one mirror at most", i))
		default:
			hosts[from.RegistryStr()] = true
		}
	}
	for _, problem := range set.template().Validate(reservedEnv...) {
		problems = append(problems, "scanPod."+problem)
	}
	if set.ScanPod != nil {
		problems = append(problems, zeroMemory(set.ScanPod.Resources)...)
	}
	return set, problems
}

// pullFrom returns the repository that a scan pulls from: repository, or the same path on the mirror that the settings
// give its registry, as the scan's --registry-mirror makes it. A scan's logins are those of the registry that it pulls
// from, so that a registry's never reach its mirror.
func (set settings) pullFrom(repository string) (name.Repository, error) {
	repo, err := name.NewRepository(repository)
	if err != nil {
		return name.Repository{}, fmt.Errorf("pull the image from %q: it isn't a repository", repository)
	}
	for _, mirror := range set.RegistryMirrors {
		// settingsOf has checked each mirror.
		from, to, err := pull.ParseMirror(mirror.Host, mirror.URL)
		if err == nil && from.RegistryStr() == repo.RegistryStr() {
			return to.Repo(repo.RepositoryStr()), nil
		}
	}
	return repo, nil
}

// reservedEnv are the names of the variables that the scanner sets on a scan pod itself, which scanPod's env must not
// set: the location of the credentials, which the SDK's Job sets. It is fixed in code, so that the settings are valid
// or not whatever the scanner's own environment is. The proxy variables are not among them: scanPod's env is the only
// source of a scan pod's proxy (decision 0037).
var reservedEnv = []string{"DOCKER_CONFIG"}

// zeroMemory returns the problems of a memory request or limit of 0 in r, the resources that the settings give the
// scan pod. Kubernetes takes either, but a limit of 0 means no memory limit, and a request alone is the limit too
// (see template), so either would let a scan pod run without one (decision 0022: each scan Job has its own limits).
// A request of 0 below a limit is refused as well: a scan pod reserves the memory that it needs. A negative quantity
// is podtemplate's Validate's.
func zeroMemory(r *corev1.ResourceRequirements) []string {
	if r == nil {
		return nil
	}
	var problems []string
	resources := field.NewPath("scanPod", "resources")
	if limit, ok := r.Limits[corev1.ResourceMemory]; ok && limit.IsZero() {
		problems = append(problems, field.Invalid(resources.Child("limits").Key(string(corev1.ResourceMemory)),
			limit.String(), "must be more than 0: a limit of 0 means no memory limit, and every scan pod has one").Error())
	}
	if request, ok := r.Requests[corev1.ResourceMemory]; ok && request.IsZero() {
		problems = append(problems, field.Invalid(resources.Child("requests").Key(string(corev1.ResourceMemory)),
			request.String(), "must be more than 0: a scan pod reserves the memory that it needs, and a request "+
				"alone is its limit too, where 0 means no memory limit").Error())
	}
	return problems
}

// template returns the pod template of the scan Jobs: scanPod, whose resources add to the default ones. Memory keeps
// its default request and limit unless scanPod names memory, so that every scan pod has a memory limit (decision 0022):
// a memory request alone is the limit too, and a memory limit alone is the request too, as Kubernetes makes it. The
// settings refuse a memory request or limit of 0 (zeroMemory), which would make a limit of 0, that is none.
func (set settings) template() podtemplate.PodTemplate {
	var t podtemplate.PodTemplate
	if set.ScanPod != nil {
		t = *set.ScanPod
	}
	var r corev1.ResourceRequirements
	if t.Resources != nil {
		r = *t.Resources.DeepCopy()
	}
	request, requested := r.Requests[corev1.ResourceMemory]
	_, limited := r.Limits[corev1.ResourceMemory]
	switch {
	case !requested && !limited:
		r.Requests = withQuantity(r.Requests, corev1.ResourceMemory, defaultScanMemory)
		r.Limits = withQuantity(r.Limits, corev1.ResourceMemory, defaultScanMemory)
	case !limited:
		r.Limits = withQuantity(r.Limits, corev1.ResourceMemory, request)
	}
	t.Resources = &r
	return t
}

// withQuantity returns list with a copy of quantity for the resource, in a new list when list is nil.
func withQuantity(list corev1.ResourceList, resourceName corev1.ResourceName,
	quantity resource.Quantity) corev1.ResourceList {
	if list == nil {
		list = corev1.ResourceList{}
	}
	list[resourceName] = quantity.DeepCopy()
	return list
}
