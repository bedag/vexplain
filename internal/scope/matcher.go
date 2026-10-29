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

// Package scope decides which pods are analysed.
//
// An OperatorConfig narrows the analysis with label selectors on namespaces and on pods. New
// parses them into a Matcher, which answers for one pod at a time from the labels it is given.
// The Matcher reads no objects itself.
package scope

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// Matcher says whether a pod is in scope. Create it with New. It does not change afterwards, so
// it is safe for concurrent use.
type Matcher struct {
	namespaces filter
	pods       filter
}

// New builds a Matcher from s. A nil s limits nothing, and so does an absent selector: an absent
// include selects every object and an absent exclude removes none. An empty include selects every
// object too.
//
// An empty exclude keeps its Kubernetes meaning and removes every object. The API server rejects
// it, so this only happens when a client skips the CRD schema.
//
// New fails on the first selector that does not parse, in the order of the fields of Scope. The
// error names the field by its JSON name and wraps the parse error.
func New(s *configv1alpha1.Scope) (*Matcher, error) {
	if s == nil {
		s = &configv1alpha1.Scope{}
	}
	includeNamespaces, err := parse("includeNamespaces", s.IncludeNamespaces, labels.Everything())
	if err != nil {
		return nil, err
	}
	excludeNamespaces, err := parse("excludeNamespaces", s.ExcludeNamespaces, labels.Nothing())
	if err != nil {
		return nil, err
	}
	includePods, err := parse("includePods", s.IncludePods, labels.Everything())
	if err != nil {
		return nil, err
	}
	excludePods, err := parse("excludePods", s.ExcludePods, labels.Nothing())
	if err != nil {
		return nil, err
	}
	return &Matcher{
		namespaces: filter{include: includeNamespaces, exclude: excludeNamespaces},
		pods:       filter{include: includePods, exclude: excludePods},
	}, nil
}

// Matches reports whether a pod is in scope, given the labels of its namespace and the labels of
// the pod. A nil map is a namespace or a pod without labels. The pod is in scope when its
// namespace passes the namespace selectors and the pod passes the pod selectors.
func (m *Matcher) Matches(nsLabels, podLabels map[string]string) bool {
	return m.namespaces.allows(nsLabels) && m.pods.allows(podLabels)
}

// filter is the include selector and the exclude selector for one kind of object. Neither is nil:
// New turns an absent selector into one that includes everything or excludes nothing.
type filter struct {
	include labels.Selector
	exclude labels.Selector
}

// allows reports whether an object with these labels passes the filter: the include selector
// selects it and the exclude selector does not. The exclude wins, so an object that both
// selectors match is out.
func (f filter) allows(objectLabels map[string]string) bool {
	set := labels.Set(objectLabels)
	return !f.exclude.Matches(set) && f.include.Matches(set)
}

// parse turns the selector in the named field into a labels.Selector, or returns whenAbsent when
// the selector is nil. The caller says what absence means, because
// metav1.LabelSelectorAsSelector reads a nil selector as one that matches nothing. That suits an
// exclude, but it would turn an absent include into one that selects no pod at all.
func parse(field string, selector *metav1.LabelSelector, whenAbsent labels.Selector) (labels.Selector, error) {
	if selector == nil {
		return whenAbsent, nil
	}
	parsed, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return parsed, nil
}
