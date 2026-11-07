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
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/bedag/vexplain/sdk/podtemplate"
)

const (
	// proxyVariable is a variable that the tests' templates set, credentials the location of the pods' credentials, and
	// firstName and firstSource the places of the first variable's name and source in a problem.
	proxyVariable = "HTTPS_PROXY"
	credentials   = "/creds"
	proxyURL      = "http://proxy.example:3128"
	// credentialsVariable is the variable that the collector sets itself.
	credentialsVariable = "DOCKER_CONFIG"
	renamed             = "renamed"
	firstName           = "env[0].name"
	firstSource         = "env[0].valueFrom"
)

// secretEnv returns a variable that comes from a key of a Secret in the pod's namespace.
func secretEnv(name, secret, key string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: secret}, Key: key,
	}}}
}

// proxyEnv is a proxy, as a template gives it: one variable with a value, and one from a Secret.
func proxyEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: proxyVariable, Value: proxyURL},
		secretEnv("NO_PROXY", "proxy-settings", "no-proxy"),
	}
}

func TestApplyGivesTheNamedContainerTheEnvironment(t *testing.T) {
	meta, spec := pod()
	spec.Containers[1].Env = []corev1.EnvVar{{Name: credentialsVariable, Value: credentials}}

	podtemplate.PodTemplate{Env: proxyEnv()}.Apply(meta, spec, worker)

	want := append([]corev1.EnvVar{{Name: credentialsVariable, Value: credentials}}, proxyEnv()...)
	require.Equal(t, want, spec.Containers[1].Env)
	require.Empty(t, spec.Containers[0].Env, "the other container keeps what it had")
}

// The collector's own variables stay as they are, even for a template that wasn't validated.
func TestApplyNeverReplacesAVariableThatTheContainerHas(t *testing.T) {
	meta, spec := pod()
	spec.Containers[1].Env = []corev1.EnvVar{{Name: credentialsVariable, Value: credentials}}

	podtemplate.PodTemplate{Env: []corev1.EnvVar{
		{Name: credentialsVariable, Value: "/elsewhere"}, {Name: proxyVariable, Value: proxyURL},
	}}.Apply(meta, spec, worker)

	require.Equal(t, []corev1.EnvVar{
		{Name: credentialsVariable, Value: credentials}, {Name: proxyVariable, Value: proxyURL},
	}, spec.Containers[1].Env)
}

func TestApplyCopiesTheEnvironment(t *testing.T) {
	meta, spec := pod()
	template := podtemplate.PodTemplate{Env: proxyEnv()}

	template.Apply(meta, spec, worker)
	template.Env[1].ValueFrom.SecretKeyRef.Name = renamed

	require.Equal(t, "proxy-settings", spec.Containers[1].Env[1].ValueFrom.SecretKeyRef.Name)
}

func TestValidateAcceptsTheEnvironment(t *testing.T) {
	env := append(proxyEnv(), corev1.EnvVar{Name: "empty"}, corev1.EnvVar{Name: "_a-b.C9"})
	template := podtemplate.PodTemplate{Env: env}
	require.Empty(t, template.Validate(credentialsVariable))

	many := podtemplate.PodTemplate{}
	for i := range 32 {
		many.Env = append(many.Env, corev1.EnvVar{Name: fmt.Sprintf("VAR_%d", i), Value: "x"})
	}
	require.Empty(t, many.Validate())
}

func TestValidateRefusesAnEnvironmentThatNoPodTakes(t *testing.T) {
	tooMany := make([]corev1.EnvVar, 33)
	for i := range tooMany {
		tooMany[i] = corev1.EnvVar{Name: fmt.Sprintf("VAR_%d", i), Value: "x"}
	}
	cases := map[string]struct {
		env  []corev1.EnvVar
		want string
	}{
		"more than 32 entries":            {tooMany, "env"},
		"a name with a space":             {[]corev1.EnvVar{{Name: "A B", Value: "x"}}, firstName},
		"a name that starts with a digit": {[]corev1.EnvVar{{Name: "1A", Value: "x"}}, firstName},
		"an empty name":                   {[]corev1.EnvVar{{Value: "x"}}, firstName},
		"a name twice":                    {[]corev1.EnvVar{{Name: "A", Value: "x"}, {Name: "A", Value: "y"}}, "env[1].name"},
		"a name that the collector sets":  {[]corev1.EnvVar{{Name: credentialsVariable, Value: "/x"}}, firstName},
		"a value and a source": {[]corev1.EnvVar{
			{Name: "A", Value: "x", ValueFrom: secretEnv("A", "s", "k").ValueFrom},
		}, "env[0]"},
		"a field reference": {[]corev1.EnvVar{{Name: "A", ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
		}}}, firstSource},
		"a config map key": {[]corev1.EnvVar{{Name: "A", ValueFrom: &corev1.EnvVarSource{
			ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "c"}, Key: "k",
			},
		}}}, firstSource},
		"a source without a secret": {[]corev1.EnvVar{{Name: "A", ValueFrom: &corev1.EnvVarSource{}}}, firstSource},
		"a secret without a name":   {[]corev1.EnvVar{secretEnv("A", "", "k")}, "env[0].valueFrom.secretKeyRef.name"},
		"a secret name that is none": {
			[]corev1.EnvVar{secretEnv("A", "Not A Name", "k")}, firstSource + ".secretKeyRef.name",
		},
		"a key without a name": {[]corev1.EnvVar{secretEnv("A", "s", "")}, "env[0].valueFrom.secretKeyRef.key"},
		"a key that is none":   {[]corev1.EnvVar{secretEnv("A", "s", "a/b")}, "env[0].valueFrom.secretKeyRef.key"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			problems := podtemplate.PodTemplate{Env: c.env}.Validate(credentialsVariable)

			require.NotEmpty(t, problems)
			require.Contains(t, strings.Join(problems, "\n"), c.want)
		})
	}
}

// A problem names a variable and why, and never the value of one: a value may be a credential.
func TestValidateNeverRepeatsAValue(t *testing.T) {
	problems := podtemplate.PodTemplate{Env: []corev1.EnvVar{
		{Name: "A B", Value: "http://user:hunter2@proxy.example:3128"},
		{Name: "C", Value: "hunter2", ValueFrom: secretEnv("C", "s", "k").ValueFrom},
	}}.Validate()

	require.NotEmpty(t, problems)
	require.NotContains(t, strings.Join(problems, "\n"), "hunter2")
}

func TestTheSchemaTakesTheEnvironment(t *testing.T) {
	schema := compileSchema(t)
	raw, err := json.Marshal(podtemplate.PodTemplate{Env: proxyEnv()})
	require.NoError(t, err)

	require.NoError(t, validate(t, schema, string(raw)))
	require.NoError(t, validate(t, schema, `{"env": [{"name": "A", "value": ""}]}`))
}

func TestTheSchemaRefusesAnEnvironmentThatNoPodTakes(t *testing.T) {
	schema := compileSchema(t)
	many := make([]string, 0, 33)
	for i := range 33 {
		many = append(many, fmt.Sprintf(`{"name": "V%d", "value": "x"}`, i))
	}
	for name, template := range map[string]string{
		"more than 32 entries":     `{"env": [` + strings.Join(many, ",") + `]}`,
		"a name with a space":      `{"env": [{"name": "A B", "value": "x"}]}`,
		"no name":                  `{"env": [{"value": "x"}]}`,
		"neither value nor source": `{"env": [{"name": "A"}]}`,
		"both value and source": `{"env": [{"name": "A", "value": "x",
			"valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]}`,
		"a field reference":      `{"env": [{"name": "A", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}]}`,
		"a config map key":       `{"env": [{"name": "A", "valueFrom": {"configMapKeyRef": {"name": "c", "key": "k"}}}]}`,
		"a secret without a key": `{"env": [{"name": "A", "valueFrom": {"secretKeyRef": {"name": "s"}}}]}`,
		"a secret's optional": `{"env": [{"name": "A", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k",
			"optional": true}}}]}`,
		"an unknown field": `{"env": [{"name": "A", "value": "x", "extra": 1}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validate(t, schema, template))
		})
	}
}
