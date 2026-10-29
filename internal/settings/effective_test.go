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

package settings_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/settings"
)

// newScheme knows the core API and the config API.
func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	return scheme
}

// newClient returns a fake client that holds objs. A fake client does not apply the defaults of
// a CRD schema.
func newClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(objs...).Build()
}

func operatorConfig(name string, spec configv1alpha1.OperatorConfigSpec) *configv1alpha1.OperatorConfig {
	return &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: spec}
}

func namespace(name, uid string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)}}
}

func TestLoadDefaultsWhenAbsent(t *testing.T) {
	eff, err := settings.Load(t.Context(), newClient(t))

	require.NoError(t, err)
	require.Equal(t, "local", eff.ClusterName)
	require.Nil(t, eff.Scope)
}

func TestLoadReadsSpec(t *testing.T) {
	scope := &configv1alpha1.Scope{
		ExcludeNamespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "team-a"}},
	}
	c := newClient(t, operatorConfig("default", configv1alpha1.OperatorConfigSpec{
		ClusterName: ptr.To("cluster-a"),
		Scope:       scope,
	}))

	eff, err := settings.Load(t.Context(), c)

	require.NoError(t, err)
	require.Equal(t, "cluster-a", eff.ClusterName)
	require.Equal(t, scope, eff.Scope)
}

// The API server fills in clusterName, but a client that skips the CRD schema, such as a fake
// client, can read an object without one. Load gives it the same default.
func TestLoadDefaultsAnEmptyClusterName(t *testing.T) {
	for name, clusterName := range map[string]*string{
		"unset": nil,
		"empty": ptr.To(""),
	} {
		t.Run(name, func(t *testing.T) {
			c := newClient(t, operatorConfig("default", configv1alpha1.OperatorConfigSpec{ClusterName: clusterName}))

			eff, err := settings.Load(t.Context(), c)

			require.NoError(t, err)
			require.Equal(t, "local", eff.ClusterName)
		})
	}
}

// Only the object named default counts: the API rejects any other name, so an object like this
// can't exist on a real cluster.
func TestLoadReadsOnlyTheDefaultObject(t *testing.T) {
	c := newClient(t, operatorConfig("other", configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To("cluster-b")}))

	eff, err := settings.Load(t.Context(), c)

	require.NoError(t, err)
	require.Equal(t, "local", eff.ClusterName)
}

// A failed read must not look like an absent object: the caller would run with the defaults
// while an admin's scope or cluster name is in force.
func TestLoadReturnsReadErrors(t *testing.T) {
	boom := errors.New("boom")
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return boom
			},
		}).Build()

	_, err := settings.Load(t.Context(), c)

	require.ErrorIs(t, err, boom)
}

func TestClusterIDIsKubeSystemUID(t *testing.T) {
	t.Run("is the UID of kube-system", func(t *testing.T) {
		c := newClient(t, namespace("kube-system", "u-1"), namespace("team-a", "u-2"))

		id, err := settings.ClusterID(t.Context(), c)

		require.NoError(t, err)
		require.Equal(t, "u-1", id)
	})

	t.Run("fails when kube-system is missing", func(t *testing.T) {
		c := newClient(t, namespace("team-a", "u-2"))

		id, err := settings.ClusterID(t.Context(), c)

		require.Error(t, err)
		require.Empty(t, id)
	})
}

// An empty ID would match every entry that has no ID, so it must never be handed out.
func TestClusterIDFailsWithoutUID(t *testing.T) {
	c := newClient(t, namespace("kube-system", ""))

	id, err := settings.ClusterID(t.Context(), c)

	require.Error(t, err)
	require.Empty(t, id)
}
