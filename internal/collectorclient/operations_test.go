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

package collectorclient_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
)

func TestMaxAge(t *testing.T) {
	t.Parallel()
	const (
		eventType = "com.example.hello.v1alpha1"
		noDefault = "com.example.none.v1alpha1"
	)
	declared := &configv1alpha1.Collector{Status: configv1alpha1.CollectorStatus{
		Capabilities: &configv1alpha1.CollectorCapabilities{Produces: []configv1alpha1.ProducedType{
			{Type: eventType, MaxAgeSeconds: ptr.To[int64](3600)}, {Type: noDefault},
		}},
	}}
	overridden := declared.DeepCopy()
	overridden.Spec.Produces = []configv1alpha1.ProducedTypeOverride{
		{Type: eventType, MaxAgeSeconds: 120}, {Type: noDefault, MaxAgeSeconds: 60},
	}

	require.Equal(t, 2*time.Minute, collectorclient.MaxAge(overridden, eventType), "the override")
	require.Equal(t, time.Hour, collectorclient.MaxAge(declared, eventType), "the declared default")
	require.Equal(t, time.Minute, collectorclient.MaxAge(overridden, noDefault), "an override of a type with no default")
	require.Zero(t, collectorclient.MaxAge(declared, noDefault), "none")
	require.Zero(t, collectorclient.MaxAge(declared, "com.example.unknown.v1alpha1"), "an unknown type")
	require.Zero(t, collectorclient.MaxAge(&configv1alpha1.Collector{}, eventType), "no capabilities")
}

func TestEntryPointSource(t *testing.T) {
	t.Parallel()
	const eventType = "com.example.hosts.v1alpha1"
	collectorWith := func(change func(*configv1alpha1.CollectorOperation)) *configv1alpha1.Collector {
		op := configv1alpha1.CollectorOperation{
			Name: "list", Role: ptr.To(configv1alpha1.CollectorRoleHub), Produces: []string{eventType}, Parameters: []string{"hosts"},
		}
		change(&op)
		return &configv1alpha1.Collector{Status: configv1alpha1.CollectorStatus{
			Capabilities: &configv1alpha1.CollectorCapabilities{Operations: []configv1alpha1.CollectorOperation{op}},
		}}
	}

	name, hosts, addresses := collectorclient.EntryPointSource(collectorWith(func(*configv1alpha1.CollectorOperation) {}), eventType)
	require.Equal(t, "list", name)
	require.True(t, hosts)
	require.False(t, addresses)

	name, hosts, addresses = collectorclient.EntryPointSource(collectorWith(func(op *configv1alpha1.CollectorOperation) {
		op.Parameters = []string{"addresses", "hosts"}
	}), eventType)
	require.Equal(t, "list", name)
	require.True(t, hosts)
	require.True(t, addresses)

	for why, change := range map[string]func(*configv1alpha1.CollectorOperation){
		"the spoke role": func(op *configv1alpha1.CollectorOperation) { op.Role = ptr.To(configv1alpha1.CollectorRoleSpoke) },
		"no role":        func(op *configv1alpha1.CollectorOperation) { op.Role = nil },
		"consumes":       func(op *configv1alpha1.CollectorOperation) { op.Consumes = []string{"com.example.in.v1alpha1"} },
		"repositories":   func(op *configv1alpha1.CollectorOperation) { op.Parameters = []string{"repositories"} },
		"another type":   func(op *configv1alpha1.CollectorOperation) { op.Produces = []string{"com.example.other.v1alpha1"} },
	} {
		name, hosts, addresses = collectorclient.EntryPointSource(collectorWith(change), eventType)
		require.Empty(t, name, why)
		require.False(t, hosts || addresses, why)
	}
	name, _, _ = collectorclient.EntryPointSource(&configv1alpha1.Collector{}, eventType)
	require.Empty(t, name, "no capabilities")
}
