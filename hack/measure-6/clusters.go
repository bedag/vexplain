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

package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/hack/internal/localcluster"
	"github.com/bedag/vexplain/internal/settings"
)

// cluster is one of the three kind clusters.
type cluster struct {
	// kind is the name of the kind cluster, whose node is the container <kind>-control-plane.
	kind       string
	kubeconfig string
	api        client.Client
	clientset  *kubernetes.Clientset
}

// connect returns the cluster of the kubeconfig, which localcluster checks first, and refuses unless it is a local kind
// cluster's own.
func connect(kubeconfig string, scheme *runtime.Scheme) (*cluster, error) {
	var cfg *rest.Config
	api, err := localcluster.ConnectTo(kubeconfig, scheme, func(c *rest.Config) {
		// The tool lists every record of the hub every few seconds while it waits.
		c.QPS, c.Burst = 50, 100
		cfg = rest.CopyConfig(c)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kubeconfig, err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	// localcluster made sure that the current context is kind's, kind-<cluster>.
	raw, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		return nil, err
	}
	return &cluster{kind: strings.TrimPrefix(raw.CurrentContext, "kind-"), kubeconfig: kubeconfig, api: api,
		clientset: clientset}, nil
}

// node is the container of the cluster's one node.
func (c *cluster) node() string { return c.kind + "-control-plane" }

func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		inventoryv1alpha1.AddToScheme, configv1alpha1.AddToScheme, appsv1.AddToScheme, corev1.AddToScheme,
		rbacv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			return nil, fmt.Errorf("register the APIs: %w", err)
		}
	}
	return scheme, nil
}

// measurement is one run of the tool.
type measurement struct {
	out      io.Writer
	opts     arguments
	hub      *cluster
	spokes   []*cluster
	names    []string          // the spokes' cluster names, as their OperatorConfigs give them
	digests  map[int]string    // the digest of each image of the load
	pods     *podNames         // the hub's pods in the operator's namespace, by UID
	usage    *sampler          // what the hub's pods use, from their cgroups
	writes   []writeSample     // the hub's writes to etcd, sampled through the run
	phases   map[string][2]int // the samples of writes that begin and end each phase
	writesMu sync.Mutex
}

// connectAll connects to the three clusters, and reads the spokes' names.
func connectAll(opts arguments, out io.Writer) (*measurement, error) {
	scheme, err := newScheme()
	if err != nil {
		return nil, err
	}
	m := &measurement{out: out, opts: opts, phases: map[string][2]int{}}
	if m.hub, err = connect(opts.hub, scheme); err != nil {
		return nil, err
	}
	for _, kubeconfig := range opts.spokes {
		spoke, err := connect(kubeconfig, scheme)
		if err != nil {
			return nil, err
		}
		m.spokes = append(m.spokes, spoke)
	}
	return m, nil
}

// measure runs the phases one after the other.
func (m *measurement) measure(ctx context.Context) error {
	start := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, spoke := range m.spokes {
		var config configv1alpha1.OperatorConfig
		if err := spoke.api.Get(ctx, client.ObjectKey{Name: settings.ConfigName}, &config); err != nil {
			return fmt.Errorf("read the OperatorConfig of %s: %w", spoke.kind, err)
		}
		m.names = append(m.names, ptr.Deref(config.Spec.ClusterName, settings.DefaultClusterName))
	}
	if m.names[0] == m.names[1] {
		return fmt.Errorf("both spokes are named %s", m.names[0])
	}
	m.say("hub %s, spokes %s (%s) and %s (%s)\n", m.hub.kind, m.names[0], m.spokes[0].kind, m.names[1],
		m.spokes[1].kind)

	m.pods = watchPods(ctx, m.hub)
	var err error
	if m.usage, err = startSampler(ctx, m.hub.node()); err != nil {
		return err
	}
	go m.sampleWrites(ctx)

	for _, phase := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"spokes", m.addSpokes},
		{"images", m.buildImages},
		{"load", m.runLoad},
		{"idle", m.measureIdle},
		{"rollout", m.rollOut},
		{"restart", m.restart},
	} {
		m.say("== %s, at %s\n", phase.name, time.Since(start).Round(time.Second))
		if err := phase.run(ctx); err != nil {
			return fmt.Errorf("%s: %w", phase.name, err)
		}
	}
	m.reportUsage()
	m.say("== done, after %s\n", time.Since(start).Round(time.Second))
	return nil
}

func (m *measurement) say(format string, args ...any) { say(m.out, format, args...) }
