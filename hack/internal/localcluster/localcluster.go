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

// Package localcluster is the guard of the tools in hack/ that write to a cluster, or start things in it. Such a
// tool belongs on a local kind cluster with a kubeconfig of its own, and nowhere else (AGENTS.md). Connect refuses
// any other cluster, and IsLoopback is one of the checks that it makes. A tool uses the same check for the other
// addresses that it must keep on the machine, such as a registry that it pushes images to.
package localcluster

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The refusals of Connect. A refused cluster is never touched.
var (
	// ErrNoKubeconfig is the error of Connect when KUBECONFIG is not set, or set to nothing.
	ErrNoKubeconfig = errors.New("KUBECONFIG is not set: the tool reads only the kubeconfig that it names, " +
		"the kind cluster's own, and never the default kubeconfig of a developer")
	// ErrNotKind is the error of Connect for a current context whose name doesn't start with kind-.
	ErrNotKind = errors.New("the current context of KUBECONFIG is not a kind cluster's, as its name doesn't " +
		"start with kind-, and the tool works only on a local kind cluster")
	// ErrNotLocal is the error of Connect for a cluster whose API server is not on a loopback address.
	ErrNotLocal = errors.New("the API server of the current context is not on a loopback address, " +
		"and the tool works only on a local cluster, such as kind")
)

// kindContextPrefix starts the name of the context that kind writes for each of its clusters: kind-<cluster>.
const kindContextPrefix = "kind-"

// Connect returns a client for the current context of the kubeconfig that KUBECONFIG names, if that is a local
// kind cluster. It refuses unless all three hold:
//   - KUBECONFIG is set, and not to nothing (ErrNoKubeconfig). Connect never falls back, as kubectl does, to
//     the default kubeconfig of a developer, whose current context can be any cluster, nor to the configuration
//     of a pod. A kind cluster has a kubeconfig of its own, such as the one that make setup-test-e2e writes.
//   - The name of the current context starts with kind-, as kind names the contexts of its clusters (ErrNotKind).
//   - The API server is on a loopback address, which kind's is (ErrNotLocal): a context can name any server.
//
// A cluster that is refused is never touched. tune, if given, changes the configuration of the client, such as
// its rate limit, once every check has passed: it never sees the configuration of a cluster that is refused.
func Connect(scheme *runtime.Scheme, tune ...func(*rest.Config)) (client.Client, error) {
	paths := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if strings.TrimSpace(paths) == "" {
		return nil, ErrNoKubeconfig
	}
	// Only the files that KUBECONFIG names, merged as kubectl merges them, and no default.
	rules := &clientcmd.ClientConfigLoadingRules{Precedence: filepath.SplitList(paths)}
	kubeconfig, err := rules.Load()
	if err != nil {
		return nil, fmt.Errorf("load the kubeconfig: %w", err)
	}
	if !strings.HasPrefix(kubeconfig.CurrentContext, kindContextPrefix) {
		return nil, ErrNotKind
	}
	cfg, err := clientcmd.NewNonInteractiveClientConfig(*kubeconfig, kubeconfig.CurrentContext,
		&clientcmd.ConfigOverrides{}, rules).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load the kubeconfig: %w", err)
	}
	if !IsLoopback(cfg.Host) {
		return nil, ErrNotLocal
	}
	for _, change := range tune {
		change(cfg)
	}
	return client.New(cfg, client.Options{Scheme: scheme})
}

// IsLoopback reports whether the address of an API server or of a registry, a URL or a host with a port as a
// client config has it, is localhost or a loopback address. It resolves no name: a name that merely resolves to
// the loopback is not one.
func IsLoopback(server string) bool {
	var host string
	if strings.Contains(server, "://") {
		u, err := url.Parse(server)
		if err != nil {
			return false
		}
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(server); err == nil {
		host = h
	} else {
		host = server
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
