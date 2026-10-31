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
// tool belongs on a local cluster, such as kind, and nowhere else (AGENTS.md). Connect refuses a cluster whose API
// server is not on a loopback address, and IsLoopback is the check that it makes. A tool uses the same check for
// the other addresses that it must keep on the machine, such as a registry that it pushes images to.
package localcluster

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// ErrNotLocal is the error of Connect for a cluster whose API server is not on a loopback address.
var ErrNotLocal = errors.New("the API server of the current context is not on a loopback address, " +
	"and the tool works only on a local cluster, such as kind")

// Connect returns a client for the current context of the kubeconfig (KUBECONFIG, as for kubectl), if its API
// server is on a loopback address, which kind's is. For any other cluster it returns ErrNotLocal, and nothing
// has touched the cluster.
//
// tune, if given, changes the configuration of the client, such as its rate limit, once the address has passed:
// it never sees the configuration of a cluster that is refused.
func Connect(scheme *runtime.Scheme, tune ...func(*rest.Config)) (client.Client, error) {
	cfg, err := config.GetConfig()
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
