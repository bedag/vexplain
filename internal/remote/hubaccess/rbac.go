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

// Package hubaccess holds the RBAC markers of the hub's access on a spoke. The hub reads each spoke's API server with
// the token of a ServiceAccount of its own, which may read what the hub copies and create its own tokens, so that it
// can renew them. The markers have a package of their own, left out of the manager's role, because the manager of a
// spoke has no need of them: they make the role `hub-reader` in config/rbac/hub-access.
package hubaccess

// What the hub copies: the records of the inventory, the collectors and the operator's settings, and the namespaces,
// for their labels and the cluster's identity.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors;operatorconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=evidences;imageinventories,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// The token of its own ServiceAccount, and no other: a token created for it only ever grants this role.
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,resourceNames=vexplain-hub,verbs=create,namespace=vexplain-system
