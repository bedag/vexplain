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

package testenv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// HubAccount is the ServiceAccount of the hub on a spoke, in the operator's namespace (design 5.4).
const HubAccount = "vexplain-hub"

// GrantHub creates the hub's ServiceAccount in namespace of the cluster that c writes, with what the spoke's install
// grants it that connecting needs: the read of the namespaces, for the cluster's identity, and the renewal of its own
// token (design 5.4). It stands in for a spoke's install in the tests that connect the hub to a spoke.
func GrantHub(ctx context.Context, c client.Client, namespace string) error {
	subjects := []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: namespace, Name: HubAccount}}
	for _, obj := range []client.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: HubAccount}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: HubAccount},
			Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get"}}}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: HubAccount},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: HubAccount},
			Subjects: subjects},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: HubAccount},
			Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"},
				ResourceNames: []string{HubAccount}, Verbs: []string{"create"}}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: HubAccount},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: HubAccount},
			Subjects: subjects},
	} {
		if err := c.Create(ctx, obj); err != nil {
			return err
		}
	}
	return nil
}

// Token asks the cluster that c writes for a token of the ServiceAccount namespace/account that lives seconds, as an
// admin asks a spoke for the hub's bootstrap token.
func Token(ctx context.Context, c client.Client, namespace, account string, seconds int64) (string, error) {
	request := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &seconds}}
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: account}}
	if err := c.SubResource("token").Create(ctx, serviceAccount, request); err != nil {
		return "", err
	}
	return request.Status.Token, nil
}

// UnsignedToken returns a token with the claims of a token of the ServiceAccount namespace/account, issued and expiring
// at the times given, and no valid signature: the hub reads its claims, which it can't check, and no API server
// accepts it. Empty names make a token that names no ServiceAccount.
func UnsignedToken(namespace, account string, issued, expires time.Time) string {
	encode := func(v any) string {
		raw, _ := json.Marshal(v) // maps of strings and numbers always encode
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return encode(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + encode(map[string]any{
		"iat": issued.Unix(),
		"exp": expires.Unix(),
		"sub": "system:serviceaccount:" + namespace + ":" + account,
		"kubernetes.io": map[string]any{
			"namespace":      namespace,
			"serviceaccount": map[string]string{"name": account},
		},
	}) + "." + base64.RawURLEncoding.EncodeToString([]byte("unsigned"))
}
