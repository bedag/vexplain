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
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// addSpokes adds each spoke to the hub, as docs/remote-spokes.md does, and waits until the hub has copied what each
// holds, and until the hub's matcher has loaded its database: a match that fails before backs off.
func (m *measurement) addSpokes(ctx context.Context) error {
	for i, spoke := range m.spokes {
		if err := addSpoke(ctx, m.hub, spoke, m.names[i]); err != nil {
			return fmt.Errorf("add %s: %w", m.names[i], err)
		}
	}
	err := m.waitFor(ctx, "the Spokes to be Ready and Synced", func(ctx context.Context) (bool, error) {
		for _, spokeName := range m.names {
			var found configv1alpha1.Spoke
			if err := m.hub.api.Get(ctx, client.ObjectKey{Name: spokeName}, &found); err != nil {
				return false, err
			}
			if !meta.IsStatusConditionTrue(found.Status.Conditions, configv1alpha1.ConditionReady) ||
				!meta.IsStatusConditionTrue(found.Status.Conditions, configv1alpha1.ConditionSynced) {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	return m.waitFor(ctx, "the hub's matcher to load its database", func(ctx context.Context) (bool, error) {
		logs, err := deploymentLogs(ctx, m.hub, vulnerabilitiesCollector)
		return strings.Contains(logs, databaseLoaded), err
	})
}

// addSpoke makes the token of the hub's account on the spoke, and on the hub the Secret with the spoke's address on
// the kind network, its CA and the token, and the Spoke. The token stays in memory and in the Secret, and is never
// printed.
func addSpoke(ctx context.Context, hub, spoke *cluster, spokeName string) error {
	internal, err := exec.CommandContext(ctx, "kind", "get", "kubeconfig", "--internal", "--name", spoke.kind).Output()
	if err != nil {
		return fmt.Errorf("read the spoke's kubeconfig on the kind network: %w", err)
	}
	config, err := clientcmd.Load(internal)
	if err != nil {
		return err
	}
	current, ok := config.Contexts[config.CurrentContext]
	if !ok || config.Clusters[current.Cluster] == nil {
		return errors.New("the spoke's kubeconfig on the kind network has no current cluster")
	}
	server, ca := config.Clusters[current.Cluster].Server, config.Clusters[current.Cluster].CertificateAuthorityData
	request := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
		ExpirationSeconds: ptr.To(int64(time.Hour / time.Second))}}
	token, err := spoke.clientset.CoreV1().ServiceAccounts(operatorNamespace).CreateToken(ctx, hubAccount, request,
		metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create a token of %s: %w", hubAccount, err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: spokeName + "-credentials", Namespace: operatorNamespace}}
	if _, err = controllerutil.CreateOrUpdate(ctx, hub.api, secret, func() error {
		secret.Data = map[string][]byte{"server": []byte(server), "ca.crt": ca, "token": []byte(token.Status.Token)}
		return nil
	}); err != nil {
		return fmt.Errorf("make the Secret of the spoke: %w", err)
	}
	record := &configv1alpha1.Spoke{ObjectMeta: metav1.ObjectMeta{Name: spokeName}}
	_, err = controllerutil.CreateOrUpdate(ctx, hub.api, record, func() error {
		record.Spec.CredentialsSecretRef.Name = secret.Name
		return nil
	})
	return err
}

// podsOf returns the pods of the Deployment of the name in the operator's namespace.
func podsOf(ctx context.Context, c *cluster, deployment string) ([]corev1.Pod, error) {
	var found appsv1.Deployment
	if err := c.api.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: deployment}, &found); err != nil {
		return nil, err
	}
	var pods corev1.PodList
	err := c.api.List(ctx, &pods, client.InNamespace(operatorNamespace),
		client.MatchingLabels(found.Spec.Selector.MatchLabels))
	return pods.Items, err
}

// deploymentLogs returns the logs of the pods of the Deployment of the name in the operator's namespace.
func deploymentLogs(ctx context.Context, c *cluster, deployment string) (string, error) {
	pods, err := podsOf(ctx, c, deployment)
	if err != nil {
		return "", err
	}
	var logs strings.Builder
	for _, pod := range pods {
		// A pod whose container hasn't started has no logs yet.
		raw, _ := c.clientset.CoreV1().Pods(operatorNamespace).GetLogs(pod.Name, &corev1.PodLogOptions{}).DoRaw(ctx)
		logs.Write(raw)
	}
	return logs.String(), nil
}

// waitFor looks every lookPoll until done says so, for the timeout at most.
func (m *measurement) waitFor(ctx context.Context, what string, done func(context.Context) (bool, error)) error {
	m.say("waiting for %s\n", what)
	err := wait.PollUntilContextTimeout(ctx, lookPoll, m.opts.timeout, true, done)
	if err != nil {
		return fmt.Errorf("waiting for %s: %w", what, err)
	}
	return nil
}
