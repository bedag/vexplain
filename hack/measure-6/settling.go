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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// runLoad deploys the load on both spokes, waits until the hub has copied, scanned and judged it, and measures what the
// hub then holds, the scans, and the series of vexplain_open_case.
func (m *measurement) runLoad(ctx context.Context) error {
	begin := m.mark()
	deployed := time.Now()
	for s, spoke := range m.spokes {
		if err := m.deploy(ctx, spoke, loadOf(s)); err != nil {
			return fmt.Errorf("deploy the load on %s: %w", m.names[s], err)
		}
	}
	err := m.waitFor(ctx, "the hub to copy, scan and judge the load", func(ctx context.Context) (bool, error) {
		held, err := m.readHub(ctx)
		if err != nil {
			return false, err
		}
		missing, err := m.missing(held)
		if missing != "" {
			m.say("  still waiting for %s\n", missing)
		}
		return missing == "" && err == nil, err
	})
	if err != nil {
		return err
	}
	m.say("the hub holds the load %s after its deployment\n", time.Since(deployed).Round(time.Second))
	if err = m.waitQuiet(ctx, begin); err != nil {
		return err
	}
	m.phases["load"] = [2]int{begin, m.mark()}
	m.reportWrites("load")
	held, err := m.readHub(ctx)
	if err != nil {
		return err
	}
	if err = m.reportHoldings(ctx, held); err != nil {
		return err
	}
	if err = m.reportScans(ctx, deployed); err != nil {
		return err
	}
	return m.reportSeries(ctx)
}

// deploy makes the namespaces and the Deployments of the load on a spoke. It updates what is there, so that a second
// run goes on where the first stopped.
func (m *measurement) deploy(ctx context.Context, spoke *cluster, load []workload) error {
	for i := range loadNamespaces {
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceOf(i)}}
		if _, err := controllerutil.CreateOrUpdate(ctx, spoke.api, namespace, func() error { return nil }); err != nil {
			return err
		}
	}
	for _, w := range load {
		want := deploymentOf(w, m.opts.registry+"/measure-6/"+imageName(w.image)+"@"+m.digests[w.image])
		have := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: want.Name, Namespace: want.Namespace}}
		if _, err := controllerutil.CreateOrUpdate(ctx, spoke.api, have, func() error {
			have.Labels, have.Spec = want.Labels, want.Spec
			return nil
		}); err != nil {
			return fmt.Errorf("make %s/%s: %w", w.namespace, w.name, err)
		}
	}
	return nil
}

// deploymentOf returns the Deployment of a workload: one replica of its image, which sleeps, as the pods of
// hack/measure-2a do. A scan reads an image's files and runs nothing, but the inventory sees images through the pods
// that run them.
func deploymentOf(w workload, image string) *appsv1.Deployment {
	labels := map[string]string{"app": w.name}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: w.name, Namespace: w.namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					// sleep as process 1 ignores SIGTERM, so the pod would wait for the end of its grace period.
					TerminationGracePeriodSeconds: ptr.To(int64(1)),
					AutomountServiceAccountToken:  ptr.To(false),
					EnableServiceLinks:            ptr.To(false),
					Containers: []corev1.Container{{
						Name: containerName, Image: image, Command: []string{"sleep", "86400"},
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						},
					}},
				},
			},
		},
	}
}

// holdings are the hub's records of the inventory group, as one look read them.
type holdings struct {
	evidence    []inventoryv1alpha1.Evidence
	inventories []inventoryv1alpha1.ImageInventory
	sheets      []inventoryv1alpha1.ImageVerdicts
	ledgers     []inventoryv1alpha1.Ledger
	statuses    []inventoryv1alpha1.PlaybookClusterStatus
}

func (m *measurement) readHub(ctx context.Context) (*holdings, error) {
	var evidence inventoryv1alpha1.EvidenceList
	var inventories inventoryv1alpha1.ImageInventoryList
	var sheets inventoryv1alpha1.ImageVerdictsList
	var ledgers inventoryv1alpha1.LedgerList
	var statuses inventoryv1alpha1.PlaybookClusterStatusList
	for _, list := range []client.ObjectList{&evidence, &inventories, &sheets, &ledgers, &statuses} {
		if err := m.hub.api.List(ctx, list); err != nil {
			return nil, err
		}
	}
	return &holdings{evidence: evidence.Items, inventories: inventories.Items, sheets: sheets.Items,
		ledgers: ledgers.Items, statuses: statuses.Items}, nil
}

// missing returns what the hub doesn't hold yet of the load, or "" once it holds it all: an entry of each cluster that
// runs an image, with the workloads of the layout, the copy of each presence record with as many workloads, the facts
// of a scan of each image, and a sheet of each manifest. A failed scan is an error: the hub tries it again only after
// a while.
func (m *measurement) missing(held *holdings) (string, error) {
	inventories := map[string]*inventoryv1alpha1.ImageInventory{}
	for i := range held.inventories {
		inventories[held.inventories[i].Spec.Digest] = &held.inventories[i]
	}
	copied := map[[2]string]int{}
	for i := range held.evidence {
		e := &held.evidence[i]
		if e.Spec.Type != sdkevidence.TypePresence || e.Spec.Cluster == nil {
			continue
		}
		presence, err := presenceOf(e)
		if err != nil {
			return "", err
		}
		copied[[2]string{e.Spec.Subject, *e.Spec.Cluster}] = len(presence.Workloads)
	}
	sheets := map[string]bool{}
	for _, sheet := range held.sheets {
		if sheet.Spec.Playbook == sheetPlaybook && sheet.Status.Counts != nil {
			sheets[sheet.Spec.ManifestDigest] = true
		}
	}
	for s, spokeName := range m.names {
		for k, g := range imagesOf(s) {
			workloads, _ := layout(k)
			found := inventories[m.digests[g]]
			if found == nil {
				return fmt.Sprintf("the inventory of %s", imageName(g)), nil
			}
			entry := slices.IndexFunc(found.Status.Clusters, func(c inventoryv1alpha1.ClusterPresence) bool {
				return c.Cluster == spokeName && ptr.Deref(c.WorkloadCount, 0) == int32(workloads)
			})
			if entry < 0 {
				return fmt.Sprintf("the entry of %s in %s", spokeName, imageName(g)), nil
			}
			if copied[[2]string{subject.Image(m.digests[g]), spokeName}] != workloads {
				return fmt.Sprintf("the presence of %s in %s", imageName(g), spokeName), nil
			}
		}
	}
	for g := range loadImages {
		facts := inventories[m.digests[g]].Status.Facts
		switch {
		case facts == nil || len(facts.Manifests) == 0 && len(facts.Failures) == 0:
			return fmt.Sprintf("the scan of %s", imageName(g)), nil
		case len(facts.Manifests) == 0:
			return "", fmt.Errorf("the scan of %s failed: %s", imageName(g), facts.Failures[0].Reason)
		}
		for _, manifest := range facts.Manifests {
			if !sheets[manifest.Digest] {
				return fmt.Sprintf("the sheet of %s", imageName(g)), nil
			}
		}
	}
	return "", nil
}

// presenceOf decodes the data of a presence record.
func presenceOf(e *inventoryv1alpha1.Evidence) (*sdkevidence.Presence, error) {
	reader, err := gzip.NewReader(bytes.NewReader(e.Spec.Data))
	if err != nil {
		return nil, fmt.Errorf("the presence record %s: %w", e.Name, err)
	}
	var presence sdkevidence.Presence
	if err = json.NewDecoder(reader).Decode(&presence); err != nil {
		return nil, fmt.Errorf("the presence record %s: %w", e.Name, err)
	}
	return &presence, nil
}
