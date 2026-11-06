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

package exposure

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/scope"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// A build computes the exposure of the cluster's workloads in three steps, so that a change computes again only what
// it can change:
//
//  1. Routing, read whole at every build: the namespaces, what exposes each Service, which pods the EndpointSlices
//     name, and Cilium's policies of the whole cluster. This step matches no selector against a pod. It costs one
//     pass over those objects.
//  2. The workloads of each namespace that a change touched: their pods, what exposes them, and what the policies
//     that select their pods let in and let them reach. This is where the selectors of Services and policies meet the
//     pods, one namespace at a time. A change of the namespaces, or of a policy of the whole cluster, touches every
//     namespace.
//  3. Indirect exposure, of the workloads of the namespaces of step 2, or of every workload when step 2 changed which
//     workloads are exposed, or the pods of one, or what one may reach. Each workload looks for exposed workloads only
//     in the namespaces that its ingress lets in.

// maxVia is how many objects an event names that expose its workload, as the exposure type's schema allows.
const maxVia = 8

// workloadKey names a workload as the subject of its events does: the namespace, and the API group, the kind and the
// name of its top-level owner. Two workloads of the same name that run at once, one being deleted, are one.
type workloadKey struct{ namespace, group, kind, name string }

// workload is what a build found of a workload.
type workload struct {
	key     workloadKey
	subject string
	// inScope says that a pod of the workload is in the scope of the Watch's context: only such a workload gets an
	// event. Every workload counts for the indirect exposure of the others.
	inScope bool
	// pods are the distinct views of the workload's pods: what a peer of a policy can select them by.
	pods     []podView
	podsSeen map[string]bool
	// via are the objects that expose the workload, sorted, all of them: an event names the first maxVia.
	via []evidence.ObjectRef
	// ingress is what the policies let in to its pods, and egress what they let its pods reach, each for all of
	// them.
	ingress, egress access
	// reach is how far the rest of the cluster reaches the workload: its widest pod's.
	reach    level
	indirect bool
	// data is the data of the workload's event, once it is encoded. A change of the workload drops it.
	data []byte
}

// addPod adds the view of a pod to the workload's, unless an equal one is there.
func (wl *workload) addPod(p podView) {
	key := fmt.Sprint(p.labels, "/", p.serviceAccount)
	if !wl.podsSeen[key] {
		wl.podsSeen[key] = true
		wl.pods = append(wl.pods, p)
	}
}

// exposed says that something outside the cluster reaches the workload.
func (wl *workload) exposed() bool { return len(wl.via) > 0 }

// encode returns the data of the workload's event.
func (wl *workload) encode() ([]byte, error) {
	if wl.data != nil {
		return wl.data, nil
	}
	exposure := evidence.Exposure{
		External:      evidence.ExternalExposure{Exposed: wl.exposed(), Via: wl.via[:min(len(wl.via), maxVia)]},
		InternalReach: wl.reach.String(),
		Indirect:      wl.indirect,
	}
	data, err := json.Marshal(exposure)
	if err != nil {
		return nil, fmt.Errorf("encode the exposure of %s: %w", wl.subject, err)
	}
	wl.data = data
	return data, nil
}

// rules are what the context of a Watch says about the workloads: the cluster, which their subjects name, which pods
// are in scope, and which are vexplain's own, which count only in vexplain's namespace.
type rules struct {
	cluster                        string
	scope                          *scope.Matcher
	ownPodLabel, operatorNamespace string
}

// rulesOf reads the rules from the context of a Watch. It refuses a scope that it can't read fully, as scope.Parse
// does, and a context without a cluster, whose events would have subjects that name none.
func rulesOf(c collector.Context) (rules, error) {
	if c.Cluster == "" {
		return rules{}, fmt.Errorf("the context names no cluster, which the subject of each event names")
	}
	matcher, err := scope.Parse(c.Scope)
	if err != nil {
		return rules{}, err
	}
	return rules{cluster: c.Cluster, scope: matcher, ownPodLabel: c.OwnPodLabel, operatorNamespace: c.OperatorNamespace},
		nil
}

// routing is what step 1 of a build reads.
type routing struct {
	namespaces namespaceLabels
	// exposers are the objects that expose each Service, by its namespace and name, sorted: the Service itself when
	// it faces outside, and the Ingresses and routes that count and route to it.
	exposers map[namespaced][]evidence.ObjectRef
	// backed are the Services, sorted, whose EndpointSlices name each pod, by the pod's namespace and name, and
	// sliceNamespaces the namespaces of the pods that each Service's slices name.
	backed          map[namespaced][]namespaced
	sliceNamespaces map[namespaced][]string
	// clusterwide are the policies of Cilium's CiliumClusterwideNetworkPolicies, and clusterwideSpecs their rules,
	// by name, which tell whether they changed.
	clusterwide      []*policy
	clusterwideSpecs map[string][]any
}

// widelyChanged reports whether rt differs from before in what can change the workloads of every namespace: the
// namespaces and their labels, which the scope and the policies' namespace selectors read, or the policies of the
// whole cluster.
func (rt *routing) widelyChanged(before *routing) bool {
	sameLabels := func(a, b map[string]string) bool { return maps.Equal(a, b) }
	return !maps.EqualFunc(rt.namespaces, before.namespaces, sameLabels) ||
		!equality.Semantic.DeepEqual(rt.clusterwideSpecs, before.clusterwideSpecs)
}

// changedNamespaces returns the namespaces whose workloads the differences between rt and before can change: those of
// the Services whose exposers changed, with the namespaces of the pods that their EndpointSlices name, and those of
// the pods that EndpointSlices name for other Services.
func (rt *routing) changedNamespaces(before *routing) map[string]bool {
	changed := map[string]bool{}
	services := slices.Concat(slices.Collect(maps.Keys(rt.exposers)), slices.Collect(maps.Keys(before.exposers)))
	for _, service := range services {
		if !slices.Equal(rt.exposers[service], before.exposers[service]) {
			changed[service.Namespace] = true
			for _, ns := range slices.Concat(rt.sliceNamespaces[service], before.sliceNamespaces[service]) {
				changed[ns] = true
			}
		}
	}
	pods := slices.Concat(slices.Collect(maps.Keys(rt.backed)), slices.Collect(maps.Keys(before.backed)))
	for _, pod := range pods {
		if !slices.Equal(rt.backed[pod], before.backed[pod]) {
			changed[pod.Namespace] = true
		}
	}
	return changed
}

// builder computes the exposure of a Watch's workloads, and keeps what the last build found, so that the next one
// computes again only what changed.
type builder struct {
	w        *Watcher
	r        client.Reader
	rules    rules
	settings settings

	routing     *routing
	byNamespace map[string]map[workloadKey]*workload
	// frontier holds a signature of each exposed workload: its pods and what it may reach.
	frontier map[workloadKey]string
}

func newBuilder(w *Watcher, rl rules, s settings) *builder {
	return &builder{w: w, r: w.informers, rules: rl, settings: s, byNamespace: map[string]map[workloadKey]*workload{}}
}

// build computes the exposure of the workloads of every namespace when all, and else of the namespaces of dirty, and
// of those that the changes of the routing touch. It reads the optional kinds of available.
func (b *builder) build(ctx context.Context, available map[schema.GroupKind]schema.GroupVersionKind, all bool,
	dirty map[string]bool) error {
	b.w.builds.Add(1)
	rt, err := b.readRouting(ctx, available)
	if err != nil {
		return err
	}
	all = all || b.routing == nil || rt.widelyChanged(b.routing)
	touched := map[string]bool{}
	maps.Copy(touched, dirty)
	if all {
		touched = map[string]bool{}
		for ns := range rt.namespaces {
			touched[ns] = true
		}
		for ns := range b.byNamespace {
			touched[ns] = true
		}
	} else {
		maps.Copy(touched, rt.changedNamespaces(b.routing))
	}
	b.routing = rt
	for _, ns := range slices.Sorted(maps.Keys(touched)) {
		found, err := b.namespace(ctx, ns, available)
		if err != nil {
			return err
		}
		b.w.recomputed.Add(1)
		if len(found) == 0 {
			delete(b.byNamespace, ns)
		} else {
			b.byNamespace[ns] = found
		}
	}
	frontier := b.frontierOf()
	if all || !maps.Equal(frontier, b.frontier) {
		b.decideIndirect(nil)
	} else {
		b.decideIndirect(touched)
	}
	b.frontier = frontier
	return nil
}

// events returns the data of the event of each workload in scope, by subject.
func (b *builder) events() (map[string][]byte, error) {
	events := map[string][]byte{}
	for _, found := range b.byNamespace {
		for _, wl := range found {
			if !wl.inScope {
				continue
			}
			data, err := wl.encode()
			if err != nil {
				return nil, err
			}
			events[wl.subject] = data
		}
	}
	return events, nil
}

// The kinds that the collector reads, in the version that it reads them in. It reads namespaces, ReplicaSets and Jobs
// as metadata: a cache of the whole objects would hold what it never reads, such as the pod templates of every
// ReplicaSet and Job of the cluster. workloads.ResolveOwner reads ReplicaSets and Jobs as metadata too.
var (
	podKind           = corev1.SchemeGroupVersion.WithKind(kindPod)
	namespaceKind     = corev1.SchemeGroupVersion.WithKind("Namespace")
	serviceKind       = corev1.SchemeGroupVersion.WithKind(kindService)
	endpointSliceKind = discoveryv1.SchemeGroupVersion.WithKind("EndpointSlice")
	ingressKind       = networkingv1.SchemeGroupVersion.WithKind("Ingress")
	policyKind        = networkingv1.SchemeGroupVersion.WithKind("NetworkPolicy")
	replicaSetKind    = appsv1.SchemeGroupVersion.WithKind("ReplicaSet")
	jobKind           = batchv1.SchemeGroupVersion.WithKind("Job")
)

// The optional kinds, by group and kind: the cluster serves them in a version that the Watch finds out.
var (
	gatewayKind = schema.GroupKind{Group: gatewayGroup, Kind: kindGateway}
	routeKinds  = []schema.GroupKind{
		{Group: gatewayGroup, Kind: kindHTTPRoute}, {Group: gatewayGroup, Kind: kindTLSRoute},
		{Group: gatewayGroup, Kind: kindGRPCRoute},
	}
	ciliumKind      = schema.GroupKind{Group: ciliumGroup, Kind: ciliumPolicyKind}
	clusterwideKind = schema.GroupKind{Group: ciliumGroup, Kind: clusterwidePolicyKind}
)

// readRouting reads step 1 of a build.
func (b *builder) readRouting(ctx context.Context, available map[schema.GroupKind]schema.GroupVersionKind) (
	*routing, error) {
	rt := &routing{
		namespaces: namespaceLabels{}, exposers: map[namespaced][]evidence.ObjectRef{},
		backed: map[namespaced][]namespaced{}, sliceNamespaces: map[namespaced][]string{},
		clusterwideSpecs: map[string][]any{},
	}
	namespaces, err := listMetadata(ctx, b.r, namespaceKind)
	if err != nil {
		return nil, err
	}
	for i := range namespaces {
		nsLabels := maps.Clone(namespaces[i].Labels)
		if nsLabels == nil {
			nsLabels = map[string]string{}
		}
		nsLabels[corev1.LabelMetadataName] = namespaces[i].Name
		rt.namespaces[namespaces[i].Name] = nsLabels
	}
	add := func(service namespaced, by evidence.ObjectRef) {
		rt.exposers[service] = append(rt.exposers[service], by)
	}
	if err := b.readServices(ctx, add); err != nil {
		return nil, err
	}
	if err := b.readIngresses(ctx, add); err != nil {
		return nil, err
	}
	if err := b.readRoutes(ctx, available, rt.namespaces, add); err != nil {
		return nil, err
	}
	var endpointSlices discoveryv1.EndpointSliceList
	if err := b.r.List(ctx, &endpointSlices, client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the EndpointSlices: %w", err)
	}
	for i := range endpointSlices.Items {
		service, pods := slicePods(&endpointSlices.Items[i])
		for _, pod := range pods {
			rt.backed[pod] = append(rt.backed[pod], service)
			rt.sliceNamespaces[service] = append(rt.sliceNamespaces[service], pod.Namespace)
		}
	}
	if gvk, ok := available[clusterwideKind]; ok {
		policies, err := listUnstructured(ctx, b.r, gvk, "")
		if err != nil {
			return nil, err
		}
		for i := range policies {
			rt.clusterwide = append(rt.clusterwide, ciliumPolicies(&policies[i])...)
			rt.clusterwideSpecs[policies[i].GetName()] = []any{policies[i].Object["spec"], policies[i].Object["specs"]}
		}
	}
	for service, refs := range rt.exposers {
		rt.exposers[service] = sortedRefs(refs)
	}
	for pod, services := range rt.backed {
		slices.SortFunc(services, func(a, b namespaced) int {
			return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
		})
		rt.backed[pod] = slices.Compact(services)
	}
	for service, namespaces := range rt.sliceNamespaces {
		slices.Sort(namespaces)
		rt.sliceNamespaces[service] = slices.Compact(namespaces)
	}
	return rt, nil
}

// readServices adds each Service that exposes the pods that it selects to its own exposers.
func (b *builder) readServices(ctx context.Context, add func(namespaced, evidence.ObjectRef)) error {
	var services corev1.ServiceList
	if err := b.r.List(ctx, &services, client.UnsafeDisableDeepCopy); err != nil {
		return fmt.Errorf("list the Services: %w", err)
	}
	for i := range services.Items {
		svc := &services.Items[i]
		if serviceExposes(svc, b.settings) {
			add(namespaced{Namespace: svc.Namespace, Name: svc.Name}, objectRef("", kindService, svc.Namespace, svc.Name))
		}
	}
	return nil
}

// readIngresses adds each Ingress that counts to the exposers of the Services that it routes to.
func (b *builder) readIngresses(ctx context.Context, add func(namespaced, evidence.ObjectRef)) error {
	var ingresses networkingv1.IngressList
	if err := b.r.List(ctx, &ingresses, client.UnsafeDisableDeepCopy); err != nil {
		return fmt.Errorf("list the Ingresses: %w", err)
	}
	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		if !ingressCounts(ing, b.settings) {
			continue
		}
		for _, backend := range ingressBackends(ing) {
			add(namespaced{Namespace: ing.Namespace, Name: backend},
				objectRef(networkingv1.GroupName, "Ingress", ing.Namespace, ing.Name))
		}
	}
	return nil
}

// readRoutes adds each route of the Gateway API that attaches to a Gateway that counts to the exposers of the
// Services that it routes to, when the cluster serves the Gateway API.
func (b *builder) readRoutes(ctx context.Context, available map[schema.GroupKind]schema.GroupVersionKind,
	namespaces namespaceLabels, add func(namespaced, evidence.ObjectRef)) error {
	gateways := map[namespaced]map[string]any{}
	if gvk, ok := available[gatewayKind]; ok {
		list, err := listUnstructured(ctx, b.r, gvk, "")
		if err != nil {
			return err
		}
		for i := range list {
			gateways[namespaced{Namespace: list[i].GetNamespace(), Name: list[i].GetName()}] = list[i].Object
		}
	}
	for _, kind := range routeKinds {
		gvk, ok := available[kind]
		if !ok {
			continue
		}
		routes, err := listUnstructured(ctx, b.r, gvk, "")
		if err != nil {
			return err
		}
		for i := range routes {
			route := &routes[i]
			parents := sliceOf(route.Object, "spec", "parentRefs")
			if !attached(parents, route.GetNamespace(), kind.Kind, gateways, b.settings, namespaces) {
				continue
			}
			for _, backend := range routeBackends(route) {
				add(backend, objectRef(gatewayGroup, kind.Kind, route.GetNamespace(), route.GetName()))
			}
		}
	}
	return nil
}

// namespace computes step 2 of a build for the namespace ns: its workloads, each with its pods, what exposes it, and
// what the policies let in to its pods and let them reach. vexplain's own pods belong to no workload. The pods of a
// namespace that the cache doesn't hold yet wait for it: the namespace's event builds again.
func (b *builder) namespace(ctx context.Context, ns string, available map[schema.GroupKind]schema.GroupVersionKind) (
	map[workloadKey]*workload, error) {
	rt := b.routing
	nsLabels, known := rt.namespaces[ns]
	if !known {
		return nil, nil
	}
	var pods corev1.PodList
	if err := b.r.List(ctx, &pods, client.InNamespace(ns), client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the pods of %s: %w", ns, err)
	}
	if len(pods.Items) == 0 {
		return nil, nil
	}
	var services corev1.ServiceList
	if err := b.r.List(ctx, &services, client.InNamespace(ns), client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the Services of %s: %w", ns, err)
	}
	policies, err := b.policiesOf(ctx, ns, available)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(pods.Items, func(a, b corev1.Pod) int { return strings.Compare(a.Name, b.Name) })
	owners := map[types.UID]workloads.WorkloadRef{}
	found := map[workloadKey]*workload{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if workloads.IsOwnPod(pod, b.rules.ownPodLabel, b.rules.operatorNamespace) {
			continue
		}
		owner, err := b.ownerOf(ctx, pod, owners)
		if err != nil {
			return nil, err
		}
		key := workloadKey{namespace: ns, group: owner.APIGroup, kind: owner.Kind, name: owner.Name}
		wl := found[key]
		if wl == nil {
			wl = &workload{key: key, podsSeen: map[string]bool{}, subject: subject.ForWorkload(subject.Workload{
				Cluster: b.rules.cluster, Namespace: ns, Group: owner.APIGroup, Kind: owner.Kind, Name: owner.Name,
			})}
			found[key] = wl
		}
		view := podView{namespace: ns, labels: pod.Labels, serviceAccount: pod.Spec.ServiceAccountName,
			hostNetwork: pod.Spec.HostNetwork}
		wl.inScope = wl.inScope || b.rules.scope.Matches(nsLabels, pod.Labels)
		// Nothing but the workload exposes it on its node's address, and the names of its pods change as they come
		// and go: the workload's own object stands for it.
		if b.settings.NodePorts != nodePortsInternal && onNodeAddress(pod) {
			wl.via = append(wl.via, objectRef(owner.APIGroup, owner.Kind, ns, owner.Name))
		}
		for j := range services.Items {
			if selects(&services.Items[j], pod) {
				wl.via = append(wl.via, rt.exposers[namespaced{Namespace: ns, Name: services.Items[j].Name}]...)
			}
		}
		for _, service := range rt.backed[namespaced{Namespace: ns, Name: pod.Name}] {
			wl.via = append(wl.via, rt.exposers[service]...)
		}
		in, out := accessOf(view, policies, rt.namespaces)
		wl.ingress, wl.egress = wl.ingress.union(in), wl.egress.union(out)
		wl.reach = max(wl.reach, in.level(ns, rt.namespaces))
		wl.addPod(view)
	}
	for _, wl := range found {
		wl.via = sortedRefs(wl.via)
	}
	return found, nil
}

// policiesOf returns the policies that can select pods of the namespace ns: its NetworkPolicies, its Cilium policies
// when the cluster serves Cilium's, and the policies of the whole cluster.
func (b *builder) policiesOf(ctx context.Context, ns string, available map[schema.GroupKind]schema.GroupVersionKind) (
	[]*policy, error) {
	var networkPolicies networkingv1.NetworkPolicyList
	if err := b.r.List(ctx, &networkPolicies, client.InNamespace(ns), client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the NetworkPolicies of %s: %w", ns, err)
	}
	policies := make([]*policy, 0, len(networkPolicies.Items)+len(b.routing.clusterwide))
	for i := range networkPolicies.Items {
		policies = append(policies, networkPolicy(&networkPolicies.Items[i]))
	}
	if gvk, ok := available[ciliumKind]; ok {
		list, err := listUnstructured(ctx, b.r, gvk, ns)
		if err != nil {
			return nil, err
		}
		for i := range list {
			policies = append(policies, ciliumPolicies(&list[i])...)
		}
	}
	return append(policies, b.routing.clusterwide...), nil
}

// ownerOf returns the workload of a pod, through workloads.ResolveOwner, once for the pods of one controller.
func (b *builder) ownerOf(ctx context.Context, pod *corev1.Pod, owners map[types.UID]workloads.WorkloadRef) (
	workloads.WorkloadRef, error) {
	controller := metav1.GetControllerOfNoCopy(pod)
	if controller == nil {
		return workloads.ResolveOwner(ctx, b.r, pod)
	}
	if owner, ok := owners[controller.UID]; ok {
		if _, mirror := pod.Annotations[corev1.MirrorPodAnnotationKey]; !mirror {
			return owner, nil
		}
	}
	owner, err := workloads.ResolveOwner(ctx, b.r, pod)
	if err != nil {
		return workloads.WorkloadRef{}, err
	}
	if _, mirror := pod.Annotations[corev1.MirrorPodAnnotationKey]; !mirror {
		owners[controller.UID] = owner
	}
	return owner, nil
}

// frontierOf returns a signature of each exposed workload: its pods, and what its egress lets it reach. When neither
// these nor which workloads are exposed changed, no workload outside the namespaces of a build's step 2 can have
// changed its indirect exposure.
func (b *builder) frontierOf() map[workloadKey]string {
	frontier := map[workloadKey]string{}
	for _, found := range b.byNamespace {
		for key, wl := range found {
			if wl.exposed() {
				frontier[key] = strings.Join(slices.Sorted(maps.Keys(wl.podsSeen)), ",") + "|" + wl.egress.signature()
			}
		}
	}
	return frontier
}

// decideIndirect decides the indirect exposure of the workloads of the namespaces of only, or of every workload when
// only is nil. A workload is indirectly exposed when another workload that is exposed may reach it: its ingress lets
// one of the other's pods in, and the other's egress lets it reach one of the workload's pods.
func (b *builder) decideIndirect(only map[string]bool) {
	byNamespace := map[string][]*workload{}
	var exposed []*workload
	for _, found := range b.byNamespace {
		for _, wl := range found {
			if wl.exposed() {
				exposed = append(exposed, wl)
				byNamespace[wl.key.namespace] = append(byNamespace[wl.key.namespace], wl)
			}
		}
	}
	for ns, found := range b.byNamespace {
		if only != nil && !only[ns] {
			continue
		}
		for _, wl := range found {
			indirect := b.reachedByExposed(wl, exposed, byNamespace)
			if indirect != wl.indirect {
				wl.indirect, wl.data = indirect, nil
			}
		}
	}
}

// reachedByExposed reports whether an exposed workload other than wl may reach it. It looks for one among all the
// exposed workloads when wl's ingress lets anything in, and else only in the namespaces that its peers select.
func (b *builder) reachedByExposed(wl *workload, exposed []*workload, byNamespace map[string][]*workload) bool {
	namespaces := b.routing.namespaces
	reaches := func(other *workload) bool { return other != wl && other.egress.admitsAny(wl.pods, namespaces) }
	if wl.ingress.anything {
		return slices.ContainsFunc(exposed, reaches)
	}
	for _, pe := range wl.ingress.peers {
		for ns, candidates := range byNamespace {
			if pe.outside || (pe.namespaces == nil && ns != pe.namespace) ||
				(pe.namespaces != nil && !pe.namespaces.Matches(labels.Set(namespaces[ns]))) {
				continue
			}
			admitted := func(p podView) bool { return pe.admits(p, namespaces) }
			for _, other := range candidates {
				if reaches(other) && slices.ContainsFunc(other.pods, admitted) {
					return true
				}
			}
		}
	}
	return false
}

// signature is a text that tells apart what two accesses let through, for frontierOf.
func (a access) signature() string {
	if a.anything {
		return "*"
	}
	parts := make([]string, 0, len(a.peers))
	for _, pe := range a.peers {
		namespaces := "=" + pe.namespace
		if pe.namespaces != nil {
			namespaces = pe.namespaces.String()
		}
		pods := ""
		if pe.pods != nil {
			pods = pe.pods.String()
		}
		parts = append(parts, fmt.Sprintf("%t;%s;%s;%t", pe.outside, namespaces, pods, pe.cilium))
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

// listMetadata lists the objects of a kind through r, as metadata only.
func listMetadata(ctx context.Context, r client.Reader, kind schema.GroupVersionKind) (
	[]metav1.PartialObjectMetadata, error) {
	list := &metav1.PartialObjectMetadataList{}
	list.SetGroupVersionKind(kind.GroupVersion().WithKind(kind.Kind + "List"))
	if err := r.List(ctx, list, client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the %s objects: %w", kind.Kind, err)
	}
	return list.Items, nil
}

// listUnstructured lists the objects of a kind through r, in the namespace, or in every namespace when it is empty.
func listUnstructured(ctx context.Context, r client.Reader, kind schema.GroupVersionKind, namespace string) (
	[]unstructured.Unstructured, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(kind.GroupVersion().WithKind(kind.Kind + "List"))
	opts := []client.ListOption{client.UnsafeDisableDeepCopy}
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	if err := r.List(ctx, list, opts...); err != nil {
		return nil, fmt.Errorf("list the %s objects: %w", kind.Kind, err)
	}
	return list.Items, nil
}
