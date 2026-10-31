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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// fixture is the synthetic export of the tests. It has the header of a real export, and neutral
// names. Of its 13 rows, 8 can be loaded, 1 has a kind that the tool doesn't know, and 4 are
// malformed: no kind and name in the workload, no namespace, too few fields, and a bare quote.
const fixture = "testdata/export.csv"

// flagCSV is the flag that names the export.
const flagCSV = "--csv"

const (
	clusterA = "cluster-a"
	clusterB = "cluster-b"

	// The four images of the fixture. The redis image has a registry with a port, a tag and a digest.
	imageNginx = "artifacts.example/lib/nginx:1.27"
	imageRedis = "registry.example:5000/lib/redis:7.2@sha256:" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imageAgent = "artifacts.example/lib/agent:2.1.0"
	imageTools = "artifacts.example/lib/tools"

	// fixtureImages is the number of images that can be loaded from the fixture, and fixturePairs the
	// number of pairs of an image and a cluster: nginx runs in two clusters, and the others in one.
	fixtureImages = 4
	fixturePairs  = 5
)

// hashOf returns the hex sha256 of s. The tests make their own digests, so that they do not
// depend on the function under test.
func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// wantDigest is the digest of copy i of an image: the plain one for copy 0, and the one of
// image#i for the others.
func wantDigest(image string, i int) string {
	if i == 0 {
		return "sha256:" + hashOf(image)
	}
	return "sha256:" + hashOf(image+"#"+strconv.Itoa(i))
}

// newFake returns a fake client that keeps the status of an ImageInventory apart from the rest, as
// the API server does for a CRD with a status subresource. The funcs intercept its calls.
func newFake(t *testing.T, funcs interceptor.Funcs) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&inventoryv1alpha1.ImageInventory{}).
		WithInterceptorFuncs(funcs).
		Build()
}

// connectTo returns the connect function of run for a client that a test made.
func connectTo(c client.Client) func() (client.Client, error) {
	return func() (client.Client, error) { return c, nil }
}

// runTool runs the tool on the client with the arguments, and returns the exit code and the output.
func runTool(t *testing.T, c client.Client, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(context.Background(), args, &out, connectTo(c))
	return code, out.String()
}

// objects returns the ImageInventory objects in the cluster, by digest.
func objects(t *testing.T, c client.Client) map[string]inventoryv1alpha1.ImageInventory {
	t.Helper()
	var list inventoryv1alpha1.ImageInventoryList
	require.NoError(t, c.List(context.Background(), &list))
	byDigest := make(map[string]inventoryv1alpha1.ImageInventory, len(list.Items))
	for _, item := range list.Items {
		byDigest[item.Spec.Digest] = item
	}
	return byDigest
}

// ref returns the reference to a workload. The core group is a nil group.
func ref(group, kind, namespace, name string) inventoryv1alpha1.WorkloadReference {
	reference := inventoryv1alpha1.WorkloadReference{Kind: kind, Namespace: namespace, Name: name}
	if group != "" {
		reference.APIGroup = ptr.To(group)
	}
	return reference
}

// keys returns the keys of a set, sorted.
func keys(set map[string]struct{}) []string {
	return slices.Sorted(maps.Keys(set))
}

// referencesOf returns the workloads of a pair as the references of the API.
func referencesOf(p *pair) []inventoryv1alpha1.WorkloadReference {
	references := make([]inventoryv1alpha1.WorkloadReference, 0, len(p.refs))
	for _, w := range p.refs {
		references = append(references, ref(w.APIGroup, w.Kind, w.Namespace, w.Name))
	}
	return references
}

// jsonSize returns the length of the JSON of an object.
func jsonSize(t *testing.T, obj inventoryv1alpha1.ImageInventory) int {
	t.Helper()
	raw, err := json.Marshal(obj)
	require.NoError(t, err)
	return len(raw)
}

// writeFile writes a file of the test.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestReadExportCountsWhatItSkips(t *testing.T) {
	e, err := readExportFile(fixture)

	require.NoError(t, err)
	require.Equal(t, 13, e.rows)
	require.Equal(t, 4, e.malformed)
	require.Equal(t, 1, e.unknownKind)
	require.Len(t, e.images, fixtureImages)
	require.Equal(t, fixturePairs, e.pairs())
}

func TestReadExportGroupsRowsByImageAndCluster(t *testing.T) {
	e, err := readExportFile(fixture)
	require.NoError(t, err)

	nginxInA := e.images[imageNginx][clusterA]
	require.NotNil(t, nginxInA)
	require.ElementsMatch(t, []string{"team-a-web", "team-a-batch"}, keys(nginxInA.namespaces))
	require.ElementsMatch(t, []inventoryv1alpha1.WorkloadReference{
		ref(groupApps, kindReplicaSet, "team-a-web", "web-7d9c4b"),
		ref(groupApps, kindReplicaSet, "team-a-web", "api-5f6d8c"),
		ref(groupBatch, kindJob, "team-a-batch", "report-28911"),
	}, referencesOf(nginxInA))

	nginxInB := e.images[imageNginx][clusterB]
	require.NotNil(t, nginxInB)
	require.Equal(t, []string{"team-b-web"}, keys(nginxInB.namespaces))
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{ref(groupApps, kindDeployment, "team-b-web", "web")},
		referencesOf(nginxInB))

	// The Pod is in the core group, and the DaemonSet in apps.
	require.ElementsMatch(t, []inventoryv1alpha1.WorkloadReference{
		ref(groupApps, kindDaemonSet, "team-a-web", "agent"),
		ref(groupCore, kindPod, "team-a-web", "debug-shell"),
	}, referencesOf(e.images[imageAgent][clusterA]))
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{ref(groupBatch, kindCronJob, "team-a-jobs", "nightly")},
		referencesOf(e.images[imageTools][clusterA]))
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{ref(groupApps, kindStatefulSet, "team-b-web", "cache")},
		referencesOf(e.images[imageRedis][clusterB]))
}

func TestReadExportReadsColumnsByNameWhateverTheirOrder(t *testing.T) {
	// A byte order mark, other columns in between, odd case and spaces in the header, and a
	// quoted field with a comma.
	export := "\xef\xbb\xbfimage,extra,Workload, namespace ,CLUSTER\n" +
		`artifacts.example/lib/app:1,"x,y",ReplicaSet/web-1,ns-1,cluster-x` + "\n"

	e, err := readExport(strings.NewReader(export))

	require.NoError(t, err)
	require.Equal(t, 1, e.rows)
	require.Zero(t, e.malformed+e.unknownKind)
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{ref(groupApps, kindReplicaSet, "ns-1", "web-1")},
		referencesOf(e.images["artifacts.example/lib/app:1"]["cluster-x"]))
}

func TestReadExportTrimsTheSpacesAroundAValue(t *testing.T) {
	export := "cluster,namespace,workload,image\n" +
		" cluster-x , ns-1 , ReplicaSet/web-1 , artifacts.example/lib/app:1 \n"

	e, err := readExport(strings.NewReader(export))

	require.NoError(t, err)
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{ref(groupApps, kindReplicaSet, "ns-1", "web-1")},
		referencesOf(e.images["artifacts.example/lib/app:1"]["cluster-x"]))
}

func TestReadExportUsesTheFirstOfAColumnThatAppearsTwice(t *testing.T) {
	export := "cluster,namespace,workload,image,image\n" +
		"cluster-x,ns-1,ReplicaSet/web-1,artifacts.example/lib/app:1,artifacts.example/lib/other:2\n"

	e, err := readExport(strings.NewReader(export))

	require.NoError(t, err)
	require.Contains(t, e.images, "artifacts.example/lib/app:1")
	require.NotContains(t, e.images, "artifacts.example/lib/other:2")
}

func TestReadExportNeedsTheFourColumns(t *testing.T) {
	for _, column := range []string{"cluster", "namespace", "workload", "image"} {
		t.Run(column, func(t *testing.T) {
			header := strings.Replace("cluster,namespace,workload,image", column, "other", 1)

			_, err := readExport(strings.NewReader(header + "\n"))

			require.ErrorContains(t, err, `no column "`+column+`"`)
		})
	}
	_, err := readExport(strings.NewReader(""))
	require.Error(t, err, "an empty export has no header")
}

func TestRepositoryOf(t *testing.T) {
	const (
		bare   = "busybox"
		app    = "artifacts.example/lib/app"
		nginx  = "artifacts.example/lib/nginx"
		redis  = "registry.example:5000/lib/redis"
		digest = "@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	for _, tc := range []struct{ image, want string }{
		{nginx + ":1.27", nginx},
		{nginx, nginx},
		{bare, bare},
		{bare + ":1.36", bare},
		{redis, redis},
		{redis + ":7.2", redis},
		{app + digest, app},
		{app + ":1.0" + digest, app},
		{"registry.example:5000/lib/app" + digest, "registry.example:5000/lib/app"},
		{"registry.example:5000/lib/app:1.0-rc.1" + digest, "registry.example:5000/lib/app"},
		{":tag", ""},
		{digest, ""},
	} {
		require.Equal(t, tc.want, repositoryOf(tc.image), tc.image)
	}
}

func TestKindsAndTheirGroups(t *testing.T) {
	// The groups are written out here, and the kinds are those of the export.
	for want, kinds := range map[string][]string{
		"apps":  {"ReplicaSet", "Deployment", "StatefulSet", "DaemonSet"},
		"batch": {"Job", "CronJob"},
		"":      {"Pod"},
	} {
		for _, kind := range kinds {
			group, known := groupOfKind(kind)
			require.True(t, known, kind)
			require.Equal(t, want, group, kind)
		}
	}
	for _, kind := range []string{"Rollout", "ReplicationController", "deployment", "", "Deployment "} {
		_, known := groupOfKind(kind)
		require.False(t, known, "%q", kind)
	}
}

func TestDigestsAreSyntheticAndValid(t *testing.T) {
	pattern := regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	for _, image := range []string{imageNginx, imageRedis, "x"} {
		for _, i := range []int{0, 1, 9, 10, 1000} {
			digest := digestOf(image, i)

			require.Equal(t, wantDigest(image, i), digest)
			require.Regexp(t, pattern, digest, "the digest pattern of the CRD")
			// The name is the digest with the colon replaced, and has to survive the trip back.
			back, ok := inventory.DigestForName(inventory.NameForDigest(digest))
			require.True(t, ok, "the name rule of the CRD")
			require.Equal(t, digest, back)
		}
	}
	require.NotEqual(t, digestOf(imageNginx, 0), digestOf(imageNginx, 1))
	require.NotEqual(t, digestOf(imageNginx, 1), digestOf(imageNginx, 2))
	require.Equal(t, hashOf(clusterA), clusterIDOf(clusterA))
	require.Len(t, clusterIDOf(clusterA), 64, "the longest cluster ID that the CRD allows")
}

func TestLoadCreatesOneObjectPerImage(t *testing.T) {
	c := newFake(t, interceptor.Funcs{})

	code, _ := runTool(t, c, flagCSV, fixture)

	require.Equal(t, exitOK, code)
	loaded := objects(t, c)
	require.Len(t, loaded, fixtureImages)

	nginx := loaded[wantDigest(imageNginx, 0)]
	require.Equal(t, inventory.NameForDigest(wantDigest(imageNginx, 0)), nginx.Name)
	require.Equal(t, ptr.To(inventoryv1alpha1.DigestKindRepoDigest), nginx.Status.DigestKind,
		"a synthetic digest has a repository")
	require.Len(t, nginx.Status.Clusters, 2, "one entry for each cluster that runs the image")

	inA, inB := nginx.Status.Clusters[0], nginx.Status.Clusters[1]
	require.Equal(t, clusterA, inA.Cluster)
	require.Equal(t, hashOf(clusterA), inA.ClusterID)
	require.Equal(t, ptr.To(int32(2)), inA.NamespaceCount, "the distinct namespaces of the rows")
	require.Equal(t, ptr.To(int32(3)), inA.WorkloadCount, "one workload for each row")
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{
		ref(groupBatch, kindJob, "team-a-batch", "report-28911"),
		ref(groupApps, kindReplicaSet, "team-a-web", "api-5f6d8c"),
		ref(groupApps, kindReplicaSet, "team-a-web", "web-7d9c4b"),
	}, inA.Workloads)
	require.Equal(t, []string{"artifacts.example/lib/nginx"}, inA.Repositories, "the image without its tag")
	require.Equal(t, clusterB, inB.Cluster)
	require.Equal(t, hashOf(clusterB), inB.ClusterID)
	require.Equal(t, ptr.To(int32(1)), inB.NamespaceCount)
	require.Equal(t, ptr.To(int32(1)), inB.WorkloadCount)

	// The repository of an image with a registry port, a tag and a digest is the plain repository.
	redis := loaded[wantDigest(imageRedis, 0)]
	require.Len(t, redis.Status.Clusters, 1)
	require.Equal(t, []string{"registry.example:5000/lib/redis"}, redis.Status.Clusters[0].Repositories)

	// A Pod has no API group, and a pair that runs in one namespace counts one.
	agent := loaded[wantDigest(imageAgent, 0)].Status.Clusters[0]
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{
		ref(groupApps, kindDaemonSet, "team-a-web", "agent"),
		ref(groupCore, kindPod, "team-a-web", "debug-shell"),
	}, agent.Workloads)
	require.Equal(t, ptr.To(int32(1)), agent.NamespaceCount)
}

func TestScaleMakesCopiesOfEveryObject(t *testing.T) {
	c := newFake(t, interceptor.Funcs{})

	code, _ := runTool(t, c, flagCSV, fixture, "--scale=3")

	require.Equal(t, exitOK, code)
	loaded := objects(t, c)
	require.Len(t, loaded, 3*fixtureImages, "three times as many objects")
	for _, image := range []string{imageNginx, imageRedis, imageAgent, imageTools} {
		for i := range 3 {
			require.Contains(t, loaded, wantDigest(image, i), "copy %d of %s", i, image)
		}
	}
	// A copy is the same object, but for its digest.
	first, second := loaded[wantDigest(imageNginx, 0)], loaded[wantDigest(imageNginx, 2)]
	require.Equal(t, first.Status.Clusters[0].Workloads, second.Status.Clusters[0].Workloads)
	require.Equal(t, first.Status.Clusters[1].ClusterID, second.Status.Clusters[1].ClusterID)
}

func TestScaleOverAnEarlierLoadAddsTheMissingCopies(t *testing.T) {
	c := newFake(t, interceptor.Funcs{})
	runTool(t, c, flagCSV, fixture)
	require.Len(t, objects(t, c), fixtureImages)

	code, _ := runTool(t, c, flagCSV, fixture, "--scale=3")

	require.Equal(t, exitOK, code)
	require.Len(t, objects(t, c), 3*fixtureImages, "copy 0 is the object of the first load, and is not made twice")
}

func TestLoadingTheSameExportAgainChangesNothing(t *testing.T) {
	c := newFake(t, interceptor.Funcs{})
	runTool(t, c, flagCSV, fixture, "--scale=2")
	before := objects(t, c)

	code, _ := runTool(t, c, flagCSV, fixture, "--scale=2")

	require.Equal(t, exitOK, code)
	require.Equal(t, before, objects(t, c), "nothing is written when nothing changes")
}

func TestTheOutputHoldsAggregatesOnly(t *testing.T) {
	c := newFake(t, interceptor.Funcs{})

	code, output := runTool(t, c, flagCSV, fixture, "--scale=2")

	require.Equal(t, exitOK, code)
	require.Contains(t, output, "export rows=13 skipped=5 malformed=4 unknown_kind=1 images=4 pairs=5\n")
	require.Contains(t, output, "load scale=2 digests=8 entries=10 failed=0\n")
	require.Regexp(t, `(?m)^sizes objects=8 p50=\d+ p95=\d+ max=\d+ total=\d+ over_512KiB=0$`, output)
	// No name of the export: not a cluster, a namespace, a workload, an image or a kind, and no digest.
	for _, name := range []string{
		"cluster-", "team-", "web", "api-", "report", "artifacts.example", "registry.example", "nginx",
		"redis", "agent", "tools", "Rollout", kindReplicaSet, kindDeployment, "sha256",
	} {
		require.NotContains(t, output, name)
	}
}

func TestFailuresAreCountedByReasonAndNeverQuoted(t *testing.T) {
	// The error of the API server for one object names an input of the export, and a network error
	// names a host. Neither may reach the output, but the reason of the first may.
	invalid := apierrors.NewInvalid(schema.GroupKind{Group: "inventory.vexplain.bedag.ch", Kind: "ImageInventory"},
		"sha256-"+hashOf(imageTools),
		field.ErrorList{field.Invalid(field.NewPath("spec", "digest"), imageTools, "no")})
	unreachable := errors.New(`Post "https://api.internal.example/apis": connection refused`)
	toolsDigest, agentDigest := wantDigest(imageTools, 0), wantDigest(imageAgent, 0)
	c := newFake(t, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object,
		opts ...client.CreateOption) error {
		switch obj.(*inventoryv1alpha1.ImageInventory).Spec.Digest {
		case toolsDigest:
			return invalid
		case agentDigest:
			return unreachable
		}
		return c.Create(ctx, obj, opts...)
	}})

	code, output := runTool(t, c, flagCSV, fixture)

	require.Equal(t, exitFailure, code)
	require.Contains(t, output, "load scale=1 digests=4 entries=3 failed=2 reasons=Invalid:1,Unclassified:1\n")
	require.Regexp(t, `(?m)^sizes objects=2 `, output, "what did get loaded is measured")
	require.Len(t, objects(t, c), 2, "a failure doesn't stop the others")
	for _, quoted := range []string{"artifacts.example", "api.internal", "connection refused", "sha256", "spec.digest"} {
		require.NotContains(t, output, quoted)
	}
}

func TestSizesAreMeasuredFromTheObjectsInTheCluster(t *testing.T) {
	c := newFake(t, interceptor.Funcs{})
	runTool(t, c, flagCSV, fixture)
	want := make([]int, 0, fixtureImages)
	for _, item := range objects(t, c) {
		want = append(want, jsonSize(t, item))
	}

	stats, err := measure(context.Background(), c)

	require.NoError(t, err)
	require.Len(t, want, fixtureImages)
	require.Equal(t, fixtureImages, stats.objects)
	total := 0
	for _, size := range want {
		total += size
	}
	require.Equal(t, total, stats.total)
	require.Equal(t, slices.Max(want), stats.max)
	require.Equal(t, 0, stats.over)
}

func TestSizesAreMeasuredOverEveryPage(t *testing.T) {
	// A server may answer a list with fewer objects than asked for, and a continue token. This one
	// answers three at a time, so that the objects of the fixture, loaded twice, come in three pages.
	const perPage = 3
	pages := 0
	paged := newFake(t, interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
		opts ...client.ListOption) error {
		if err := c.List(ctx, list, opts...); err != nil {
			return err
		}
		var asked client.ListOptions
		for _, opt := range opts {
			opt.ApplyToList(&asked)
		}
		start := 0
		if asked.Continue != "" {
			var err error
			if start, err = strconv.Atoi(asked.Continue); err != nil {
				return err
			}
		}
		items := list.(*inventoryv1alpha1.ImageInventoryList)
		total := len(items.Items)
		end := min(start+perPage, total)
		items.Items = items.Items[start:end]
		items.Continue = ""
		if end < total {
			items.Continue = strconv.Itoa(end)
		}
		pages++
		return nil
	}})
	runTool(t, paged, flagCSV, fixture, "--scale=2")
	pages = 0

	stats, err := measure(context.Background(), paged)

	require.NoError(t, err)
	require.Equal(t, 2*fixtureImages, stats.objects, "every object, from every page")
	require.Equal(t, 3, pages, "8 objects, three at a time")
}

func TestSummarize(t *testing.T) {
	kib := 1024
	stats := summarize([]int{300 * kib, 10, 20, 30, 40, 50, 60, 70, 80, 600 * kib})

	require.Equal(t, 10, stats.objects)
	require.Equal(t, 50, stats.p50, "the nearest rank of 10 values")
	require.Equal(t, 600*kib, stats.p95)
	require.Equal(t, 600*kib, stats.max)
	require.Equal(t, 300*kib+600*kib+360, stats.total)
	require.Equal(t, 1, stats.over, "only the object above 512 KiB is over the trigger")

	require.Equal(t, 1, summarize([]int{512*kib + 1}).over)
	require.Equal(t, 0, summarize([]int{512 * kib}).over, "512 KiB itself is not above it")
	require.Equal(t, sizeStats{}, summarize(nil))
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no export":        {},
		"no scale":         {flagCSV, fixture, "--scale=0"},
		"a negative scale": {flagCSV, fixture, "--scale=-1"},
		"scale as text":    {flagCSV, fixture, "--scale=many"},
		"an unknown flag":  {flagCSV, fixture, "--delete"},
		"a stray argument": {flagCSV, fixture, "more"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newFake(t, interceptor.Funcs{})

			code, output := runTool(t, c, args...)

			require.Equal(t, exitUsage, code)
			require.Contains(t, output, "Usage:")
			require.Empty(t, objects(t, c))
		})
	}
	code, output := runTool(t, newFake(t, interceptor.Funcs{}), "--help")
	require.Equal(t, exitOK, code)
	require.Contains(t, output, "Usage:")
}

func TestAnExportThatCannotBeUsedFailsBeforeTouchingTheCluster(t *testing.T) {
	dir := t.TempDir()
	noRows := dir + "/no-rows.csv"
	allSkipped := dir + "/all-skipped.csv"
	noImageColumn := dir + "/no-image-column.csv"
	writeFile(t, noRows, "cluster,namespace,workload,image\n")
	writeFile(t, allSkipped, "cluster,namespace,workload,image\ncluster-a,ns,Rollout/x,artifacts.example/lib/app:1\n")
	writeFile(t, noImageColumn, "cluster,namespace,workload\ncluster-a,ns,ReplicaSet/x\n")

	for name, path := range map[string]string{
		"no such file":      dir + "/missing.csv",
		"no rows":           noRows,
		"every row skipped": allSkipped,
		"a missing column":  noImageColumn,
	} {
		t.Run(name, func(t *testing.T) {
			connected := false
			var out bytes.Buffer

			code := run(context.Background(), []string{flagCSV, path}, &out, func() (client.Client, error) {
				connected = true
				return newFake(t, interceptor.Funcs{}), nil
			})

			require.Equal(t, exitFailure, code)
			require.False(t, connected, "nothing is loaded from an export that can't be used")
			require.NotContains(t, out.String(), dir, "the path of the export is not printed")
		})
	}
}

func TestAClusterThatIsRefusedLoadsNothing(t *testing.T) {
	var out bytes.Buffer

	code := run(context.Background(), []string{flagCSV, fixture}, &out, func() (client.Client, error) {
		return nil, errors.New("not a local cluster")
	})

	require.Equal(t, exitFailure, code)
	require.Contains(t, out.String(), "not a local cluster")
}

func TestAnInterruptedLoadStops(t *testing.T) {
	c := newFake(t, interceptor.Funcs{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer

	code := run(ctx, []string{flagCSV, fixture}, &out, connectTo(c))

	require.Equal(t, exitFailure, code)
	require.Contains(t, out.String(), "interrupted")
	require.Empty(t, objects(t, c))
}

func TestAnInterruptionStopsTheLoadInTheMiddle(t *testing.T) {
	// The load is interrupted when the third object is created. Of the 200 that --scale=50 would make,
	// only the ones that were under way are written: at most one for each worker.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var created atomic.Int32
	c := newFake(t, interceptor.Funcs{Create: func(_ context.Context, c client.WithWatch, obj client.Object,
		opts ...client.CreateOption) error {
		if created.Add(1) == 3 {
			cancel()
		}
		return c.Create(ctx, obj, opts...)
	}})
	var out bytes.Buffer

	code := run(ctx, []string{flagCSV, fixture, "--scale=50"}, &out, connectTo(c))

	require.Equal(t, exitFailure, code)
	require.Contains(t, out.String(), "interrupted")
	require.Less(t, len(objects(t, c)), 3+workers+1)
}

func TestNearestRank(t *testing.T) {
	sorted := []int{10, 20, 30, 40, 50}

	require.Equal(t, 30, nearestRank(sorted, 50))
	require.Equal(t, 50, nearestRank(sorted, 95))
	require.Equal(t, 10, nearestRank(sorted, 1))
	require.Equal(t, 50, nearestRank(sorted, 100))
	require.Equal(t, 7, nearestRank([]int{7}, 95))
	require.Zero(t, nearestRank(nil, 50))
}
