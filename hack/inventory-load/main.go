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

// Command inventory-load loads an export of the images that run in some clusters into ImageInventory
// objects, and measures how big the objects are. It is an early indicator for the storage decision
// (decision 0004): how big the objects of the ImageInventory API are, and how the cost of listing
// them grows with their number. It is an indicator and not a decision, which waits for a real cluster.
//
// The export is a CSV with a header. The tool reads the columns cluster, namespace, workload and
// image by name, and ignores the others. A row is one workload that runs one image in one cluster.
// The tool makes one object for each image, and one entry in it for each cluster that runs the image.
// Nothing of a real image or cluster is used but its name: the digest of an image is made up, as the
// sha256 of the image string, and so is the ID of a cluster, as the sha256 of its name.
//
// The real export is real platform data, so it never goes into the repository. The tool prints
// numbers only, never a name from the export: no cluster, namespace, workload or image.
//
// The operator must not run while the tool loads. The digests are made up, no pod runs them, and
// the operator would remove the entries of its own cluster. Install the CRDs only, with make install.
// The tool refuses a cluster whose API server is not on a loopback address, which kind's is.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/hack/internal/localcluster"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/workloads"
)

// The exit codes.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

const (
	// workers is the number of images that are written at once. An image is the unit of work, so no
	// two workers ever write the same object.
	workers = 16
	// qps and burst raise the rate limit of the client, which would make a load of many thousands of
	// objects, three requests each, take hours. The cluster is local.
	qps   = 400
	burst = 800
	// pageSize is the number of objects that the measurement reads at once.
	pageSize = 500

	// triggerBytes is the size above which an object fires the first trigger of decision 0004: 512 KiB.
	triggerBytes = 512 * 1024

	// unclassified is the reason that a failure gets when it is no answer of the API server.
	unclassified = "Unclassified"
)

const usage = `Usage: inventory-load --csv PATH [--scale N]

  --csv    the export to load: a CSV with the columns cluster, namespace, workload and image
  --scale  make N copies of every image (default 1). Copy 0 has the digest of the image itself and
           copy i the digest of the image with "#i" added, so a load with --scale=10 after one with
           --scale=1 makes the nine missing copies, and ends with ten times the objects.

The cluster is the one of the current context of the kubeconfig that KUBECONFIG names, which must be
the own kubeconfig of a local kind cluster, such as bin/kind-e2e.kubeconfig of make setup-test-e2e:

  KUBECONFIG=bin/kind-e2e.kubeconfig go run ./hack/inventory-load --csv PATH

The tool refuses to run without KUBECONFIG, when the name of the current context doesn't start with
kind-, and when the API server is not on a loopback address. Install the CRDs with make install, and
don't run the operator, which would remove the made-up digests.

The output has numbers only, never a name from the export.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, connectToLocalCluster)
	stop() // os.Exit doesn't run deferred calls.
	os.Exit(code)
}

// run is the tool. It takes what main takes from the process, so that a test can give it a client
// that is not a cluster, and read what it printed. It returns the exit code.
func run(ctx context.Context, args []string, out io.Writer, connect func() (client.Client, error)) int {
	cfg, err := parseArguments(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		say(out, "%s", usage)
		return exitOK
	case err != nil:
		say(out, "inventory-load: %v\n\n%s", err, usage)
		return exitUsage
	}

	// The export is read and checked before the cluster is touched.
	e, err := readExportFile(cfg.csv)
	if err != nil {
		say(out, "inventory-load: %s\n", reason(err))
		return exitFailure
	}
	say(out, "export rows=%d skipped=%d malformed=%d unknown_kind=%d images=%d pairs=%d\n",
		e.rows, e.malformed+e.unknownKind, e.malformed, e.unknownKind, len(e.images), e.pairs())
	if len(e.images) == 0 {
		say(out, "inventory-load: no row of the export can be loaded\n")
		return exitFailure
	}

	api, err := connect()
	if err != nil {
		say(out, "inventory-load: %s\n", reason(err))
		return exitFailure
	}
	// The tool only observes. The writes of Observe carry the cluster of each observation, and only
	// SetFacts would label a write with the store's own cluster, so the store needs no name.
	noName := func() string { return "" }
	result := load(ctx, inventory.NewCRDStore(api, nil, noName), e, cfg.scale)
	say(out, "load scale=%d digests=%d entries=%d failed=%d%s\n",
		cfg.scale, len(e.images)*cfg.scale, result.entries, result.failed(), result.reasons())
	if ctx.Err() != nil {
		say(out, "inventory-load: interrupted\n")
		return exitFailure
	}

	stats, err := measure(ctx, api)
	if err != nil {
		say(out, "inventory-load: %s\n", reason(err))
		return exitFailure
	}
	say(out, "sizes objects=%d p50=%d p95=%d max=%d total=%d over_512KiB=%d\n",
		stats.objects, stats.p50, stats.p95, stats.max, stats.total, stats.over)
	if result.failed() > 0 {
		return exitFailure
	}
	return exitOK
}

// say prints to out. The tool can do nothing about a terminal that it can't write to.
func say(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

// reason returns what an error says, without the path of a file. The path is the one of the export,
// and the output never names anything of it.
func reason(err error) string {
	var pathError *fs.PathError
	if errors.As(err, &pathError) {
		return pathError.Err.Error()
	}
	return err.Error()
}

// arguments are what the command line says.
type arguments struct {
	csv   string
	scale int
}

// parseArguments reads the flags. Its errors are for the person who ran the tool.
func parseArguments(args []string) (arguments, error) {
	flags := flag.NewFlagSet("inventory-load", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // run prints the error and the usage.
	path := flags.String("csv", "", "")
	scale := flags.Int("scale", 1, "")
	if err := flags.Parse(args); err != nil {
		return arguments{}, err
	}
	switch {
	case flags.NArg() > 0:
		return arguments{}, errors.New("unexpected arguments")
	case *path == "":
		return arguments{}, errors.New("--csv is required")
	case *scale < 1:
		return arguments{}, errors.New("--scale must be at least 1")
	}
	return arguments{csv: *path, scale: *scale}, nil
}

// pair is one image in one cluster, as the export describes it.
type pair struct {
	// namespaces are the distinct namespaces of the rows.
	namespaces map[string]struct{}
	// refs are the workloads of the rows, one for each row.
	refs []workloads.WorkloadRef
}

// export is what the CSV says, grouped by image and cluster, and what the tool skipped of it.
type export struct {
	// images maps an image, as the export writes it, to the clusters that run it.
	images map[string]map[string]*pair
	// rows is the number of rows that were read, the skipped ones included. malformed is the number
	// that could not be used, and unknownKind the number whose workload is of a kind that the tool
	// doesn't know.
	rows, malformed, unknownKind int
}

// pairs returns the number of pairs of an image and a cluster.
func (e *export) pairs() int {
	n := 0
	for _, clusters := range e.images {
		n += len(clusters)
	}
	return n
}

// The columns that the tool reads, and their positions in the header of one export.
const (
	columnCluster   = "cluster"
	columnNamespace = "namespace"
	columnWorkload  = "workload"
	columnImage     = "image"
)

// columns holds the position of each column that the tool reads.
type columns struct{ cluster, namespace, workload, image int }

// columnsOf finds the columns that the tool reads in a header. Names are matched without case and
// without the spaces around them. Of a column that appears twice, the first counts.
func columnsOf(header []string) (columns, error) {
	position := make(map[string]int, len(header))
	for i, name := range slices.Backward(header) { // backwards, so that the first of a name wins
		position[strings.ToLower(strings.TrimSpace(name))] = i
	}
	var found columns
	// A fixed order, so that an export that lacks several columns always names the same one.
	for _, column := range []struct {
		name string
		into *int
	}{
		{columnCluster, &found.cluster},
		{columnNamespace, &found.namespace},
		{columnWorkload, &found.workload},
		{columnImage, &found.image},
	} {
		i, ok := position[column.name]
		if !ok {
			return columns{}, fmt.Errorf("the header of the export has no column %q", column.name)
		}
		*column.into = i
	}
	return found, nil
}

// readExportFile reads the export in a file.
func readExportFile(path string) (*export, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readExport(f)
}

// readExport reads an export. A row that can't be used is counted and skipped, and never stops the
// read. Only a header that lacks a column, or a read that fails, is an error.
func readExport(r io.Reader) (*export, error) {
	reader := bufio.NewReader(r)
	// A byte order mark, which some tools put in front of a CSV, would be part of the first name.
	if mark, err := reader.Peek(3); err == nil && bytes.Equal(mark, []byte("\xef\xbb\xbf")) {
		_, _ = reader.Discard(3)
	}
	// The reader takes the number of fields of the header for the number of every row, and reports
	// a row with another number as a parse error. So a row it returns has every column.
	rows := csv.NewReader(reader)
	header, err := rows.Read()
	if err != nil {
		return nil, fmt.Errorf("read the header of the export: %w", err)
	}
	positions, err := columnsOf(header)
	if err != nil {
		return nil, err
	}

	e := &export{images: make(map[string]map[string]*pair)}
	for {
		record, err := rows.Read()
		if errors.Is(err, io.EOF) {
			return e, nil
		}
		e.rows++
		var syntax *csv.ParseError
		switch {
		case errors.As(err, &syntax):
			// A bad quote, or another number of fields than the header has. The next row is a new
			// line, so it reads on.
			e.malformed++
		case err != nil:
			return nil, fmt.Errorf("read the export: %w", err)
		default:
			e.add(record, positions)
		}
	}
}

// The API groups and the kinds of workload that the tool knows. A Pod is in the core group, which is
// the empty one.
const (
	groupApps  = "apps"
	groupBatch = "batch"
	groupCore  = ""

	kindReplicaSet  = "ReplicaSet"
	kindDeployment  = "Deployment"
	kindStatefulSet = "StatefulSet"
	kindDaemonSet   = "DaemonSet"
	kindJob         = "Job"
	kindCronJob     = "CronJob"
	kindPod         = "Pod"
)

// groups maps the kinds of workload that the tool knows to their API groups.
var groups = map[string]string{
	kindReplicaSet:  groupApps,
	kindDeployment:  groupApps,
	kindStatefulSet: groupApps,
	kindDaemonSet:   groupApps,
	kindJob:         groupBatch,
	kindCronJob:     groupBatch,
	kindPod:         groupCore,
}

// groupOfKind returns the API group of a kind, and false for a kind that the tool doesn't know.
func groupOfKind(kind string) (string, bool) {
	group, known := groups[kind]
	return group, known
}

// add counts a row, and files it under its image and cluster unless it can't be used.
func (e *export) add(record []string, c columns) {
	cluster, namespace := strings.TrimSpace(record[c.cluster]), strings.TrimSpace(record[c.namespace])
	image, workload := strings.TrimSpace(record[c.image]), strings.TrimSpace(record[c.workload])
	kind, name, hasName := strings.Cut(workload, "/")
	if cluster == "" || namespace == "" || repositoryOf(image) == "" || !hasName || kind == "" || name == "" {
		e.malformed++
		return
	}
	group, known := groupOfKind(kind)
	if !known {
		e.unknownKind++
		return
	}

	clusters, ok := e.images[image]
	if !ok {
		clusters = make(map[string]*pair)
		e.images[image] = clusters
	}
	p, ok := clusters[cluster]
	if !ok {
		p = &pair{namespaces: make(map[string]struct{})}
		clusters[cluster] = p
	}
	p.namespaces[namespace] = struct{}{}
	p.refs = append(p.refs, workloads.WorkloadRef{APIGroup: group, Kind: kind, Namespace: namespace, Name: name})
}

// repositoryOf returns the image without its tag, and without its digest if it has one. A tag
// follows the last colon after the last slash: a colon before that one starts the port of a registry.
func repositoryOf(image string) string {
	// The digest goes first. It ends the string, and a tag may come before it.
	if at := strings.LastIndexByte(image, '@'); at >= 0 {
		image = image[:at]
	}
	if colon := strings.LastIndexByte(image, ':'); colon > strings.LastIndexByte(image, '/') {
		image = image[:colon]
	}
	return image
}

// digestOf returns the made-up digest of copy i of an image: "sha256:" and the hex sha256 of the
// image string, for copy 0, and of the image string with "#i" added for the others. It matches the
// pattern of spec.digest, and its name, the digest with the colon replaced, follows the name rule.
func digestOf(image string, i int) string {
	seed := image
	if i > 0 {
		seed += "#" + strconv.Itoa(i)
	}
	return "sha256:" + sha256Hex(seed)
}

// clusterIDOf returns the made-up ID of a cluster: the hex sha256 of its name, which is as long as
// an ID can be.
func clusterIDOf(cluster string) string {
	return sha256Hex(cluster)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// observation returns what the cluster reports about the image that this pair describes. A made-up
// digest has a repository, so it is a repository digest.
func (p *pair) observation(cluster, image string) inventory.Observation {
	return inventory.Observation{
		Cluster:        cluster,
		ClusterID:      clusterIDOf(cluster),
		DigestKind:     inventoryv1alpha1.DigestKindRepoDigest,
		Repositories:   []string{repositoryOf(image)},
		NamespaceCount: int32(len(p.namespaces)),
		Workloads:      p.refs, // the store sorts a copy, and keeps the first 100
	}
}

// loadResult is what a load did.
type loadResult struct {
	// entries is the number of entries that were written, and failures the number of failed writes
	// by the reason of the failure.
	entries  int
	failures map[string]int
}

// failed returns the number of failed writes.
func (r loadResult) failed() int {
	n := 0
	for _, count := range r.failures {
		n += count
	}
	return n
}

// reasons returns the failures as " reasons=Invalid:2,Timeout:1", or "" when there are none. It
// names the reason of the API server, such as Invalid, and nothing of the error: an error can quote
// the input of the object, or a host.
func (r loadResult) reasons() string {
	if len(r.failures) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.failures))
	for _, name := range slices.Sorted(maps.Keys(r.failures)) {
		parts = append(parts, fmt.Sprintf("%s:%d", name, r.failures[name]))
	}
	return " reasons=" + strings.Join(parts, ",")
}

// load writes the export into the store, scale copies of each image. The image is the unit of work,
// so no two workers write the same object, and a pair that is already in the store is not written
// again.
func load(ctx context.Context, store inventory.Store, e *export, scale int) loadResult {
	result := loadResult{failures: make(map[string]int)}
	var mu sync.Mutex
	record := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			result.entries++
			return
		}
		name := string(apierrors.ReasonForError(err))
		if name == "" {
			name = unclassified
		}
		result.failures[name]++
	}

	images := make(chan string)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for image := range images {
				for i := range scale {
					writeCopy(ctx, store, e.images[image], image, i, record)
				}
			}
		})
	}
feed:
	for _, image := range slices.Sorted(maps.Keys(e.images)) {
		select {
		case images <- image:
		case <-ctx.Done():
			break feed
		}
	}
	close(images)
	wg.Wait()
	return result
}

// writeCopy writes copy i of an image: its entry for every cluster that runs it.
func writeCopy(ctx context.Context, store inventory.Store, clusters map[string]*pair, image string, i int,
	record func(error)) {
	digest := digestOf(image, i)
	for _, cluster := range slices.Sorted(maps.Keys(clusters)) {
		if ctx.Err() != nil {
			return
		}
		record(store.Observe(ctx, digest, clusters[cluster].observation(cluster, image)))
	}
}

// sizeStats describes the sizes of the objects in the cluster, in bytes.
type sizeStats struct {
	objects int
	// p50 and p95 are percentiles by the nearest-rank method, and total is the sum of all sizes.
	p50, p95, max, total int
	// over is the number of objects above the trigger of 512 KiB.
	over int
}

// measure reads every ImageInventory object in the cluster, a page at a time, and returns the sizes
// of the objects. The size of an object is the length of the JSON that encodes it as the API server
// returned it, managed fields included. That is what the operator's own metric of the size of an
// object records after a write, and it is close to what the storage holds.
func measure(ctx context.Context, api client.Reader) (sizeStats, error) {
	var sizes []int
	options := []client.ListOption{client.Limit(pageSize)}
	for {
		var list inventoryv1alpha1.ImageInventoryList
		if err := api.List(ctx, &list, options...); err != nil {
			return sizeStats{}, fmt.Errorf("list the ImageInventory objects: %w", err)
		}
		for i := range list.Items {
			raw, err := json.Marshal(&list.Items[i])
			if err != nil {
				return sizeStats{}, fmt.Errorf("encode an ImageInventory object: %w", err)
			}
			sizes = append(sizes, len(raw))
		}
		if list.Continue == "" {
			return summarize(sizes), nil
		}
		options = []client.ListOption{client.Limit(pageSize), client.Continue(list.Continue)}
	}
}

// summarize returns the statistics of a list of sizes.
func summarize(sizes []int) sizeStats {
	if len(sizes) == 0 {
		return sizeStats{}
	}
	sorted := slices.Sorted(slices.Values(sizes))
	stats := sizeStats{
		objects: len(sorted),
		p50:     nearestRank(sorted, 50),
		p95:     nearestRank(sorted, 95),
		max:     sorted[len(sorted)-1],
	}
	for _, size := range sorted {
		stats.total += size
		if size > triggerBytes {
			stats.over++
		}
	}
	return stats
}

// nearestRank returns the p-th percentile of sorted values by the nearest-rank method: the smallest
// value that at least p percent of the values are not above. It returns zero for no values.
func nearestRank(sorted []int, p int) int {
	if len(sorted) == 0 {
		return 0
	}
	rank := (p*len(sorted) + 99) / 100 // the rank is p/100 of the count, rounded up
	return sorted[min(max(rank, 1), len(sorted))-1]
}

// connectToLocalCluster returns a client for the local kind cluster of the kubeconfig that
// KUBECONFIG names, and refuses any other cluster, as localcluster.Connect does. The tool writes
// thousands of made-up objects, which belong on a local kind cluster and nowhere else.
func connectToLocalCluster() (client.Client, error) {
	scheme := runtime.NewScheme()
	if err := inventoryv1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register the ImageInventory API: %w", err)
	}
	return localcluster.Connect(scheme, func(cfg *rest.Config) { cfg.QPS, cfg.Burst = qps, burst })
}
