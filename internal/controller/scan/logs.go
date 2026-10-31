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

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/scan/result"
)

// This file reads what a scan pod's log says. The log is the trust boundary of a scan: a line in
// it proves nothing about where it came from, and an image's content can be crafted. So nothing in
// a log is stored before it has been checked against the scan that the Job asked for, only a pod
// that succeeded can deliver a result, and what the runner logs about a log is a fixed text.

const (
	// scannerContainer is the name of the one container of a scan pod.
	scannerContainer = "scanner"
	// maxLogBytes is the most of a scan pod's log that is read: 8 MiB. A log that long can't hold a
	// whole result line, because the line may go on beyond what was read.
	maxLogBytes = 8 << 20
	// maxResultBytes is the most JSON that a result line may decode to: 64 MiB.
	maxResultBytes = 64 << 20
	// maxManifests is the most platforms that the facts of an ImageInventory hold.
	maxManifests = 16
	// maxPlatformLength is the longest platform that the API holds.
	maxPlatformLength = 64
)

// platformPattern matches a platform as the API holds one: os/architecture[/variant].
var platformPattern = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)

// The runner reads the logs of its scan pods, which run in its namespace, and of no other pod.
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get,namespace=vexplain-system

// LogReader reads the log of a scan pod.
type LogReader interface {
	// ScanLog returns the log of the container named scanner of the pod named pod in namespace. It
	// reads 8 MiB at most: of a longer log, it returns the first 8 MiB.
	ScanLog(ctx context.Context, namespace, pod string) (string, error)
}

// NewLogReader returns a LogReader that reads the logs through the API server, with cs.
func NewLogReader(cs kubernetes.Interface) LogReader {
	return &podLogReader{clientset: cs}
}

// podLogReader reads the logs of pods through the API server, which asks the kubelet for them.
type podLogReader struct {
	clientset kubernetes.Interface
}

func (r *podLogReader) ScanLog(ctx context.Context, namespace, pod string) (string, error) {
	stream, err := r.clientset.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{
		Container:  scannerContainer,
		LimitBytes: ptr.To(int64(maxLogBytes)),
	}).Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("read the log of scan pod %s/%s: %w", namespace, pod, err)
	}
	defer func() { _ = stream.Close() }()
	// The API server passes the limit on to the kubelet. The reader holds to it all the same, so that
	// a server that sends more can't make the operator read it.
	log, err := io.ReadAll(io.LimitReader(stream, maxLogBytes))
	if err != nil {
		return "", fmt.Errorf("read the log of scan pod %s/%s: %w", namespace, pod, err)
	}
	return string(log), nil
}

// scanCall is what a scan Job asked the scanner for, as the arguments of its container say.
type scanCall struct {
	// digest is the digest that the Job scans.
	digest string
	// image is the --image argument: the repository to pull from, and the digest.
	image string
	// platforms are the --platform arguments.
	platforms []string
}

// scanOutcome is what a finished scan found: a result whose every manifest passed the checks, or
// the reason why the scan failed, and never both.
type scanOutcome struct {
	// result is what the scan found. It is nil when the scan failed.
	result *result.Result
	// reason is why the scan failed. It is empty when the scan succeeded.
	reason inventoryv1alpha1.ScanFailureReason
	// why says in a fixed text why the scan failed. Nothing in it comes from the log.
	why string
}

// failedWith returns the outcome of a scan that failed for reason, for the cause why.
func failedWith(reason inventoryv1alpha1.ScanFailureReason, why string) scanOutcome {
	return scanOutcome{reason: reason, why: why}
}

// succeededScan reads the log of a scan pod that succeeded, the only kind of pod that delivers a
// result. The result must be the one line of the log, and must fit the scan that call asked for in
// every manifest, or the scan failed: TooLarge when the log or the result is larger than the
// operator reads, and Internal for anything else, since the scanner never prints such a result.
func succeededScan(log string, call scanCall) scanOutcome {
	if len(log) >= maxLogBytes {
		return failedWith(inventoryv1alpha1.ScanFailureReasonTooLarge, "the log reached the size limit, so its line can't be whole")
	}
	r, reason, err := result.Parse(log, maxResultBytes)
	switch {
	case errors.Is(err, result.ErrTooLarge):
		return failedWith(inventoryv1alpha1.ScanFailureReasonTooLarge, err.Error())
	case err != nil:
		// The errors of Parse are fixed texts.
		return failedWith(inventoryv1alpha1.ScanFailureReasonInternal, err.Error())
	case reason != "":
		return failedWith(inventoryv1alpha1.ScanFailureReasonInternal, "the scan pod succeeded, but printed an error line")
	}
	if why := check(r, call); why != "" {
		return failedWith(inventoryv1alpha1.ScanFailureReasonInternal, why)
	}
	return scanOutcome{result: r}
}

// check returns why r doesn't fit the scan that call asked for, or "" when it does:
//   - it names the image of the --image argument, byte for byte
//   - it has 1 to 16 manifests, each of a platform of its own
//   - each manifest fits the scan, as checkManifest says
func check(r *result.Result, call scanCall) string {
	if r.Image != call.image {
		return "the result names another image than the scan asked for"
	}
	if len(r.Manifests) == 0 || len(r.Manifests) > maxManifests {
		return fmt.Sprintf("the result has %d manifests, and not 1 to %d", len(r.Manifests), maxManifests)
	}
	platforms := make(map[string]bool, len(r.Manifests))
	for _, m := range r.Manifests {
		if why := checkManifest(m, call); why != "" {
			return why
		}
		if platforms[m.Platform] {
			return "two manifests of the result have the same platform"
		}
		platforms[m.Platform] = true
	}
	return ""
}

// checkManifest returns why m doesn't fit the scan that call asked for, or "" when it does. Its
// digest and its platform must be values that the API holds. Its platform must match one that the
// scan asked for, unless the manifest is the digest of the scan itself: an image of one manifest,
// and no index, is scanned whatever its platform. Its SBOM must be a JSON object with members, and
// its count of ELF files a number that the API holds.
func checkManifest(m result.Manifest, call scanCall) string {
	switch {
	case !digestPattern.MatchString(m.Digest):
		return "a manifest of the result has no sha256 digest"
	case len(m.Platform) > maxPlatformLength || !platformPattern.MatchString(m.Platform):
		return "a manifest of the result has a platform that the API can't hold"
	case m.Digest != call.digest && !slices.ContainsFunc(call.platforms, func(requested string) bool {
		return result.PlatformMatches(requested, m.Platform)
	}):
		return "a manifest of the result is of a platform that the scan didn't ask for"
	case !isObjectWithMembers(m.SBOM):
		return "a manifest of the result has no SBOM"
	case m.ELF.Total < 0 || m.ELF.Total > math.MaxInt32:
		return "a manifest of the result has a count of ELF files that the API can't hold"
	}
	return ""
}

// isObjectWithMembers reports whether raw is a JSON object with at least one member. raw comes from
// a JSON decoder, which has checked that it is valid JSON, so its first characters tell.
func isObjectWithMembers(raw json.RawMessage) bool {
	const space = " \t\r\n"
	value := bytes.TrimLeft(raw, space)
	if len(value) == 0 || value[0] != '{' {
		return false
	}
	members := bytes.TrimLeft(value[1:], space)
	return len(members) > 0 && members[0] != '}'
}

// failedScan reads the log of a scan pod that failed. Only the reason of its error line counts: a
// result line in it is ignored, and a pod that failed without saying why, such as an evicted one,
// failed for a reason of its own, Internal.
func failedScan(log string) scanOutcome {
	if len(log) >= maxLogBytes {
		return failedWith(inventoryv1alpha1.ScanFailureReasonTooLarge, "the log reached the size limit, so its line can't be whole")
	}
	_, reason, err := result.Parse(log, maxResultBytes)
	switch {
	case err != nil:
		// The errors of Parse are fixed texts.
		return failedWith(inventoryv1alpha1.ScanFailureReasonInternal, "the scan pod failed without an error line: "+err.Error())
	case reason == "":
		return failedWith(inventoryv1alpha1.ScanFailureReasonInternal, "the scan pod failed, but printed a result line")
	}
	// The scanner's reasons are values of the API's enum, spelled the same.
	return failedWith(inventoryv1alpha1.ScanFailureReason(reason), "the scanner reported why the scan failed")
}

// scanLog returns the log of pod, a scan pod that has finished, and reports false when the pod has
// no log: its container never ran, or the log is gone. The API server answers the read of a log that
// is gone with Bad Request, as the kubelet does for a container that it no longer has, and a pod that
// has finished won't get one back. Any other error is returned, so that the read is tried again.
func (r *Runner) scanLog(ctx context.Context, pod *corev1.Pod) (string, bool, error) {
	if !scannerRan(pod) {
		return "", false, nil
	}
	log, err := r.Logs.ScanLog(ctx, pod.Namespace, pod.Name)
	switch {
	case apierrors.IsBadRequest(err):
		return "", false, nil
	case err != nil:
		return "", false, err
	}
	return log, true, nil
}

// scannerRan reports whether the scanner container of pod has run, so that it can have a log, as the
// kubelet judges it: the container runs, or ended with the ID of a container that the runtime
// started. A container that waited, such as one of a pod that the kubelet refused, or whose end the
// kubelet couldn't see, has no log to read.
func scannerRan(pod *corev1.Pod) bool {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != scannerContainer {
			continue
		}
		state, last := status.State, status.LastTerminationState
		return state.Running != nil ||
			(state.Terminated != nil && state.Terminated.ContainerID != "") ||
			(last.Terminated != nil && last.Terminated.ContainerID != "")
	}
	return false
}
