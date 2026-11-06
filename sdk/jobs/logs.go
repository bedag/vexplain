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

package jobs

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// maxLogBytes is the most of a pod's log that a LogReader reads: 8 MiB. A log that long can't hold a whole line,
// because the line may go on beyond what was read.
const maxLogBytes = 8 << 20

// LogReader reads the log of a Job's pod.
type LogReader interface {
	// Log returns the log of the container of the pod named pod in namespace. It reads 8 MiB at most: of a longer
	// log, it returns the first 8 MiB. A log that is gone is an error that apierrors.IsBadRequest reports.
	Log(ctx context.Context, namespace, pod, container string) (string, error)
}

// NewLogReader returns a LogReader that reads the logs through the API server, with cs.
func NewLogReader(cs kubernetes.Interface) LogReader {
	return &podLogReader{clientset: cs}
}

// podLogReader reads the logs of pods through the API server, which asks the kubelet for them.
type podLogReader struct {
	clientset kubernetes.Interface
}

func (r *podLogReader) Log(ctx context.Context, namespace, pod, container string) (string, error) {
	stream, err := r.clientset.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{
		Container:  container,
		LimitBytes: ptr.To(int64(maxLogBytes)),
	}).Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("read the log of pod %s/%s: %w", namespace, pod, err)
	}
	defer func() { _ = stream.Close() }()
	// The API server passes the limit on to the kubelet. The reader holds to it all the same, so that a server that
	// sends more can't make the collector read it.
	log, err := io.ReadAll(io.LimitReader(stream, maxLogBytes))
	if err != nil {
		return "", fmt.Errorf("read the log of pod %s/%s: %w", namespace, pod, err)
	}
	return string(log), nil
}
