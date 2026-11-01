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

package scan_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/scan"
)

// These tests check where the runner reads the settings of its scans: the spec.settings of the
// Collector named scanner, which is the scanner's own settings, whatever shape the scanner gives them.
// The runner reads the four settings below, and ignores any other key. A fake client, which applies no
// schema, stands for the API server: nothing in the Collector's schema keeps a value in bounds, so the
// runner does.

// maxConcurrentScans is the name of the setting that the specs refuse values of.
const maxConcurrentScans = "maxConcurrentScans"

// scannerWith returns the scanner Collector with settings, which is JSON.
func scannerWith(settings string) *configv1alpha1.Collector {
	return &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: scannerCollector},
		Spec: configv1alpha1.CollectorSpec{
			Package:  unitScannerImage,
			Settings: &runtime.RawExtension{Raw: []byte(settings)},
		},
	}
}

// busyScans returns n scan Jobs that hold a slot, for digests that no test scans. A Job holds a slot
// until it finishes, whether or not its pod has started.
func busyScans(n int) []client.Object {
	objs := make([]client.Object, 0, n)
	for i := range n {
		job, _ := scanJobOf("sha256:"+strings.Repeat(strconv.FormatInt(int64(i+1), 16), 64), corev1.PodRunning)
		job.Name = fmt.Sprintf("scan-busy-%d", i)
		job.UID = types.UID(fmt.Sprintf("busy-uid-%d", i))
		objs = append(objs, job)
	}
	return objs
}

// startedJob returns the one scan Job of unitDigest, which the runner started.
func (f *unitFixture) startedJob(t *testing.T) batchv1.Job {
	t.Helper()
	var list batchv1.JobList
	require.NoError(t, f.client.List(t.Context(), &list, client.InNamespace(runnerNamespace)))
	var started []batchv1.Job
	for _, job := range list.Items {
		if job.Annotations[scan.DigestLabel] == unitDigest {
			started = append(started, job)
		}
	}
	require.Len(t, started, 1)
	return started[0]
}

// The scans that run at once are at most maxConcurrentScans of the Collector's settings. Two scans
// run, which is as many as the default allows: the Collector allows three, so a request starts a Job,
// and with three running, a request waits.
func TestRunnerReadsMaxConcurrentScansFromTheSettingsOfTheCollector(t *testing.T) {
	t.Run("starts a scan while fewer than three run", func(t *testing.T) {
		objs := append(busyScans(2), workload(), scannerWith(`{"maxConcurrentScans":3}`))
		f := newUnitFixture(t, interceptor.Funcs{}, objs...)
		f.request(t)

		res, err := f.reconcile(t)

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, res)
		require.Len(t, f.jobs(t), 3, "the two that run, and the one that started")
	})

	t.Run("waits for a slot while three run", func(t *testing.T) {
		objs := append(busyScans(3), workload(), scannerWith(`{"maxConcurrentScans":3}`))
		f := newUnitFixture(t, interceptor.Funcs{}, objs...)
		f.request(t)

		res, err := f.reconcile(t)

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{RequeueAfter: 30 * time.Second}, res)
		require.Len(t, f.jobs(t), 3, "no Job started")
	})
}

func TestRunnerReadsTheOtherSettingsOfTheScansFromTheCollector(t *testing.T) {
	f := newUnitFixture(t, interceptor.Funcs{}, workload(),
		scannerWith(`{"scanTimeoutSeconds":600,"memoryLimitMebibytes":512,"workspaceMebibytes":2048}`))
	f.request(t)

	_, err := f.reconcile(t)

	require.NoError(t, err)
	job := f.startedJob(t)
	require.Equal(t, ptr.To(int64(600)), job.Spec.ActiveDeadlineSeconds)
	container := job.Spec.Template.Spec.Containers[0]
	memory := resource.MustParse("512Mi")
	require.True(t, memory.Equal(container.Resources.Limits[corev1.ResourceMemory]), "the memory limit is 512Mi")
	require.True(t, memory.Equal(container.Resources.Requests[corev1.ResourceMemory]), "the memory request is 512Mi")
	workspace := resource.MustParse("2Gi")
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if volume.Name == "work" {
			require.True(t, workspace.Equal(*volume.EmptyDir.SizeLimit), "the workspace is 2048Mi")
		}
	}
	// Three quarters of the workspace is what the scanner may unpack.
	require.Contains(t, container.Args, strconv.FormatInt(int64(2048)<<20*3/4, 10))
}

// A setting that the Collector leaves out, or a Collector that has no settings, gets the default, and
// a key that the runner doesn't read is left alone: the scanner's settings are the scanner's own.
func TestRunnerUsesTheDefaultsForSettingsThatTheCollectorLeavesOut(t *testing.T) {
	for name, collector := range map[string]*configv1alpha1.Collector{
		"a Collector without settings": {
			ObjectMeta: metav1.ObjectMeta{Name: scannerCollector},
			Spec:       configv1alpha1.CollectorSpec{Package: unitScannerImage},
		},
		"empty settings":                   scannerWith(`{}`),
		"null settings":                    scannerWith(`null`),
		"keys that the runner doesn't use": scannerWith(`{"registryMirrors":[{"host":"artifacts.example"}],"scanPod":{}}`),
	} {
		t.Run(name, func(t *testing.T) {
			f := newUnitFixture(t, interceptor.Funcs{}, append(busyScans(1), workload(), collector)...)
			f.request(t)

			_, err := f.reconcile(t)

			require.NoError(t, err)
			job := f.startedJob(t)
			require.Equal(t, ptr.To(int64(1800)), job.Spec.ActiveDeadlineSeconds)
			memory := resource.MustParse("2Gi")
			require.True(t, memory.Equal(job.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceMemory]))
		})
	}

	t.Run("two scans at once", func(t *testing.T) {
		f := newUnitFixture(t, interceptor.Funcs{}, append(busyScans(2), workload(), scannerWith(`{}`))...)
		f.request(t)

		res, err := f.reconcile(t)

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{RequeueAfter: 30 * time.Second}, res, "the default allows two, and two run")
	})
}

// A value that the runner can't use must not become a scan with a guess for a setting. The runner
// starts nothing, returns an error that names the setting, and reports it as the health of the Scanner,
// which an admin reads on the Collector.
func TestRunnerRefusesSettingsItCannotUse(t *testing.T) {
	refuses := func(t *testing.T, settings, named string) {
		t.Helper()
		f := newUnitFixture(t, interceptor.Funcs{}, workload(), scannerWith(settings))
		f.request(t)

		_, err := f.reconcile(t)

		require.ErrorContains(t, err, named)
		require.Empty(t, f.jobs(t), "no scan starts with a setting that was guessed")
		_, lastErr, known := f.registry.Health(scannerCollector)
		require.True(t, known)
		require.ErrorContains(t, lastErr, named, "the Scanner reports it, and the Collector shows it")
	}

	// Each setting has a range, and the first value below it and the first above it are refused.
	for _, setting := range []struct {
		name         string
		below, above int
	}{
		{maxConcurrentScans, 0, 33},
		{"scanTimeoutSeconds", 59, 21601},
		{"memoryLimitMebibytes", 255, 65537},
		{"workspaceMebibytes", 1023, 1048577},
	} {
		for _, value := range []int{setting.below, setting.above} {
			t.Run(fmt.Sprintf("%s of %d", setting.name, value), func(t *testing.T) {
				refuses(t, fmt.Sprintf(`{%q:%d}`, setting.name, value), setting.name)
			})
		}
	}

	for name, settings := range map[string]struct{ json, setting string }{
		"a number given as text":          {`{"maxConcurrentScans":"3"}`, maxConcurrentScans},
		"a number with a fraction":        {`{"maxConcurrentScans":2.5}`, maxConcurrentScans},
		"a number that doesn't fit int32": {`{"scanTimeoutSeconds":4294967296}`, "scanTimeoutSeconds"},
		"settings that are no object":     {`"three"`, scannerCollector},
		"settings that are a list":        {`[3]`, scannerCollector},
	} {
		t.Run(name, func(t *testing.T) { refuses(t, settings.json, settings.setting) })
	}
}

// The ends of every range are settings, and reach the Job.
func TestRunnerAcceptsSettingsAtTheEndsOfTheirRanges(t *testing.T) {
	for name, ends := range map[string]struct {
		settings        string
		deadlineSeconds int64
		memory          string
	}{
		"the lowest": {
			`{"maxConcurrentScans":1,"scanTimeoutSeconds":60,"memoryLimitMebibytes":256,"workspaceMebibytes":1024}`,
			60, "256Mi",
		},
		"the highest": {
			`{"maxConcurrentScans":32,"scanTimeoutSeconds":21600,"memoryLimitMebibytes":65536,"workspaceMebibytes":1048576}`,
			21600, "64Gi",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newUnitFixture(t, interceptor.Funcs{}, workload(), scannerWith(ends.settings))
			f.request(t)

			_, err := f.reconcile(t)

			require.NoError(t, err)
			job := f.startedJob(t)
			require.Equal(t, ptr.To(ends.deadlineSeconds), job.Spec.ActiveDeadlineSeconds)
			memory := resource.MustParse(ends.memory)
			require.True(t, memory.Equal(job.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceMemory]))
		})
	}
}
