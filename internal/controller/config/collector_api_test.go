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

package config_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// scanOperation is the name of an operation of the example collector.
const scanOperation = "scan"

// workloadsName and scannerName are the names of the sample Collectors.
const (
	workloadsName = "workloads"
	scannerName   = "scanner"
)

// These specs check the schema of the Collector against the API server. The kind installs a package,
// and holds the settings of that package, whose shape vexplain can't know.
var _ = Describe("Collector API", func() {
	// collectorNamed returns a Collector that the schema accepts.
	collectorNamed := func(name string) *configv1alpha1.Collector {
		return &configv1alpha1.Collector{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       configv1alpha1.CollectorSpec{Package: examplePackage},
		}
	}

	Describe("the spec", func() {
		It("refuses a Collector without a package", func() {
			err := k8sClient.Create(ctx, &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: apiName("hello")}})

			Expect(err).To(refusedWith("spec.package: Required value"))
		})

		It("refuses a package that is empty", func() {
			err := k8sClient.Create(ctx, rawObject("Collector", apiName("hello"), map[string]any{packageField: ""}))

			Expect(err).To(refusedWith("spec.package"))
		})

		It("refuses a package of 513 characters, and accepts one of 512", func() {
			tooLong := collectorNamed(apiName("hello"))
			tooLong.Spec.Package = "artifacts.example/" + strings.Repeat("a", 495)

			Expect(k8sClient.Create(ctx, tooLong)).To(refusedWith("spec.package"))

			longest := collectorNamed(apiName("hello"))
			longest.Spec.Package = "artifacts.example/" + strings.Repeat("a", 494)
			createObject(longest)
		})

		// vexplain can't know the settings of a collector that someone else wrote. The collector checks
		// them, so the Collector keeps them as they are, whatever their shape.
		DescribeTable("keeps settings of any shape",
			func(settings string) {
				obj := collectorNamed(apiName("hello"))
				obj.Spec.Settings = &runtime.RawExtension{Raw: []byte(settings)}
				createObject(obj)

				var got configv1alpha1.Collector
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
				Expect(got.Spec.Settings).NotTo(BeNil())
				Expect(got.Spec.Settings.Raw).To(MatchJSON(settings))
			},
			Entry("a flat object", `{"greeting":"Hello"}`),
			Entry("an empty object", `{}`),
			Entry("nested objects and lists of every kind of value",
				`{"maxConcurrentScans":3,"ratio":0.5,"enabled":true,"labels":{"team":"team-a"},`+
					`"registryMirrors":[{"host":"artifacts.example","url":"http://mirror.example:5000"}],"tags":["a","b"]}`),
			Entry("keys that no schema of vexplain knows", `{"setting-with-dashes":{"x.y":[1,2,3]},"UPPER":"case"}`),
		)

		It("refuses spec.type, the field of the earlier shape, as an unknown field", func() {
			spec := map[string]any{packageField: examplePackage, typeField: "Workloads", "workloads": map[string]any{}}

			err := k8sClient.Create(ctx, rawObject("Collector", apiName("hello"), spec), client.FieldValidation("Strict"))

			Expect(err).To(Satisfy(apierrors.IsBadRequest))
			Expect(err).To(MatchError(ContainSubstring(`unknown field "spec.type"`)))
			Expect(err).To(MatchError(ContainSubstring(`unknown field "spec.workloads"`)))
		})

		It("keeps the runtime config that a Collector names", func() {
			obj := collectorNamed(apiName("hello"))
			obj.Spec.RuntimeConfigRef = &configv1alpha1.RuntimeConfigReference{Name: vulnerabilitiesName}
			createObject(obj)

			var got configv1alpha1.Collector
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
			Expect(got.Spec.RuntimeConfigRef).To(Equal(&configv1alpha1.RuntimeConfigReference{Name: vulnerabilitiesName}))
		})

		DescribeTable("refuses a runtime config reference with",
			func(ref map[string]any, field string) {
				spec := map[string]any{packageField: examplePackage, "runtimeConfigRef": ref}

				err := k8sClient.Create(ctx, rawObject("Collector", apiName("hello"), spec))

				Expect(err).To(refusedWith(field))
			},
			Entry("no name", map[string]any{}, "spec.runtimeConfigRef.name: Required value"),
			Entry("an empty name", map[string]any{nameField: ""}, "spec.runtimeConfigRef.name"),
			Entry("an uppercase name", map[string]any{nameField: "Default"}, "spec.runtimeConfigRef.name"),
			Entry("a name of 254 characters", map[string]any{nameField: strings.Repeat("a", 254)}, "spec.runtimeConfigRef.name"),
		)
	})

	// A trigger names a schedule that the collector declares, and may replace its cron expression. Whether the name
	// is declared, and whether the expression parses, only the operator can tell: it says so in the Ready condition.
	Describe("the triggers", func() {
		// triggersSpec is the raw spec of a Collector with the triggers.
		triggersSpec := func(triggers ...any) map[string]any {
			return map[string]any{packageField: examplePackage, triggersField: triggers}
		}
		// triggerOf is a raw trigger of the name, with the cron expression unless it is empty.
		triggerOf := func(name, cron string) map[string]any {
			trigger := map[string]any{nameField: name}
			if cron != "" {
				trigger[scheduleField] = cron
			}
			return trigger
		}

		It("keeps triggers, with or without a cron expression", func() {
			obj := collectorNamed(apiName("hello"))
			obj.Spec.Triggers = []configv1alpha1.CollectorTrigger{
				{Name: scheduleRefresh, Schedule: ptr.To(cronHourly)}, {Name: scheduleCompact},
			}
			createObject(obj)

			var got configv1alpha1.Collector
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
			Expect(got.Spec.Triggers).To(Equal(obj.Spec.Triggers))
		})

		It("accepts 8 triggers, a name of 63 characters and a cron expression of 128", func() {
			obj := collectorNamed(apiName("hello"))
			for i := range 8 {
				obj.Spec.Triggers = append(obj.Spec.Triggers,
					configv1alpha1.CollectorTrigger{Name: fmt.Sprintf("schedule-%d", i), Schedule: ptr.To(cronHourly)})
			}
			obj.Spec.Triggers[0].Name = strings.Repeat("a", 63)
			obj.Spec.Triggers[1].Schedule = ptr.To(strings.Repeat("*", 128))

			createObject(obj)
		})

		DescribeTable("refuses a trigger with",
			func(trigger map[string]any, field string) {
				err := k8sClient.Create(ctx, rawObject("Collector", apiName("hello"), triggersSpec(trigger)))

				Expect(err).To(refusedWith(field))
			},
			Entry("no name", map[string]any{scheduleField: cronHourly}, "spec.triggers[0].name: Required value"),
			Entry("an empty name", map[string]any{nameField: "", scheduleField: cronHourly}, "spec.triggers[0].name"),
			Entry("a name of 64 characters", map[string]any{nameField: strings.Repeat("a", 64)}, "spec.triggers[0].name"),
			Entry("an empty cron expression", map[string]any{nameField: scheduleRefresh, scheduleField: ""},
				"spec.triggers[0].schedule"),
			Entry("a cron expression of 129 characters",
				map[string]any{nameField: scheduleRefresh, scheduleField: strings.Repeat("*", 129)}, "spec.triggers[0].schedule"),
		)

		It("refuses 9 triggers", func() {
			triggers := make([]any, 9)
			for i := range triggers {
				triggers[i] = triggerOf(fmt.Sprintf("schedule-%d", i), cronHourly)
			}

			err := k8sClient.Create(ctx, rawObject("Collector", apiName("hello"), triggersSpec(triggers...)))

			Expect(err).To(refusedWith("spec.triggers: Too many"))
		})

		It("refuses two triggers of one name", func() {
			spec := triggersSpec(triggerOf(scheduleRefresh, cronHourly), triggerOf(scheduleRefresh, cronWeekly))

			Expect(k8sClient.Create(ctx, rawObject("Collector", apiName("hello"), spec))).To(refusedWith("Duplicate value"))
		})
	})

	// A Collector's name is part of the names that the operator gives what it makes for the collector.
	// Playbooks name collectors with a DNS-1123 label, so a Collector's name is one too. The Service is
	// named vexplain-collector-<name>, which must be a DNS-1035 label of at most 63 characters, and so must
	// the first label of the collector's TLS server name: after the prefix, 44 characters are left.
	Describe("the name", func() {
		const (
			// servicePrefix starts the name of the Service of a collector, and of its Deployment and its
			// service account.
			servicePrefix = "vexplain-collector-"
			// longestName is what a label of 63 characters leaves of the name after servicePrefix.
			longestName = 63 - len(servicePrefix)
		)

		It("refuses a name with a dot, which is no DNS-1123 label", func() {
			err := k8sClient.Create(ctx, collectorNamed("hello.example"))

			Expect(err).To(refusedWith("a Collector is named with a DNS-1123 label"))
		})

		It("accepts a name of 44 characters, the longest that its Service can be named after", func() {
			// The rule of the Collector says 44, and this is where the number comes from.
			Expect(longestName).To(Equal(44))
			name := strings.Repeat("a", longestName)
			Expect(validation.IsDNS1035Label(servicePrefix+name)).To(BeEmpty(), "the Service name is a DNS-1035 label")

			createObject(collectorNamed(name))
		})

		DescribeTable("refuses a name that its Service can't be named after, of",
			func(length int) {
				name := strings.Repeat("a", length)
				Expect(validation.IsDNS1035Label(servicePrefix+name)).NotTo(BeEmpty(), "the Service name is no DNS-1035 label")

				err := k8sClient.Create(ctx, collectorNamed(name))

				// The message says why: the Service's name, and the 63 characters of a label.
				Expect(err).To(refusedWith("a Collector's name is at most 44 characters",
					"vexplain-collector-<name>", "DNS-1035 label of at most 63 characters"))
			},
			Entry("45 characters", longestName+1),
			Entry("63 characters, the longest DNS-1123 label", 63),
			Entry("64 characters", 64),
		)
	})

	Describe("the status", func() {
		// caps is what the identity service of a collector answered.
		caps := func() *configv1alpha1.CollectorCapabilities {
			return &configv1alpha1.CollectorCapabilities{
				Roles: []configv1alpha1.CollectorRole{"Spoke", "Hub"},
				Produces: []configv1alpha1.ProducedType{
					{Type: contentsType, Scope: "Hub"},
					{Type: presenceType, Scope: "Spoke"},
				},
				Consumes: []string{findingsType},
				Watch:    "Supported",
				Operations: []configv1alpha1.CollectorOperation{
					{Name: scanOperation, Produces: []string{contentsType}},
					{Name: "match", Produces: []string{findingsType}, Consumes: []string{contentsType}},
				},
			}
		}

		// patchCapabilities writes capabilities into the status of obj, as the operator does, and
		// returns the error of the API server. A merge patch leaves the conditions alone, which the
		// Collector controller of the suite writes meanwhile.
		patchCapabilities := func(obj *configv1alpha1.Collector, c *configv1alpha1.CollectorCapabilities) error {
			base := obj.DeepCopy()
			obj.Status.Capabilities = c
			return k8sClient.Status().Patch(ctx, obj, client.MergeFrom(base))
		}

		It("records the package that runs, its version and its capabilities", func() {
			obj := collectorNamed(apiName("hello"))
			createObject(obj)
			digest := "sha256:" + strings.Repeat("a", 64)
			base := obj.DeepCopy()
			obj.Status.PackageDigest = ptr.To(digest)
			obj.Status.Version = ptr.To("0.1.0")
			obj.Status.Capabilities = caps()

			Expect(k8sClient.Status().Patch(ctx, obj, client.MergeFrom(base))).To(Succeed())

			var got configv1alpha1.Collector
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
			Expect(got.Status.PackageDigest).To(HaveValue(Equal(digest)))
			Expect(got.Status.Version).To(HaveValue(Equal("0.1.0")))
			Expect(got.Status.Capabilities).To(Equal(caps()))
		})

		DescribeTable("refuses a package digest that is no sha256 digest",
			func(digest string) {
				obj := collectorNamed(apiName("hello"))
				createObject(obj)
				base := obj.DeepCopy()
				obj.Status.PackageDigest = ptr.To(digest)

				err := k8sClient.Status().Patch(ctx, obj, client.MergeFrom(base))

				Expect(err).To(refusedWith("status.packageDigest"))
			},
			Entry("a tag", "latest"),
			Entry("a short digest", "sha256:abc"),
			Entry("a digest in capitals", "sha256:"+strings.Repeat("A", 64)),
		)

		It("refuses a version of 129 characters", func() {
			obj := collectorNamed(apiName("hello"))
			createObject(obj)
			base := obj.DeepCopy()
			obj.Status.Version = ptr.To(strings.Repeat("1", 129))

			Expect(k8sClient.Status().Patch(ctx, obj, client.MergeFrom(base))).To(refusedWith("status.version"))
		})

		It("refuses a version that is empty", func() {
			obj := collectorNamed(apiName("hello"))
			createObject(obj)
			base := obj.DeepCopy()
			obj.Status.Version = ptr.To("")

			Expect(k8sClient.Status().Patch(ctx, obj, client.MergeFrom(base))).To(refusedWith("status.version"))
		})

		// Each case changes one thing in capabilities that the schema accepts, and names the field that
		// the API server refuses it at.
		DescribeTable("refuses capabilities with",
			func(change func(*configv1alpha1.CollectorCapabilities), message string) {
				obj := collectorNamed(apiName("hello"))
				createObject(obj)
				c := caps()
				change(c)

				Expect(patchCapabilities(obj, c)).To(refusedWith(message))
			},
			Entry("a role that no version knows",
				func(c *configv1alpha1.CollectorCapabilities) { c.Roles = []configv1alpha1.CollectorRole{"Edge"} },
				"status.capabilities.roles"),
			Entry("a role listed twice",
				func(c *configv1alpha1.CollectorCapabilities) {
					c.Roles = []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke, configv1alpha1.CollectorRoleSpoke}
				}, "Duplicate value"),
			Entry("a scope that no version knows",
				func(c *configv1alpha1.CollectorCapabilities) { c.Produces[0].Scope = "Cluster" },
				"status.capabilities.produces[0].scope"),
			Entry("a produced type listed twice",
				func(c *configv1alpha1.CollectorCapabilities) {
					c.Produces = append(c.Produces, configv1alpha1.ProducedType{Type: contentsType, Scope: configv1alpha1.EvidenceScopeSpoke})
				}, "Duplicate value"),
			Entry("a produced type outside the pattern of types",
				func(c *configv1alpha1.CollectorCapabilities) { c.Produces[0].Type = "image-contents" },
				"status.capabilities.produces[0].type"),
			Entry("33 produced types",
				func(c *configv1alpha1.CollectorCapabilities) { c.Produces = typesOfScope(33) },
				"status.capabilities.produces: Too many"),
			Entry("a consumed type outside the pattern of types",
				func(c *configv1alpha1.CollectorCapabilities) { c.Consumes = []string{"Findings"} },
				"status.capabilities.consumes[0]"),
			Entry("33 consumed types",
				func(c *configv1alpha1.CollectorCapabilities) { c.Consumes = typeNames(33) },
				"status.capabilities.consumes: Too many"),
			Entry("a consumed type listed twice",
				func(c *configv1alpha1.CollectorCapabilities) { c.Consumes = []string{findingsType, findingsType} },
				"Duplicate value"),
			Entry("a value of watch that no version knows",
				func(c *configv1alpha1.CollectorCapabilities) { c.Watch = "Always" },
				"status.capabilities.watch"),
			Entry("no value of watch",
				func(c *configv1alpha1.CollectorCapabilities) { c.Watch = "" },
				"status.capabilities.watch: Required value"),
			Entry("17 operations",
				func(c *configv1alpha1.CollectorCapabilities) { c.Operations = operationsNamed(17) },
				"status.capabilities.operations: Too many"),
			Entry("an operation listed twice",
				func(c *configv1alpha1.CollectorCapabilities) {
					c.Operations = append(c.Operations, configv1alpha1.CollectorOperation{Name: scanOperation})
				}, "Duplicate value"),
			Entry("an operation without a name",
				func(c *configv1alpha1.CollectorCapabilities) {
					c.Operations = []configv1alpha1.CollectorOperation{{Produces: []string{contentsType}}}
				}, "status.capabilities.operations[0].name: Required value"),
			Entry("an operation of a name of 64 characters",
				func(c *configv1alpha1.CollectorCapabilities) {
					c.Operations = []configv1alpha1.CollectorOperation{{Name: strings.Repeat("a", 64)}}
				}, "status.capabilities.operations[0].name"),
			Entry("a type outside the pattern that an operation produces",
				func(c *configv1alpha1.CollectorCapabilities) { c.Operations[0].Produces = []string{scanOperation} },
				"status.capabilities.operations[0].produces[0]"),
			Entry("a type outside the pattern that an operation consumes",
				func(c *configv1alpha1.CollectorCapabilities) { c.Operations[1].Consumes = []string{scanOperation} },
				"status.capabilities.operations[1].consumes[0]"),
			Entry("33 types that an operation produces",
				func(c *configv1alpha1.CollectorCapabilities) { c.Operations[0].Produces = typeNames(33) },
				"status.capabilities.operations[0].produces: Too many"),
		)

		It("accepts capabilities of a collector that does nothing but watch", func() {
			obj := collectorNamed(apiName("hello"))
			createObject(obj)

			Expect(patchCapabilities(obj, &configv1alpha1.CollectorCapabilities{Watch: "NotSupported"})).To(Succeed())
		})

		It("accepts capabilities at every bound", func() {
			obj := collectorNamed(apiName("hello"))
			createObject(obj)
			c := caps()
			c.Produces = typesOfScope(32)
			c.Consumes = typeNames(32)
			c.Operations = operationsNamed(16)
			c.Operations[0].Name = strings.Repeat("o", 63)
			c.Operations[0].Produces = typeNames(32)
			c.Operations[0].Consumes = typeNames(32)

			Expect(patchCapabilities(obj, c)).To(Succeed())
		})

		// The fields of the status of the schedules and of run now, as raw content names them.
		const (
			schedulesField   = "schedules"
			runNowField      = "lastHandledRunNow"
			lastFailureField = "lastFailure"
		)
		// patchRawStatus writes status, as raw content, into the status of obj with a merge patch, and returns the
		// error of the API server.
		patchRawStatus := func(obj *configv1alpha1.Collector, status map[string]any) error {
			patch, err := json.Marshal(map[string]any{statusField: status})
			Expect(err).NotTo(HaveOccurred())
			return k8sClient.Status().Patch(ctx, obj, client.RawPatch(types.MergePatchType, patch))
		}
		// scheduleOf is the raw status of a schedule that runs the cron expression.
		scheduleOf := func(name, cron string) map[string]any {
			return map[string]any{nameField: name, scheduleField: cron}
		}
		// failedSchedule is the raw status of a schedule whose last fire failed for the reason.
		failedSchedule := func(failure string) map[string]any {
			schedule := scheduleOf(scheduleRefresh, cronHourly)
			schedule[lastFailureField] = failure
			return schedule
		}
		schedulesOf := func(schedules ...any) map[string]any { return map[string]any{schedulesField: schedules} }

		It("records the schedules that run, each with its last fire, and the run-now value handled last", func() {
			obj := collectorNamed(apiName("hello"))
			createObject(obj)
			fired := metav1.NewTime(time.Date(2026, 11, 8, 6, 0, 0, 0, time.UTC))
			base := obj.DeepCopy()
			obj.Status.Schedules = []configv1alpha1.ScheduleStatus{
				{Name: scheduleCompact, Schedule: cronWeekly},
				{Name: scheduleRefresh, Schedule: cronEverySixHours, LastFireTime: &fired,
					LastFailure: ptr.To("Fire of collector hello: rpc error: code = Unavailable desc = connection refused")},
			}
			obj.Status.LastHandledRunNow = ptr.To("2026-11-08T13:42:05Z")

			Expect(k8sClient.Status().Patch(ctx, obj, client.MergeFrom(base))).To(Succeed())

			var got configv1alpha1.Collector
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
			Expect(got.Status.Schedules).To(HaveLen(2))
			Expect(got.Status.Schedules[0]).To(Equal(obj.Status.Schedules[0]))
			Expect(got.Status.Schedules[1]).To(And(
				HaveField("Name", scheduleRefresh), HaveField("Schedule", cronEverySixHours),
				HaveField("LastFireTime.Time", BeTemporally("==", fired.Time)),
				HaveField("LastFailure", Equal(obj.Status.Schedules[1].LastFailure))))
			Expect(got.Status.LastHandledRunNow).To(Equal(obj.Status.LastHandledRunNow))
		})

		It("accepts 8 schedules, a failure of 1024 characters and a run-now value of 128", func() {
			obj := collectorNamed(apiName("hello"))
			createObject(obj)
			status := schedulesOf(rawSchedules(8)...)
			status[schedulesField].([]any)[0] = failedSchedule(strings.Repeat("x", 1024))
			status[runNowField] = strings.Repeat("1", 128)

			Expect(patchRawStatus(obj, status)).To(Succeed())
		})

		DescribeTable("refuses the status of the schedules and of run now with",
			func(status map[string]any, field string) {
				obj := collectorNamed(apiName("hello"))
				createObject(obj)

				Expect(patchRawStatus(obj, status)).To(refusedWith(field))
			},
			Entry("9 schedules", schedulesOf(rawSchedules(9)...), "status.schedules: Too many"),
			Entry("a schedule twice", schedulesOf(scheduleOf(scheduleRefresh, cronHourly), scheduleOf(scheduleRefresh, cronWeekly)),
				"Duplicate value"),
			Entry("a schedule without a name", schedulesOf(map[string]any{scheduleField: cronHourly}),
				"status.schedules[0].name: Required value"),
			Entry("a schedule without a cron expression", schedulesOf(map[string]any{nameField: scheduleRefresh}),
				"status.schedules[0].schedule: Required value"),
			Entry("a name of 64 characters", schedulesOf(scheduleOf(strings.Repeat("a", 64), cronHourly)), "status.schedules[0].name"),
			Entry("a cron expression of 129 characters", schedulesOf(scheduleOf(scheduleRefresh, strings.Repeat("*", 129))),
				"status.schedules[0].schedule"),
			Entry("a failure of 1025 characters", schedulesOf(failedSchedule(strings.Repeat("x", 1025))),
				"status.schedules[0].lastFailure"),
			Entry("an empty failure", schedulesOf(failedSchedule("")), "status.schedules[0].lastFailure"),
			Entry("a run-now value of 129 characters", map[string]any{runNowField: strings.Repeat("1", 129)},
				"status.lastHandledRunNow"),
			Entry("an empty run-now value", map[string]any{runNowField: ""}, "status.lastHandledRunNow"),
		)
	})

	Describe("the samples", func() {
		// Both samples are what an admin copies, so each must be a Collector that the API server accepts.
		DescribeTable("are accepted",
			func(file, name string) {
				data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples", file))
				Expect(err).NotTo(HaveOccurred())
				sample := &configv1alpha1.Collector{}
				Expect(yaml.UnmarshalStrict(data, sample)).To(Succeed())

				createObject(sample)

				Expect(sample.Name).To(Equal(name))
				Expect(sample.Spec.Package).NotTo(BeEmpty())
			},
			Entry("the workloads sample", "config_v1alpha1_collector.yaml", workloadsName),
			Entry("the scanner sample", "config_v1alpha1_collector_scanner.yaml", scannerName),
		)
	})
})

// typeNames returns n different names of types that match the pattern of types.
func typeNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = "com.example.type" + strings.Repeat("x", i) + ".v1alpha1"
	}
	return names
}

// typesOfScope returns n produced types of different names, each with the scope Spoke.
func typesOfScope(n int) []configv1alpha1.ProducedType {
	produced := make([]configv1alpha1.ProducedType, n)
	for i, name := range typeNames(n) {
		produced[i] = configv1alpha1.ProducedType{Type: name, Scope: configv1alpha1.EvidenceScopeSpoke}
	}
	return produced
}

// rawSchedules returns the raw status of n schedules of different names.
func rawSchedules(n int) []any {
	schedules := make([]any, n)
	for i := range schedules {
		schedules[i] = map[string]any{nameField: fmt.Sprintf("schedule-%d", i), scheduleField: cronHourly}
	}
	return schedules
}

// operationsNamed returns n operations of different names that produce and consume nothing.
func operationsNamed(n int) []configv1alpha1.CollectorOperation {
	operations := make([]configv1alpha1.CollectorOperation, n)
	for i := range operations {
		operations[i] = configv1alpha1.CollectorOperation{Name: "op" + strings.Repeat("x", i)}
	}
	return operations
}
