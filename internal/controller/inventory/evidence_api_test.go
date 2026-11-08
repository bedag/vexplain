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

package inventory_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

const (
	// maxEvidenceData is the most data that an Evidence holds, in bytes: what fits as base64 in the
	// 1 MiB of characters that the schema allows. The object stays below the 1.5 MiB that etcd takes
	// for a request.
	maxEvidenceData = 786432
	// maxUncompressedBytes is the most that the data of an Evidence is once it is decoded: 64 MiB.
	maxUncompressedBytes = 67108864
	// writtenOnce is the message of the rule that makes the spec of an Evidence immutable.
	writtenOnce = "Evidence is written once; replace it by deleting and creating it"
	// imageContents is the type of the evidence that the specs write, which the scanner delivers.
	imageContents = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"
	// scannerSource is the name of the Collector that delivers it, and scannerEventSource the source of
	// the CloudEvents that carry it.
	scannerSource      = "scanner"
	scannerEventSource = "/clusters/cluster-a/collectors/scanner"
	// amd64 is a platform that evidence about a manifest names.
	amd64 = "linux/amd64"
	// platformField is the field of a platform in the errors of the API server.
	platformField = "spec.platform"
)

// evidenceCount numbers the Evidence objects that the specs create. The kind is cluster-scoped, so
// every spec shares one namespace of names.
var evidenceCount int

// newEvidence returns an Evidence that the schema accepts: the scanner's evidence about a platform
// manifest, with every optional field set. The API server checks the size of the data and nothing
// else about it: only the operator's store decodes it.
func newEvidence() *inventoryv1alpha1.Evidence {
	evidenceCount++
	return &inventoryv1alpha1.Evidence{
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("evidence-%03d", evidenceCount)},
		Spec: inventoryv1alpha1.EvidenceSpec{
			Subject:           "manifest/" + newManifestDigest(),
			Type:              imageContents,
			Source:            scannerSource,
			EventID:           fmt.Sprintf("event-%03d", evidenceCount),
			EventSource:       scannerEventSource,
			CollectorVersion:  "1.0.0",
			Time:              ptr.To(metav1.NewTime(time.Now().Truncate(time.Second))),
			Coverage:          ptr.To[int32](97),
			Platform:          ptr.To(amd64),
			DataSchema:        ptr.To("urn:vexplain:schema:" + imageContents),
			Encoding:          inventoryv1alpha1.EvidenceEncodingGzipJSON,
			Data:              []byte("data"),
			UncompressedBytes: ptr.To[int64](4096),
		},
	}
}

// withoutOptionalFields returns an Evidence that sets only what the schema requires: evidence about
// an image, which has no platform and carries no coverage or schema.
func withoutOptionalFields() *inventoryv1alpha1.Evidence {
	obj := newEvidence()
	obj.Spec.Subject = "image/" + newManifestDigest()
	obj.Spec.Coverage, obj.Spec.Platform, obj.Spec.DataSchema = nil, nil, nil
	return obj
}

// createEvidence creates obj, and deletes it after the spec.
func createEvidence(obj *inventoryv1alpha1.Evidence) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, obj)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
	})
}

// refusedWith matches the error of a request that the API server refused as invalid, and whose
// message holds each of parts: the field that it names, or the message of the rule that refused it.
func refusedWith(parts ...string) types.GomegaMatcher {
	matchers := make([]types.GomegaMatcher, 0, 1+len(parts))
	matchers = append(matchers, Satisfy(apierrors.IsInvalid))
	for _, part := range parts {
		matchers = append(matchers, MatchError(ContainSubstring(part)))
	}
	return And(matchers...)
}

// typeOfLength returns a name that matches the pattern of types of evidence and is n characters
// long: a run of letters, then two more labels, the last of them the version.
func typeOfLength(n int) string {
	const tail = ".b.v1"
	return chars(n-len(tail)) + tail
}

// rawEvidence returns the Evidence of newEvidence as unstructured content, with the fields of its
// spec that set names changed. A Go struct can't say a value that its field leaves out, such as an
// empty string, and some specs need exactly that on the wire.
func rawEvidence(set map[string]any) *unstructured.Unstructured {
	GinkgoHelper()
	encoded, err := json.Marshal(newEvidence())
	Expect(err).NotTo(HaveOccurred())
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	Expect(json.Unmarshal(encoded, &obj.Object)).To(Succeed())
	obj.SetGroupVersionKind(inventoryv1alpha1.GroupVersion.WithKind("Evidence"))
	for field, value := range set {
		Expect(unstructured.SetNestedField(obj.Object, value, "spec", field)).To(Succeed())
	}
	return obj
}

// The operator's evidence store writes Evidence objects, and checks what it writes before. These
// specs write the objects by hand, past those checks, and check the rules of the schema against the
// real API server.
var _ = Describe("Evidence API", func() {
	It("stores evidence as it was written", func() {
		obj := newEvidence()
		obj.Spec.Data = bytes.Repeat([]byte{0x00, 0xFF, 0x1F, 0x8B}, 64)
		createEvidence(obj)

		var got inventoryv1alpha1.Evidence
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())

		Expect(got.Spec.Time.Time).To(BeTemporally("==", obj.Spec.Time.Time))
		got.Spec.Time, obj.Spec.Time = nil, nil
		Expect(got.Spec).To(Equal(obj.Spec), "the data and every other field come back as written")
	})

	// Evidence about an image has no platform, and a collector may give no coverage or schema.
	It("stores evidence without a coverage, a platform and a schema", func() {
		obj := withoutOptionalFields()
		createEvidence(obj)

		var got inventoryv1alpha1.Evidence
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())

		Expect(got.Spec.Coverage).To(BeNil())
		Expect(got.Spec.Platform).To(BeNil())
		Expect(got.Spec.DataSchema).To(BeNil())
	})

	// The evidence of every source and type is in one cluster-wide list, so the object has no namespace.
	It("is cluster-scoped", func() {
		obj := newEvidence()
		createEvidence(obj)

		Expect(obj.Namespace).To(BeEmpty())
		var list inventoryv1alpha1.EvidenceList
		Expect(k8sClient.List(ctx, &list)).To(Succeed())
		Expect(list.Items).To(ContainElement(HaveField("Name", obj.Name)))
	})

	Describe("being written once", func() {
		DescribeTable("refuses a change to the spec of an existing object, in",
			func(change func(*inventoryv1alpha1.EvidenceSpec)) {
				obj := newEvidence()
				createEvidence(obj)

				// A merge patch carries no resourceVersion, so the API server validates it against the
				// object as it is.
				patch := client.MergeFrom(obj.DeepCopy())
				change(&obj.Spec)
				err := k8sClient.Patch(ctx, obj, patch)

				Expect(err).To(refusedWith(writtenOnce))
			},
			Entry("the subject", func(s *inventoryv1alpha1.EvidenceSpec) { s.Subject += "-other" }),
			Entry("the type", func(s *inventoryv1alpha1.EvidenceSpec) { s.Type = "ch.bedag.vexplain.findings.v1alpha1" }),
			Entry("the source", func(s *inventoryv1alpha1.EvidenceSpec) { s.Source = "vulnerabilities" }),
			Entry("the id of the event", func(s *inventoryv1alpha1.EvidenceSpec) { s.EventID += "-other" }),
			Entry("the source of the event", func(s *inventoryv1alpha1.EvidenceSpec) {
				s.EventSource = "/clusters/cluster-b/collectors/scanner"
			}),
			Entry("the collector version", func(s *inventoryv1alpha1.EvidenceSpec) { s.CollectorVersion = "2.0.0" }),
			Entry("the time", func(s *inventoryv1alpha1.EvidenceSpec) {
				s.Time = ptr.To(metav1.NewTime(s.Time.Add(time.Hour)))
			}),
			Entry("the coverage", func(s *inventoryv1alpha1.EvidenceSpec) { s.Coverage = ptr.To[int32](12) }),
			Entry("the coverage, taken away", func(s *inventoryv1alpha1.EvidenceSpec) { s.Coverage = nil }),
			Entry("the platform", func(s *inventoryv1alpha1.EvidenceSpec) { s.Platform = ptr.To("linux/arm64") }),
			Entry("the schema of the data", func(s *inventoryv1alpha1.EvidenceSpec) {
				s.DataSchema = ptr.To("urn:vexplain:schema:other")
			}),
			Entry("the data", func(s *inventoryv1alpha1.EvidenceSpec) { s.Data = []byte("other data") }),
			Entry("the size of the decoded data", func(s *inventoryv1alpha1.EvidenceSpec) {
				s.UncompressedBytes = ptr.To[int64](8192)
			}),
		)

		// A field that the object lacked can't be added either: the whole spec is written once.
		It("refuses to add a field that the object lacked", func() {
			obj := withoutOptionalFields()
			createEvidence(obj)

			patch := client.MergeFrom(obj.DeepCopy())
			obj.Spec.Coverage = ptr.To[int32](50)
			err := k8sClient.Patch(ctx, obj, patch)

			Expect(err).To(refusedWith(writtenOnce))
		})

		// Whoever replaces evidence deletes it and creates it again: the evidence of the same subject,
		// type and source, from another version of the collector.
		It("is replaced by deleting it and creating it again, with another version", func() {
			obj := newEvidence()
			createEvidence(obj)
			Expect(k8sClient.Delete(ctx, obj)).To(Succeed())

			again := &inventoryv1alpha1.Evidence{
				ObjectMeta: metav1.ObjectMeta{Name: obj.Name},
				Spec:       *obj.Spec.DeepCopy(),
			}
			again.Spec.CollectorVersion = "2.0.0"

			createEvidence(again)
		})

		// The operator labels each object by its source, and annotates it with its subject, so the rule
		// on the spec must leave the metadata alone.
		It("lets the metadata of an object change, so that only its spec is written once", func() {
			obj := newEvidence()
			createEvidence(obj)

			patch := client.MergeFrom(obj.DeepCopy())
			obj.Labels = map[string]string{"example.com/source": obj.Spec.Source}
			obj.Annotations = map[string]string{"example.com/subject": obj.Spec.Subject}

			Expect(k8sClient.Patch(ctx, obj, patch)).To(Succeed())
		})
	})

	Describe("the coverage", func() {
		// The core shows the coverage and never interprets it. The schema only keeps it a percentage.
		DescribeTable("accepts a whole number from 0 to 100, with",
			func(coverage int32) {
				obj := newEvidence()
				obj.Spec.Coverage = ptr.To(coverage)

				createEvidence(obj)
			},
			Entry("0, which is a coverage and not an absent one", int32(0)),
			Entry("1", int32(1)),
			Entry("99", int32(99)),
			Entry("100", int32(100)),
		)

		DescribeTable("refuses a number outside it, with",
			func(coverage int32) {
				obj := newEvidence()
				obj.Spec.Coverage = ptr.To(coverage)

				Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.coverage: Invalid value"))
			},
			Entry("101", int32(101)),
			Entry("-1", int32(-1)),
			Entry("a very large number", int32(1<<30)),
		)
	})

	Describe("the platform", func() {
		// Evidence about a manifest names the platform of the manifest, as os/architecture, or with a variant.
		DescribeTable("accepts the platform",
			func(platform string) {
				obj := newEvidence()
				obj.Spec.Platform = ptr.To(platform)

				createEvidence(obj)
			},
			Entry("of a common image", amd64),
			Entry("with a variant", "linux/arm64/v8"),
			Entry("of an arm image", "linux/arm/v7"),
			Entry("of a big-endian machine", "linux/ppc64le"),
			Entry("of another operating system", "windows/amd64"),
			Entry("of 64 characters, the longest", "linux/"+chars(58)),
		)

		DescribeTable("refuses the platform",
			func(platform string) {
				obj := newEvidence()
				obj.Spec.Platform = ptr.To(platform)

				Expect(k8sClient.Create(ctx, obj)).To(refusedWith(platformField))
			},
			Entry("linux, with no architecture", "linux"),
			Entry("with a capital letter", "Linux/amd64"),
			Entry("with two variants", "linux/arm64/v8/v9"),
			Entry("with an empty architecture", "linux/"),
			Entry("with an empty operating system", "/amd64"),
			Entry("with an empty variant", "linux/arm64/"),
			Entry("with a space", "linux/amd 64"),
			Entry("of 65 characters", "linux/"+chars(59)),
		)
	})

	Describe("the source", func() {
		// The source is the name of a Collector: a DNS-1123 label, of at most 44 characters because the
		// name of a Collector is that long at most.
		DescribeTable("accepts the name",
			func(source string) {
				obj := newEvidence()
				obj.Spec.Source = source

				createEvidence(obj)
			},
			Entry("of a collector", "vulnerabilities"),
			Entry("of one character", "a"),
			Entry("with digits and dashes", "a1-b2-c3"),
			Entry("of 44 characters, the longest", chars(44)),
		)

		DescribeTable("refuses the name",
			func(source string) {
				obj := newEvidence()
				obj.Spec.Source = source

				Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.source"))
			},
			Entry("with a capital letter", "Scanner"),
			Entry("with a dot, which a DNS-1123 label has none of", "scan.ner"),
			Entry("with an underscore", "scan_ner"),
			Entry("that starts with a dash", "-scanner"),
			Entry("that ends with a dash", "scanner-"),
			Entry("with a slash", "clusters/cluster-a"),
			Entry("of 45 characters", chars(45)),
		)
	})

	Describe("the type", func() {
		// The same pattern as every other place that names a type of evidence, which a test of the
		// config group pins to the SDK's.
		DescribeTable("accepts the type",
			func(evidenceType string) {
				obj := newEvidence()
				obj.Spec.Type = evidenceType

				createEvidence(obj)
			},
			Entry("of the core", "ch.bedag.vexplain.presence.v1alpha1"),
			Entry("of a collector", "com.example.hello.v2beta1"),
			Entry("of 253 characters, the longest", typeOfLength(253)),
		)

		DescribeTable("refuses the type",
			func(evidenceType string) {
				obj := newEvidence()
				obj.Spec.Type = evidenceType

				Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.type"))
			},
			Entry("with no version", "ch.bedag.vexplain.scanner.image-contents"),
			Entry("with a capital letter", "ch.bedag.vexplain.Scanner.v1alpha1"),
			Entry("with no dots", "contents"),
			Entry("with a version that has no number", "ch.bedag.vexplain.scanner.v"),
			Entry("with an underscore", "ch.bedag.vexplain.image_contents.v1alpha1"),
			Entry("of 254 characters", typeOfLength(254)),
		)
	})

	Describe("the data", func() {
		// 786432 bytes is the most compressed evidence that the operator's store keeps. It is the most that
		// fits as base64 in the 1 MiB of characters that the schema allows, which stays below etcd's limit
		// of 1.5 MiB for a request.
		It("holds data of 786432 bytes, and refuses one byte more", func() {
			obj := newEvidence()
			obj.Spec.Data = bytes.Repeat([]byte{0xA5}, maxEvidenceData+1)

			err := k8sClient.Create(ctx, obj)

			Expect(err).To(refusedWith("spec.data"))

			obj.Spec.Data = obj.Spec.Data[:maxEvidenceData]
			createEvidence(obj)
		})

		It("refuses data that is present and empty", func() {
			err := k8sClient.Create(ctx, rawEvidence(map[string]any{"data": ""}))

			Expect(err).To(refusedWith("spec.data"))
		})

		// The data is bytes, which JSON carries as base64. A text that isn't base64 holds no bytes,
		// and only a client that writes the JSON by hand can send it.
		It("refuses data that is not base64", func() {
			err := k8sClient.Create(ctx, rawEvidence(map[string]any{"data": "not base64!"}))

			Expect(err).To(refusedWith("spec.data"))
		})
	})

	// The id and the source of the CloudEvent identify the event that carried the evidence, so that
	// the store can give the same event back.
	Describe("the identity of the event", func() {
		It("holds an id of 256 characters, and refuses one more", func() {
			obj := newEvidence()
			obj.Spec.EventID = chars(257)

			Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.eventID: Too long"))

			obj.Spec.EventID = chars(256)
			createEvidence(obj)
		})

		It("holds a source of 512 characters, and refuses one more", func() {
			obj := newEvidence()
			obj.Spec.EventSource = "/" + chars(512)

			Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.eventSource: Too long"))

			obj.Spec.EventSource = "/" + chars(511)
			createEvidence(obj)
		})
	})

	Describe("the size of the decoded data", func() {
		DescribeTable("accepts",
			func(size int64) {
				obj := newEvidence()
				obj.Spec.UncompressedBytes = ptr.To(size)

				createEvidence(obj)
			},
			Entry("no bytes", int64(0)),
			Entry("64 MiB, the most", int64(maxUncompressedBytes)),
		)

		DescribeTable("refuses",
			func(size int64) {
				obj := newEvidence()
				obj.Spec.UncompressedBytes = ptr.To(size)

				Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.uncompressedBytes: Invalid value"))
			},
			Entry("a negative size", int64(-1)),
			Entry("one byte more than 64 MiB", int64(maxUncompressedBytes+1)),
		)
	})

	It("holds every other field at its limit", func() {
		obj := newEvidence()
		obj.Spec.Subject = chars(512)
		obj.Spec.Type = typeOfLength(253)
		obj.Spec.Source = chars(44)
		obj.Spec.EventID = chars(256)
		obj.Spec.EventSource = "/" + chars(511)
		obj.Spec.CollectorVersion = chars(128)
		obj.Spec.Platform = ptr.To("linux/" + chars(58))
		obj.Spec.DataSchema = ptr.To(chars(512))

		createEvidence(obj)
	})

	// The evidence store refuses what doesn't fit an Evidence before it writes, so its limits must be
	// the schema's: an event at each of them, written through the store, is one that the API server
	// takes.
	It("takes what the evidence store writes at every limit of an event", func() {
		store := evidence.NewCRDStore(k8sClient, nil, func() string { return localCluster })
		e, err := sdkevidence.New(typeOfLength(253), "vm/"+chars(509), map[string]any{"field": "value"},
			sdkevidence.WithPlatform("linux/"+chars(58)), sdkevidence.WithCoverage(100),
			sdkevidence.WithSource("/"+chars(511)))
		Expect(err).NotTo(HaveOccurred())
		e.SetID(chars(256))
		e.SetDataSchema("urn:" + chars(508))
		key := evidence.Key{Subject: e.Subject(), Type: e.Type(), Source: chars(44)}

		Expect(store.Put(ctx, key.Source, chars(128), e)).To(Succeed())
		DeferCleanup(store.DeleteSubject, ctx, key.Subject)

		record, err := store.Get(ctx, key)
		Expect(err).NotTo(HaveOccurred())
		Expect(record).NotTo(BeNil())
		Expect(record.Event.ID()).To(Equal(e.ID()))
	})

	DescribeTable("refuses a spec that breaks the schema",
		func(mutate func(*inventoryv1alpha1.EvidenceSpec), field string) {
			obj := newEvidence()
			mutate(&obj.Spec)

			err := k8sClient.Create(ctx, obj)

			Expect(err).To(refusedWith(field))
		},
		Entry("no subject",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.Subject = "" },
			"spec.subject: Required value"),
		Entry("a subject of 513 characters",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.Subject = chars(513) },
			"spec.subject: Too long"),
		Entry("no type",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.Type = "" },
			"spec.type: Required value"),
		Entry("no source",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.Source = "" },
			"spec.source: Required value"),
		Entry("no id of the event",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.EventID = "" },
			"spec.eventID: Required value"),
		Entry("no source of the event",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.EventSource = "" },
			"spec.eventSource: Required value"),
		Entry("no collector version",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.CollectorVersion = "" },
			"spec.collectorVersion: Required value"),
		Entry("a collector version of 129 characters",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.CollectorVersion = chars(129) },
			"spec.collectorVersion: Too long"),
		Entry("no time",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.Time = nil },
			"spec.time: Required value"),
		Entry("a schema of 513 characters",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.DataSchema = ptr.To(chars(513)) },
			"spec.dataSchema: Too long"),
		Entry("no encoding",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.Encoding = "" },
			"spec.encoding: Required value"),
		Entry("an encoding that no version knows",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.Encoding = "Zstd" },
			`spec.encoding: Unsupported value: "Zstd"`),
		Entry("no data",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.Data = nil },
			"spec.data: Required value"),
		Entry("no size of the decoded data",
			func(s *inventoryv1alpha1.EvidenceSpec) { s.UncompressedBytes = nil },
			"spec.uncompressedBytes: Required value"),
	)

	// An optional field that is present must say something: a Go struct leaves an empty string out, so
	// these specs put it on the wire.
	DescribeTable("refuses an optional text that is present and empty",
		func(field string) {
			err := k8sClient.Create(ctx, rawEvidence(map[string]any{field: ""}))

			Expect(err).To(refusedWith("spec." + field))
		},
		Entry("the platform", "platform"),
		Entry("the schema of the data", "dataSchema"),
	)
})
