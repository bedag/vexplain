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

package result

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

// The errors that Parse and DecodeManifest return are fixed texts. A scan's log can carry text
// that an image influenced, so no error repeats the data that was read, not even by passing on the
// error of the base64, gzip or JSON library that failed on it. Use errors.Is to tell them apart.
var (
	// ErrNoLine means the log has no result line and no error line.
	ErrNoLine = errors.New("the scan log has no result line")
	// ErrMultipleLines means the log has more than one result or error line, so it can't be told
	// which of them speaks for the scan.
	ErrMultipleLines = errors.New("the scan log has more than one result line")
	// ErrUnsupportedVersion means the line, or the JSON in it, is of a version that this package
	// doesn't read.
	ErrUnsupportedVersion = errors.New("the scan result is of an unsupported version")
	// ErrMalformed means the data can't be decoded: it isn't base64, gzip or JSON of the expected
	// shape, or the reason of an error line is not one of the known ones. The text of the error
	// says which part is wrong.
	ErrMalformed = errors.New("the scan result is malformed")
	// ErrTooLarge means the data decompresses to more JSON than the caller allowed. It is about the
	// size of the result, and not about the size of the image: it is not the TooLarge reason.
	ErrTooLarge = errors.New("the scan result is too large")
)

// The names that start the lines of every version of the format. Parse tells a line of a version
// that it doesn't read from the noise by them.
const (
	resultLead = "vexplain-scan-result "
	errorLead  = "vexplain-scan-error "
)

// Encode returns the log line of a scan that succeeded: ResultPrefix, then the base64 of the gzip
// of the JSON of r. The line has no newline; the caller prints it as a line of its own. Encode sets
// r.SchemaVersion itself, so that a line never carries another version than its prefix names.
func Encode(r Result) (string, error) {
	r.SchemaVersion = SchemaVersion
	compressed, _, err := gzipJSON(r)
	if err != nil {
		return "", fmt.Errorf("encoding the scan result: %w", err)
	}
	return ResultPrefix + base64.StdEncoding.EncodeToString(compressed), nil
}

// EncodeError returns the log line of a scan that failed: ErrorPrefix, then the reason. The line
// has no newline. A reason that is none of the seven values is written as ErrorReasonInternal, so
// that the line always parses, and nothing else, such as a second line, can end up on it.
func EncodeError(reason ErrorReason) string {
	if !reason.valid() {
		reason = ErrorReasonInternal
	}
	return ErrorPrefix + string(reason)
}

// Parse finds the one result or error line in a scan pod's log. Exactly one of the result and the
// reason is set when err is nil.
//
// A line of the scan starts, at the beginning of a line of the log, with the name of the format and
// a space: ResultPrefix and ErrorPrefix are such lines of version 1, and a line of another version
// counts as a line of the scan too. The log must not carry timestamps in front of its lines. Lines
// end at a newline, which a carriage return may precede. Parse fails when the log has no such
// line (ErrNoLine) or more than one (ErrMultipleLines), when the line is of another version
// (ErrUnsupportedVersion) or doesn't decode (ErrMalformed), and when its JSON is more than
// maxBytes long once decompressed (ErrTooLarge).
func Parse(log string, maxBytes int64) (*Result, ErrorReason, error) {
	line, err := findLine(log)
	if err != nil {
		return nil, "", err
	}

	if rest, ok := strings.CutPrefix(line, ErrorPrefix); ok {
		reason := ErrorReason(rest)
		if !reason.valid() {
			return nil, "", malformed("the reason is unknown")
		}
		return nil, reason, nil
	}

	payload, ok := strings.CutPrefix(line, ResultPrefix)
	if !ok {
		return nil, "", ErrUnsupportedVersion
	}
	compressed, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, "", malformed("the payload is not base64")
	}
	var r Result
	if err = gunzipJSON(compressed, maxBytes, &r); err != nil {
		return nil, "", err
	}
	if r.SchemaVersion != SchemaVersion {
		return nil, "", ErrUnsupportedVersion
	}
	return &r, "", nil
}

// findLine returns the one line of the scan in log. It reads the log with strings functions and not
// with a bufio.Scanner, whose token limit of 64 KiB is below the size of a result line.
func findLine(log string) (string, error) {
	var line string
	found := false
	for text := range strings.SplitSeq(log, "\n") {
		text = strings.TrimSuffix(text, "\r")
		if !strings.HasPrefix(text, resultLead) && !strings.HasPrefix(text, errorLead) {
			continue
		}
		if found {
			return "", ErrMultipleLines
		}
		line, found = text, true
	}
	if !found {
		return "", ErrNoLine
	}
	return line, nil
}

// EncodeManifest returns the gzip JSON of one manifest, and the size of that JSON before
// compression, for an ImagePackages. DecodeManifest reads the bytes back, and the size is a limit
// that it accepts.
func EncodeManifest(m Manifest) ([]byte, int64, error) {
	compressed, size, err := gzipJSON(m)
	if err != nil {
		return nil, 0, fmt.Errorf("encoding the manifest: %w", err)
	}
	return compressed, size, nil
}

// DecodeManifest decodes the gzip JSON that EncodeManifest made. It fails with ErrTooLarge when
// the JSON is more than maxBytes long once decompressed, and with ErrMalformed when the data
// doesn't decode.
func DecodeManifest(b []byte, maxBytes int64) (Manifest, error) {
	var m Manifest
	if err := gunzipJSON(b, maxBytes, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// gzipJSON returns the gzip of the JSON of v, and the length of that JSON before compression.
func gzipJSON(v any) ([]byte, int64, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, 0, err
	}
	// The best compression: these bytes are scarce, in a pod's log and in an etcd object, and the
	// time it takes is small next to that of a scan.
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, 0, err
	}
	if _, err = zw.Write(raw); err != nil {
		return nil, 0, err
	}
	if err = zw.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), int64(len(raw)), nil
}

// gunzipJSON decodes gzip data that holds one JSON value into v. The JSON may be at most maxBytes
// long once decompressed: a few KiB of gzip can unpack into gigabytes, so the data is read through
// a limit.
func gunzipJSON(compressed []byte, maxBytes int64, v any) error {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return malformed("the data is not gzip")
	}
	// The reader has nothing to release, and a Close would only repeat what the reads report.

	// Read one byte more than allowed, to tell a JSON of exactly maxBytes from a longer one. The
	// min keeps that byte from overflowing. A negative limit reads nothing, and refuses everything.
	limit := min(maxBytes, math.MaxInt64-1)
	raw, err := io.ReadAll(io.LimitReader(zr, limit+1))
	if err != nil {
		return malformed("the gzip data is corrupt")
	}
	if int64(len(raw)) > limit {
		return ErrTooLarge
	}
	// Unmarshal fails on anything after the JSON value, too.
	if err = json.Unmarshal(raw, v); err != nil {
		return malformed("the JSON is invalid or has the wrong shape")
	}
	return nil
}

// malformed returns ErrMalformed with a text that says which part of the data is wrong. The text
// is always fixed, never made of the data.
func malformed(part string) error {
	return fmt.Errorf("%w: %s", ErrMalformed, part)
}
