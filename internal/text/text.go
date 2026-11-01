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

// Package text makes text from images, databases and other evidence fit to show: printable, and cut
// to the limits of a schema. A crafted image can influence such text, and kubectl prints the strings
// of a status as they are, so a string that reaches a status is made printable first. The cuts
// follow, so that they hold for what is shown, and the API server, which refuses a whole object for
// one field over its limit, accepts the result.
package text

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Placeholder is what a field says where the schema requires text and the source has none. It claims
// nothing about what the field describes.
const Placeholder = "unknown"

// Printable returns s with each character that Go doesn't call printable replaced by U+FFFD. Go calls
// a character printable when it is a letter, a mark, a number, a punctuation mark or a symbol, or the
// ASCII space. Control characters, line breaks and the format characters that reverse the direction of
// text are not. Bytes that aren't valid UTF-8 become U+FFFD too, so the result is always valid UTF-8,
// and the cuts that follow can rely on it.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return utf8.RuneError
	}, s)
}

// Required returns s for a string that the schema requires: made printable, the placeholder when
// nothing is left, and cut to at most n characters. Every limit of the operator's schemas is longer
// than the placeholder, which a lower limit cuts as well.
func Required(s string, n int) string {
	if s = Printable(s); s == "" {
		s = Placeholder
	}
	return CutChars(s, n)
}

// CutChars returns s cut to at most n characters, which is what the schema's maxLength counts. A
// limit of zero or below leaves nothing.
func CutChars(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n { // no more bytes than n, so no more characters
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// CutBytes returns s cut to at most n bytes, on the boundary of a character: a character that the
// cut would split is left out. A limit of zero or below leaves nothing.
func CutBytes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
