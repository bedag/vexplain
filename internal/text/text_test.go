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

package text_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/text"
)

// short is a text that the cuts below keep whole or leave out.
const short = "abc"

// dirty is what a crafted file name or package field can carry: an escape sequence, a newline, a
// right-to-left override, a NUL and a zero-width joiner. clean is what is shown of it: each
// character that Go doesn't call printable is one U+FFFD.
const (
	dirty = "a\x1b[31m\n\u202eb\x00\u200dc"
	clean = "a\ufffd[31m\ufffd\ufffdb\ufffd\ufffdc"
)

func TestPrintableReplacesEveryCharacterThatIsNotPrintable(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"control and format characters", dirty, clean},
		{"a path that clears the terminal and starts a line of its own",
			"/opt/\x1b[2J\x1b[31mred\nreached by /usr/bin/safe", "/opt/\ufffd[2J\ufffd[31mred\ufffdreached by /usr/bin/safe"},
		{"a right-to-left override", "invoice\u202efdp.exe", "invoice\ufffdfdp.exe"},
		{"bytes that aren't valid UTF-8", "lib\xffname", "lib\ufffdname"},
		// A no-break space, an em space and a tab.
		{"the ASCII space is the one space that is printable", "a b\u00a0c\u2003d\te", "a b\ufffdc\ufffdd\ufffde"},
		{"letters of other scripts, symbols and emoji are kept", "libé€ 中文 😀", "libé€ 中文 😀"},
		{"nothing stays nothing", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := text.Printable(tc.in)
			require.Equal(t, tc.want, got)
			require.True(t, utf8.ValidString(got))
		})
	}
}

func TestRequiredGivesThePlaceholderForNothing(t *testing.T) {
	require.Equal(t, "unknown", text.Required("", 64))
	require.Equal(t, text.Placeholder, text.Required("", 64))
	// A character that isn't printable is still something: the field shows that it held one.
	require.Equal(t, "\ufffd", text.Required("\x00", 64))
}

func TestRequiredIsPrintableAndCutInCharacters(t *testing.T) {
	require.Equal(t, clean, text.Required(dirty, 64))
	// An escape character is one byte, and its replacement three. The cut follows the replacement,
	// so it holds for what the field shows.
	require.Equal(t, strings.Repeat("\ufffd", 253), text.Required(strings.Repeat("\x1b", 300), 253))
	require.Equal(t, strings.Repeat("é", 253), text.Required(strings.Repeat("é", 300), 253))
}

func TestRequiredCutsThePlaceholderToALimitBelowItsLength(t *testing.T) {
	// No schema of the operator sets a limit this low, but the result never passes the limit.
	require.Equal(t, "unk", text.Required("", 3))
}

func TestCutCharsCountsCharacters(t *testing.T) {
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"one-byte characters", strings.Repeat("a", 300), 253, strings.Repeat("a", 253)},
		// 253 two-byte characters are 506 bytes, and within the limit.
		{"two-byte characters within the limit are kept", strings.Repeat("é", 253), 253, strings.Repeat("é", 253)},
		{"two-byte characters over the limit", strings.Repeat("é", 300), 253, strings.Repeat("é", 253)},
		{"four-byte characters", strings.Repeat("😀", 10), 4, strings.Repeat("😀", 4)},
		{"exactly the limit", short, 3, short},
		{"no limit to speak of", short, 0, ""},
		{"a limit below zero", short, -1, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, text.CutChars(tc.in, tc.n))
		})
	}
}

func TestCutBytesCutsOnACharacterBoundary(t *testing.T) {
	// "reached by " takes 11 bytes. With two-byte characters after it the 256th byte is inside one,
	// and three-byte and four-byte characters put it inside one at other offsets.
	tests := []struct {
		name      string
		character string
		wantBytes int
	}{
		{"one-byte characters", "a", 256},
		{"two-byte characters", "é", 255},
		{"three-byte characters", "€", 254},
		{"four-byte characters", "😀", 255},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := "reached by " + strings.Repeat(tc.character, 300)
			got := text.CutBytes(s, 256)
			require.True(t, utf8.ValidString(got))
			require.Len(t, got, tc.wantBytes)
			require.True(t, strings.HasPrefix(s, got), "the cut is the start of the text, not a rewrite of it")
		})
	}

	t.Run("text within the limit is kept", func(t *testing.T) {
		require.Equal(t, "€€", text.CutBytes("€€", 6))
	})
	t.Run("a limit inside the first character leaves nothing", func(t *testing.T) {
		require.Empty(t, text.CutBytes("€€", 2))
	})
	t.Run("a limit of zero or below leaves nothing", func(t *testing.T) {
		require.Empty(t, text.CutBytes(short, 0))
		require.Empty(t, text.CutBytes(short, -1))
	})
}
