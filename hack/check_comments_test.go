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

package hack

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These tests run check-comments.sh, which `make lint` runs on the repository. The check keeps the
// comments of Go files free of citations of a decision that is kept outside the repository: the
// numbered decisions that a developer's agent keeps in a file of its own, cited by number, by the
// word for such a decision, or by the name of the file. A comment states its reason itself. A
// decision record in docs/decisions is part of the repository and may be cited, so the numbers of
// those pass. So does the bare word ledger, which is the product's own term for what the agent
// of the operator records as evidence.
//
// The fixtures hold the Go files that the script reads as strings of this file. The script must
// see a comment only where a Go comment is, so the test that runs it on the repository, this file
// included, shows that it reads these strings as strings.

const (
	scriptName = "check-comments.sh"
	// sourceFile is the name of the Go file in most fixtures.
	sourceFile = "p.go"

	// The exit codes of the script.
	exitCited = 1
	exitUsage = 2
)

// tick is a backquote, which a raw string literal of this file can't hold.
const tick = "`"

// What the script flags by name: two words, and the two names of the file that an agent keeps.
const (
	ruling            = "ruling"
	rulings           = "rulings"
	developmentLedger = "development ledger"
	sddLedger         = "SDD ledger"
)

// goFile is a Go file with body, which starts on line 3.
func goFile(body string) string { return "package p\n\n" + body }

// scriptPath is the absolute path of the script. A test runs in the directory of its package.
func scriptPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(scriptName)
	require.NoError(t, err)
	return path
}

// run runs the script, as make does, with args. It returns what the script wrote and its exit
// code, and fails the test when the script can't be started at all.
func run(t *testing.T, script string, args ...string) (output string, exitCode int) {
	t.Helper()
	return runWithin(t, t.Context(), script, args...)
}

// runWithin is run, and it stops the script when ctx ends.
func runWithin(t *testing.T, ctx context.Context, script string, args ...string) (output string, exitCode int) {
	t.Helper()
	cmd := exec.CommandContext(ctx, script, args...)
	// The script starts find and awk. When ctx ends the script is killed, and they may keep the
	// output open, so the wait ends a little later all the same.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	default:
		require.NoError(t, err, "the script must start")
		return "", -1
	}
}

// write creates the files of a tree, given as paths in the tree and their content.
func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
}

// check runs the script on a new tree that holds files.
func check(t *testing.T, files map[string]string) (output string, exitCode int) {
	t.Helper()
	root := t.TempDir()
	write(t, root, files)
	return run(t, scriptPath(t), root)
}

// cited is the line that the script writes for a citation.
func cited(file string, line int, citation string) string {
	return fmt.Sprintf("%s:%d: comment cites %q", file, line, citation)
}

func TestCheckCommentsFlagsACitation(t *testing.T) {
	tests := []struct {
		name string
		body string
		line int // the line of the file where the citation is: the first line of body is line 3
		cite string
	}{
		// By number.
		{"a number in a line comment", "// The limit follows R9.\nvar limit = 5\n", 3, "R9"},
		{"a number of several digits", "// The limit follows R123.\n", 3, "R123"},
		{"a number that ends the comment", "// The limit follows R12", 3, "R12"},
		{"a number in brackets", "// The limit (R9) is five.\n", 3, "R9"},
		{"a number that starts the comment", "//R9: the limit.\n", 3, "R9"},
		{"a number followed by a colon", "// R9: the limit.\n", 3, "R9"},
		{"a number in a comment after code", "var limit = 5 // per R3\n", 3, "R3"},
		{"a number in a block comment", "/* per R4 */\nvar limit = 5\n", 3, "R4"},
		{"a number on a later line of a block comment", "/*\nLimits.\n\nR7 says five.\n*/\n", 6, "R7"},
		{"a number on a later line of a comment", "// The limit is five.\n// It follows R5.\n", 4, "R5"},
		{"a number in a comment with CRLF line ends", "// per R9\r\nvar limit = 5\r\n", 3, "R9"},
		// By name.
		{"the word ruling", "// This follows the ruling on retries.\n", 3, ruling},
		{"the word rulings", "// See the rulings.\n", 3, rulings},
		{"the word Ruling, capitalised", "// Ruling on retries: five.\n", 3, "Ruling"},
		{"a name in a block comment", "/* the ruling */\n", 3, ruling},
		{"a name in a comment after code", "var limit = 5 // the ruling says so\n", 3, ruling},
		{"the name development ledger", "// Recorded in the development ledger.\n", 3, developmentLedger},
		{"the name SDD ledger", "// Recorded in the SDD ledger.\n", 3, sddLedger},
		{"the name development ledger in capitals", "// The DEVELOPMENT LEDGER says so.\n", 3, "DEVELOPMENT LEDGER"},
		{"the name development ledger in the plural", "// See the development ledgers.\n", 3, "development ledgers"},
		{"the name SDD ledger in a block comment", "/* the SDD ledger */\n", 3, sddLedger},
		{"the name SDD ledger in a comment after code",
			"var limit = 5 // the SDD ledger says so\n", 3, sddLedger},
		{"the name development ledger, wrapped over two lines",
			"// Recorded in the development\n// ledger.\n", 3, developmentLedger},
		{"the name SDD ledger, wrapped, with CRLF line ends", "// Recorded in the SDD\r\n// ledger.\r\n", 3, sddLedger},
		{"the name development ledger, wrapped in a block comment",
			"/* the development\n   ledger */\n", 3, developmentLedger},
		{"the word ruling before a word that starts with out", "// A ruling outside the repository.\n", 3, ruling},
		{"the word ruling at the end of a line, and no out after it", "// The ruling\n// that applies.\n", 3, ruling},
		{"the word rulings before out", "// The rulings out there.\n", 3, rulings},
		// Where the script must see a comment, after code that looks like the start of one.
		{"a comment after a string with a comment marker in it",
			"var u = \"http://example.test\" // per R6\n", 3, "R6"},
		{"a comment after a rune that is a double quote", "var q = '\"' // per R6\n", 3, "R6"},
		{"a comment after a rune that is an escaped quote", "var q = '\\'' // per R6\n", 3, "R6"},
		{"a comment after a string that ends in an escaped backslash",
			"var b = \"\\\\\" // per R6\n", 3, "R6"},
		{"a comment after a string with an escaped quote", "var e = \"\\\"\" // per R6\n", 3, "R6"},
		{"a comment after a raw string on one line", "var raw = " + tick + "one" + tick + " // per R6\n", 3, "R6"},
		{"a comment after a raw string over several lines",
			"var raw = " + tick + "one\ntwo" + tick + " // per R6\n", 4, "R6"},
		{"a comment after a raw string with quotes and comment markers in it",
			"var raw = " + tick + "it's \"quoted\" // R9 /* ledger\n" + tick + "\nvar limit = 5 // per R6\n", 5, "R6"},
		{"a comment after a block comment on the same line", "/* note */ var limit = 5 // per R6\n", 3, "R6"},
		{"a block comment that holds a line comment marker", "/* see // here\n   R8 */\n", 4, "R8"},
		{"a comment after a division", "var q = 6 / 3 // per R6\n", 3, "R6"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, code := check(t, map[string]string{sourceFile: goFile(tc.body)})

			require.Equal(t, exitCited, code, output)
			require.Contains(t, output, cited(sourceFile, tc.line, tc.cite))
			// Each fixture has one citation, and nothing else in it may be taken for one.
			require.Equal(t, 1, strings.Count(output, "comment cites"), output)
		})
	}
}

func TestCheckCommentsPassesTextThatIsNoCitation(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		// What looks like a citation, and is not one.
		{"RFC numbers", "// Timestamps follow RFC 3339, as RFC 7231 asks.\n"},
		{"the idiom ruling out", "// Checking this first allows ruling out most cases.\n"},
		{"the idiom ruling out in capitals", "// Ruling out the cache comes first.\n"},
		{"the idiom ruling out, wrapped", "// Checking this first allows ruling\n// out most cases.\n"},
		{"the idiom ruling out, wrapped, with CRLF line ends",
			"// Checking this first allows ruling\r\n// out most cases.\r\n"},
		{"the idiom ruling out in a block comment", "/* allows ruling\n   out most cases */\n"},
		{"other forms of the verb", "// The check rules out what the last run ruled out.\n"},
		{"a word that only holds a number", "// AR9, R9x, R2D2 and 2R9 are names.\n"},
		{"a word that only holds the name", "// A sledger, some ledgers, a ledgerless book, a rulingless court.\n"},
		{"a bare ledger", "// Each tool result goes into the evidence ledger.\n"},
		{"a bare ledger that starts a comment", "// Ledger holds the evidence of one investigation.\n"},
		{"a bare ledger in a block comment", "/* the agent's ledger */\n"},
		{"a bare ledger in a comment after code", "var limit = 5 // the ledger keeps five\n"},
		{"development at the end of a line, and a ledger later", "// A comment on the development\n// of the ledger.\n"},
		{"development, then other words, then ledger", "// The development of the ledger, and SDD and the ledger.\n"},
		{"ledger before development", "// The ledger of a development, and the ledger of SDD.\n"},
		{"a word that only starts with development", "// A developmental ledger.\n"},
		{"a word that only ends in development", "// A redevelopment ledger, and a codevelopment ledger.\n"},
		{"a word that only starts with ledger", "// The development ledgerless book, and the SDD ledgerlike one.\n"},
		{"a word that only ends in sdd, and sdd with a suffix", "// The xsdd ledger, and the sdd's ledger.\n"},
		{"R without digits, or digits without R", "// R is a letter, 9 is a digit, and R 9 are two words.\n"},
		{"R and digits apart", "// R-9 and R_9 and R.9 are not numbers of that kind.\n"},
		{"a lower-case r with digits", "// Alpine versions look like 1.2.3-r1, and ARM has a register r9.\n"},
		{"comments with no words in them", "//\n/**/\n/*\n*/\n"},
		{"directives and markers", "//go:build linux\n// +kubebuilder:rbac:groups=example.test,verbs=get\n"},
		{"decision records, which are part of the repository",
			"// Known exploitation holds a finding open (0035).\n// See docs/decisions, and decision 0004 in it.\n"},
		{"a licence header",
			"/*\nCopyright 2026.\n\nLicensed under the Apache License, Version 2.0 (the \"License\");\n*/\n"},
		// Code that is no comment.
		{"identifiers", "var R9 = 1\nvar ledger = []string{}\nfunc ruling() int { return R9 }\n"},
		{"identifiers next to a comment without a citation", "var R9 = 1 // five\n"},
		{"strings", "var s = \"per R9, the ruling in the ledger\"\n"},
		{"a string with a comment marker", "var u = \"http://example.test/R9\"\n"},
		{"a string with an escaped quote and a comment marker", "var e = \"\\\"// R9 ledger\"\n"},
		{"a string that ends in an escaped backslash, then code", "var b = \"\\\\\"\nvar R9 = 1\n"},
		{"a string with a block comment marker, then code", "var s = \"/* not a comment\"\nvar R9 = 1\n"},
		{"runes", "var q = '\"'\nvar slash = '/'\nvar tick = '\\''\nvar s = \"R9\"\n"},
		{"a raw string on one line", "var raw = " + tick + "// per R9 /* ledger" + tick + "\nvar R2 = 2\n"},
		{"a raw string over several lines",
			"var raw = " + tick + "// per R9\n/* the ledger */\nruling" + tick + "\nvar R2 = 2\n"},
		{"a raw string with quotes in it, then code",
			"var raw = " + tick + "it's \"quoted\" // R9\n" + tick + "\nvar R2 = 2\n"},
		{"a raw string with a block comment marker, then code",
			"var raw = " + tick + "/* not a comment" + tick + "\nvar R9 = 1\n"},
		{"code after a block comment", "/* note */ var R9 = 1\n"},
		{"code after a block comment that spans lines", "/* note\nover two lines */ var R9 = 1\n"},
		{"code after block comments that touch", "/* a *//* b */ var R9 = 1\n"},
		{"code after a block comment that ends in a star", "/* a **/ var R9 = 1\n"},
		{"a block comment marker in a line comment", "// a /* does not open a block comment\nvar R8 = 1\n"},
		{"a division", "var q = 6 / 3\nvar R8 = q\n"},
		{"no comment at all", "var limit = 5\n"},
		{"an empty file", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, code := check(t, map[string]string{sourceFile: goFile(tc.body)})

			require.Zero(t, code, output)
			require.Empty(t, output, "a passing check is silent")
		})
	}
}

func TestCheckCommentsReadsOnlyHandWrittenGoFiles(t *testing.T) {
	citation := goFile("// per R9, the ruling in the ledger\n")

	output, code := check(t, map[string]string{
		// Generated code.
		"api/v1/zz_generated.deepcopy.go": citation,
		"sdk/api/collector.pb.go":         citation,
		"sdk/api/collector_grpc.pb.go":    citation,
		// Tools that are installed into bin, and vendored code.
		"bin/tools/main.go":            citation,
		"vendor/example.test/x.go":     citation,
		"sdk/vendor/example.test/y.go": citation,
		// Directories that are not source: the repository's own, and the agent's.
		".git/hooks/x.go":   citation,
		".superpowers/x.go": citation,
		".hidden/deep/x.go": citation,
		// Files that are not Go files.
		"docs/notes.md": "// per R9, the ruling in the ledger\n",
		"x.go.txt":      citation,
		"Makefile":      "# per R9\n",
	})

	require.Zero(t, code, output)
	require.Empty(t, output)
}

func TestCheckCommentsReadsEveryDirectory(t *testing.T) {
	clean := goFile("// A comment that states its reason itself.\n")

	output, code := check(t, map[string]string{
		"a.go":                   goFile("// per R9\n"),
		"internal/deep/er/b.go":  goFile("var limit = 5\n// the development ledger\n"),
		"internal/deep/clean.go": clean,
		// Only the bin at the root is skipped.
		"internal/bin/c.go":         goFile("// the ruling\n"),
		"cmd/tool/main_test.go":     goFile("/*\n * per R10\n */\n"),
		"name with space/d.go":      goFile("// per R11\n"),
		"internal/deep/er/clean.go": clean,
	})

	require.Equal(t, exitCited, code, output)
	require.Contains(t, output, cited("a.go", 3, "R9"))
	require.Contains(t, output, cited("internal/deep/er/b.go", 4, developmentLedger))
	require.Contains(t, output, cited("internal/bin/c.go", 3, ruling))
	require.Contains(t, output, cited("cmd/tool/main_test.go", 4, "R10"))
	require.Contains(t, output, cited("name with space/d.go", 3, "R11"))
	require.NotContains(t, output, "clean.go")
}

// One run of awk reads many files, and what a file leaves open must not reach the next one: a block
// comment or a raw string that has no end, and a comment that ends the file. Which file follows
// which depends on the order that find gives, so each kind comes in tens.
func TestCheckCommentsReadsEachFileOnItsOwn(t *testing.T) {
	const files = 10
	tree := make(map[string]string)
	for i := range files {
		// Starts with code that a block comment left open would take for its text.
		tree[fmt.Sprintf("block%d.go", i)] = "var R9 = 1\n/* never closed\n"
		// Starts with a comment that a raw string left open would take for its text.
		tree[fmt.Sprintf("raw%d.go", i)] = "// per R8\nvar s = " + tick + "never closed\n"
		// Starts and ends with a comment, which make the idiom when they are read as one.
		tree[fmt.Sprintf("wrap%d.go", i)] = "// out of the box\npackage p\n\n// the ruling"
	}

	output, code := check(t, tree)

	require.Equal(t, exitCited, code, output)
	for i := range files {
		require.Contains(t, output, cited(fmt.Sprintf("raw%d.go", i), 1, "R8"))
		require.Contains(t, output, cited(fmt.Sprintf("wrap%d.go", i), 4, ruling))
	}
	require.NotContains(t, output, "block")
	require.Equal(t, 2*files, strings.Count(output, "comment cites"), output)
}

// The script reads a line through windows of a few hundred characters. A line longer than that
// must read as a short one does, wherever a token falls at the end of a window, so each shape puts
// its token at every place in and around the end of the first window.
func TestCheckCommentsReadsALongLineLikeAShortOne(t *testing.T) {
	const first, last = 470, 560
	shapes := []struct {
		name  string
		fill  string                  // what the pad is made of
		line  func(pad string) string // a line whose token comes after the pad
		cites bool                    // whether the line holds a citation
	}{
		{"an escaped quote ends nothing", "a", func(pad string) string {
			return `var s = "` + pad + `\"" // per R6`
		}, true},
		{"an escaped backslash ends nothing", "a", func(pad string) string {
			return `var s = "` + pad + `\\" // per R6`
		}, true},
		{"a raw string ends", "a", func(pad string) string {
			return "var s = " + tick + pad + tick + " // per R6"
		}, true},
		{"a rune follows a string", "a", func(pad string) string {
			return `var s = "` + pad + `" + '"' // per R6`
		}, true},
		{"a line comment follows a gap", " ", func(pad string) string {
			return "var s = 1" + pad + " // per R6"
		}, true},
		{"a block comment follows a gap", " ", func(pad string) string {
			return "var s = 1" + pad + " /* per R6 */"
		}, true},
		{"a citation follows a gap in a comment", " ", func(pad string) string {
			return "// " + pad + " R6"
		}, true},
		{"a block comment ends", "a", func(pad string) string {
			return "/* " + pad + "*/\nvar R6 = 1"
		}, false},
		{"a string ends after an escaped quote", "a", func(pad string) string {
			return `var s = "` + pad + `\""` + "\nvar R6 = 1"
		}, false},
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			tree := make(map[string]string)
			for k := first; k <= last; k++ {
				tree[fmt.Sprintf("%d.go", k)] = goFile(sh.line(strings.Repeat(sh.fill, k)) + "\n")
			}

			output, code := check(t, tree)

			if !sh.cites {
				require.Zero(t, code, output)
				require.Empty(t, output)
				return
			}
			require.Equal(t, exitCited, code, output)
			for k := first; k <= last; k++ {
				require.Contains(t, output, cited(fmt.Sprintf("%d.go", k), 3, "R6"))
			}
			require.Equal(t, last-first+1, strings.Count(output, "comment cites"), output)
		})
	}
}

// A line of embedded data must not cost the square of its length: this one is a megabyte of
// escapes in one string, as a generated file of data has it, and it took minutes once.
func TestCheckCommentsReadsAMegabyteLineInSeconds(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		sourceFile: goFile("var data = \"" + strings.Repeat(`\x1f\x8b`, 250_000) + "\" // per R6\n"),
	})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	output, code := runWithin(t, ctx, scriptPath(t), root)

	require.Equal(t, exitCited, code, output)
	require.Contains(t, output, cited(sourceFile, 3, "R6"))
}

func TestCheckCommentsReportsEveryCitationOfAFile(t *testing.T) {
	output, code := check(t, map[string]string{sourceFile: goFile(
		"// per R9 and R10,\n// and the ruling\n\nvar limit = 5 // the SDD ledger\n")})

	require.Equal(t, exitCited, code, output)
	require.Contains(t, output, cited(sourceFile, 3, "R9"))
	require.Contains(t, output, cited(sourceFile, 3, "R10"))
	require.Contains(t, output, cited(sourceFile, 4, ruling))
	require.Contains(t, output, cited(sourceFile, 6, sddLedger))
}

func TestCheckCommentsTellsWhatToDoInstead(t *testing.T) {
	output, code := check(t, map[string]string{sourceFile: goFile("// per R9\n")})

	require.Equal(t, exitCited, code, output)
	require.Contains(t, output, "state its reason itself")
	require.Contains(t, output, "docs/decisions")
}

// Without an argument the script reads the tree that it is part of, the parent of its directory,
// and does so whichever directory it is run from.
func TestCheckCommentsReadsItsOwnTreeByDefault(t *testing.T) {
	script, err := os.ReadFile(scriptPath(t))
	require.NoError(t, err)
	root := t.TempDir()
	write(t, root, map[string]string{"internal/x.go": goFile("// per R9\n")})
	require.NoError(t, os.MkdirAll(filepath.Join(root, "hack"), 0o755))
	installed := filepath.Join(root, "hack", scriptName)
	require.NoError(t, os.WriteFile(installed, script, 0o755))
	t.Chdir(t.TempDir())

	output, code := run(t, installed)

	require.Equal(t, exitCited, code, output)
	require.Contains(t, output, cited("internal/x.go", 3, "R9"))
}

func TestCheckCommentsRefusesARootThatIsNotADirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	output, code := run(t, scriptPath(t), missing)

	require.Equal(t, exitUsage, code, output)
	require.Contains(t, output, missing)
}

func TestCheckCommentsRefusesMoreThanOneRoot(t *testing.T) {
	output, code := run(t, scriptPath(t), t.TempDir(), t.TempDir())

	require.Equal(t, exitUsage, code, output)
	require.Contains(t, output, "usage")
}

// A check that can't run must not pass. The script runs awk through find, so without awk it fails,
// and says what is missing.
func TestCheckCommentsFailsWhenItCannotRun(t *testing.T) {
	// The only tools on the path are the ones that the script needs before awk.
	bin := t.TempDir()
	for _, tool := range []string{"bash", "find", "dirname"} {
		path, err := exec.LookPath(tool)
		require.NoError(t, err)
		require.NoError(t, os.Symlink(path, filepath.Join(bin, tool)))
	}
	root := t.TempDir()
	write(t, root, map[string]string{sourceFile: goFile("var limit = 5\n")})
	cmd := exec.CommandContext(t.Context(), scriptPath(t), root)
	cmd.Env = []string{"PATH=" + bin}

	out, err := cmd.CombinedOutput()

	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, string(out))
	require.Equal(t, exitCited, exit.ExitCode(), string(out))
	require.Contains(t, string(out), "awk")
}

// The repository passes today, and `make lint` keeps it so.
func TestCheckCommentsPassesOnTheRepository(t *testing.T) {
	output, code := run(t, scriptPath(t))

	require.Zero(t, code, output)
	require.Empty(t, output)
}
