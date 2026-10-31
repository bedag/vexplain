#!/usr/bin/env bash
#
# Usage: hack/check-comments.sh [root]
#
# check-comments.sh fails when a comment in a Go file cites a decision that is kept outside the
# repository, and names each such comment. A reader of the repository can't look the decision up, so
# a comment states its reason itself. While a plan is carried out, the agent that carries it out
# keeps a ledger of numbered decisions of its own, outside the repository, and a comment is easily
# tempted to cite them. A decision record in docs/decisions is part of the repository, and a comment
# may cite it by its number.
#
# The script reads the comments of the Go files below root, which is the root of the repository
# unless an argument says otherwise. It flags a comment that cites one of those decisions
#   - by number: an R and digits, as a word of their own, such as R9
#   - by name: the word ruling, rulings or ledger, in any case, except in "ruling out"
# and passes the rest: RFC 3339, "ruling out", and identifiers and strings that only look like
# what it flags, because it reads comments, and nothing else. It skips generated code
# (zz_generated.* and *.pb.go), bin/ at the root, where make installs its tools, vendored code
# (vendor directories), and the hidden directories, such as .git and the agent's own.
#
# Exit status: 0 when no comment cites such a decision, 1 when one does, and 2 when the script is
# called wrongly. `make lint` runs it.

set -euo pipefail

if [[ $# -gt 1 ]]; then
    echo "usage: ${0##*/} [root]" >&2
    exit 2
fi
root=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
if [[ ! -d $root ]]; then
    echo "${0##*/}: $root is not a directory" >&2
    exit 2
fi

# The patterns are ASCII. With bytes for characters, a file that is not valid UTF-8 can't stop awk,
# and awk's classes of letters mean the same on every machine.
export LC_ALL=C

# The awk program is plain POSIX awk, for the awk of macOS as well as for gawk and mawk. A Go
# comment starts with // and runs to the end of the line, or starts with /* and ends at */. The
# program tells those from text that only looks like one, inside a string "...", a rune '...' or a
# raw string `...`, which can run over several lines. Where comments of consecutive lines meet, it
# reads them as one text, so that a phrase wrapped over two lines is the phrase that it is.
IFS= read -r -d '' program <<'AWK' || true
function isword(c) {
    return c != "" && c ~ /[A-Za-z0-9_]/
}

# charbefore is the character of s before position at, or "" at the start.
function charbefore(s, at) {
    return at > 1 ? substr(s, at - 1, 1) : ""
}

# ruledout says whether tail, the text after the word ruling, goes on with the word out, and so makes
# the idiom "ruling out". Whitespace includes a line end, because a comment can wrap there.
function ruledout(tail) {
    return match(tail, /^[ \t\r\n]+out/) && !isword(substr(tail, RLENGTH + 1, 1))
}

# The scan reads a line through windows of W characters. A very long line, such as embedded data,
# then costs time in proportion to its length, where a copy of the rest of the line for every token
# would make it cost the square of that.

# nextof returns the position of the first character at or after pos that set matches, which is a
# bracket expression or one character, or 0 when the line has none.
function nextof(set, pos,    k) {
    while (pos <= n) {
        k = match(substr(line, pos, W), set)
        if (k > 0) {
            return pos + k - 1
        }
        pos += W
    }
    return 0
}

# endofblock returns the position of the */ at or after pos, which closes a block comment, or 0.
# Consecutive windows share a character, because a window can end in the * of the */.
function endofblock(pos,    k) {
    while (pos <= n) {
        k = index(substr(line, pos, W), "*/")
        if (k > 0) {
            return pos + k - 1
        }
        pos += W - 1
    }
    return 0
}

# endofquoted returns the position after the closing q of a string or a rune, which starts at pos,
# or past the end of the line when that comes first, because neither runs over lines. A quote is
# escaped when an odd number of backslashes come right before it.
function endofquoted(q, pos,    p, backslashes) {
    while ((p = nextof(q, pos)) > 0) {
        backslashes = 0
        while (substr(line, p - backslashes - 1, 1) == "\\") {
            backslashes++
        }
        if (backslashes % 2 == 0) {
            return p + 1
        }
        pos = p + 1
    }
    return n + 1
}

# cite names the citation that is len characters long at position at of text, which starts on line
# firstline of the file.
function cite(text, at, len, firstline,    before) {
    before = substr(text, 1, at - 1)
    printf "%s:%d: comment cites \"%s\"\n", name, firstline + gsub(/\n/, "\n", before), substr(text, at, len)
    bad = 1
}

# check looks in text for what it must not cite. The text is the comments of the lines from
# firstline on, one line of text for each line of the file.
function check(text, firstline,    low, off, at, len, word) {
    # By number: an R and digits, as a word of their own.
    off = 0
    while (match(substr(text, off + 1), /R[0-9]+/)) {
        at = off + RSTART
        len = RLENGTH
        if (!isword(charbefore(text, at)) && !isword(substr(text, at + len, 1))) {
            cite(text, at, len, firstline)
        }
        off = at + len - 1
    }
    # By name: ruling, rulings or ledger, as a word of their own and in any case. "ruling out" is
    # no citation, even when the line ends between the two words.
    low = tolower(text)
    off = 0
    while (match(substr(low, off + 1), /rulings?|ledger/)) {
        at = off + RSTART
        len = RLENGTH
        word = substr(low, at, len)
        if (!isword(charbefore(low, at)) && !isword(substr(low, at + len, 1)) &&
            !(word == "ruling" && ruledout(substr(low, at + len)))) {
            cite(text, at, len, firstline)
        }
        off = at + len - 1
    }
}

# flush checks the comments that were gathered, and starts a new group.
function flush() {
    if (live) {
        check(group, groupline)
    }
    live = 0
    group = ""
}

BEGIN {
    bad = 0
    W = 512
}

# A new file starts. The comments that the file before it ended with belong to that file, so they
# are checked first.
FNR == 1 {
    flush()
    name = FILENAME
    sub(/^\.\//, "", name)
    # 0 is code, 1 is inside a block comment, and 2 is inside a raw string
    state = 0
}

{
    line = $0
    n = length(line)
    pos = 1
    comment = ""
    # Whether comment text is on this line: a line inside a block comment has it, even when empty.
    touched = (state == 1)
    while (pos <= n) {
        if (state == 1) {
            k = endofblock(pos)
            if (k == 0) {
                comment = comment substr(line, pos)
                break
            }
            comment = comment substr(line, pos, k - pos) " "
            pos = k + 2
            state = 0
        } else if (state == 2) {
            k = nextof("`", pos)
            if (k == 0) {
                break
            }
            pos = k + 1
            state = 0
        } else {
            # In code, the next character that starts a string, a rune, a raw string or a comment.
            k = nextof("[\"`'/]", pos)
            if (k == 0) {
                break
            }
            c = substr(line, k, 1)
            pos = k + 1
            if (c == "\"" || c == "'") {
                pos = endofquoted(c, pos)
            } else if (c == "`") {
                state = 2
            } else if (substr(line, pos, 1) == "/") {
                touched = 1
                comment = comment substr(line, pos + 1)
                break
            } else if (substr(line, pos, 1) == "*") {
                touched = 1
                state = 1
                pos++
            }
        }
    }
    if (touched) {
        if (!live) {
            live = 1
            groupline = FNR
            group = ""
        }
        group = group comment "\n"
    } else {
        flush()
    }
}

END {
    flush()
    if (bad) {
        print "check-comments: a comment must state its reason itself. It may cite a decision record of"
        print "docs/decisions by its number, and nothing that is kept outside the repository."
    }
    exit bad
}
AWK

cd "$root"
# A check that can't run must not pass. So the script fails when find does, which it does when a run
# of awk does, and also when anything is written: a passing check is silent, and so is awk's own
# complaint about a file that it can't read.
status=0
report=$(find . \( -name '.?*' -o -path ./bin -o -name vendor \) -prune -o \
    -type f -name '*.go' ! -name 'zz_generated.*' ! -name '*.pb.go' \
    -exec awk "$program" {} + 2>&1) || status=1
if [[ -n $report ]]; then
    printf '%s\n' "$report" >&2
    status=1
fi
exit "$status"
