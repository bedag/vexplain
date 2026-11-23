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

package fetch

import (
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// dropped are the elements whose content a browser doesn't show as text, or that the parser reads as raw text.
var dropped = map[atom.Atom]bool{
	atom.Script: true, atom.Style: true, atom.Noscript: true, atom.Template: true, atom.Iframe: true, atom.Svg: true,
	atom.Object: true, atom.Noembed: true, atom.Noframes: true,
}

// separators are what an element puts around its text: a line for a block, a space for a table cell, which a browser
// sets apart too.
var separators = map[atom.Atom]byte{
	atom.Address: '\n', atom.Article: '\n', atom.Aside: '\n', atom.Blockquote: '\n', atom.Br: '\n', atom.Caption: '\n',
	atom.Dd: '\n', atom.Details: '\n', atom.Div: '\n', atom.Dl: '\n', atom.Dt: '\n', atom.Figcaption: '\n',
	atom.Figure: '\n', atom.Footer: '\n', atom.Form: '\n', atom.H1: '\n', atom.H2: '\n', atom.H3: '\n', atom.H4: '\n',
	atom.H5: '\n', atom.H6: '\n', atom.Header: '\n', atom.Hr: '\n', atom.Li: '\n', atom.Main: '\n', atom.Nav: '\n',
	atom.Ol: '\n', atom.P: '\n', atom.Pre: '\n', atom.Section: '\n', atom.Summary: '\n', atom.Table: '\n',
	atom.Title: '\n', atom.Tr: '\n', atom.Ul: '\n',
	atom.Td: ' ', atom.Th: ' ',
}

// htmlText returns the text of an HTML page: what a browser shows of it, without scripts, styles and hidden elements,
// with a line for each block, and whitespace collapsed (collapse). Links keep their text, and no attribute is read
// as text, so no URL of a link reaches the text: a page can't hand the agent a URL to follow that way.
func htmlText(r io.Reader) (string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			// A line break in HTML's text is a space: only blocks make lines.
			b.WriteString(strings.Map(func(r rune) rune {
				if unicode.IsSpace(r) {
					return ' '
				}
				return r
			}, n.Data))
			return
		}
		if n.Type == html.ElementNode && (dropped[n.DataAtom] || hidden(n)) {
			return
		}
		sep := separators[n.DataAtom]
		if sep != 0 {
			b.WriteByte(sep)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
		if sep != 0 {
			b.WriteByte(sep)
		}
	}
	walk(doc)
	return collapse(b.String()), nil
}

// hidden reports whether a browser hides the element: by the attribute hidden, aria-hidden="true", or a style of
// display: none or visibility: hidden.
func hidden(n *html.Node) bool {
	for _, a := range n.Attr {
		value := strings.ToLower(strings.Join(strings.Fields(a.Val), ""))
		switch {
		case a.Key == "hidden",
			a.Key == "aria-hidden" && value == "true",
			a.Key == "style" && (strings.Contains(value, "display:none") || strings.Contains(value, "visibility:hidden")):
			return true
		}
	}
	return false
}

// collapse turns each run of whitespace into one line break where the run holds one, and else into one space, and
// drops it at the ends. It drops the other control characters, the format characters, such as zero-width ones, bidi
// controls and tags, and the variation selectors, which a page shows as nothing: they could carry text that a person
// reading it doesn't see.
func collapse(s string) string {
	var b strings.Builder
	var pending rune
	for _, r := range s {
		switch {
		case r == '\n':
			pending = '\n'
		case unicode.IsSpace(r):
			if pending == 0 {
				pending = ' '
			}
		case unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Variation_Selector):
		default:
			if pending != 0 && b.Len() > 0 {
				b.WriteRune(pending)
			}
			pending = 0
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cutBytes returns the start of s that is at most n bytes long, without cutting a character.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
