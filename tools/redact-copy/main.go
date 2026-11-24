// Command redact-copy takes the credential-shaped spans out of one text with the evidence store's own rules, so a folder
// made of such texts passes the store's scan.
//
// The store (onedroid-fleet internal/evidence/folder.go, Check) runs redact.Scan from github.com/OneDro1d/onedroid-indie/redact
// over every file of a claims-snapshot folder but the .sig files, and refuses the whole folder when anything matches. The
// audit's text copies of fetched web pages (sources/NNN.txt) routinely hold such strings (a shop's inline
// "static_token":"<32 hex>", a consent module's "ApiToken":"..."), so the package step pipes each copy through this command
// before it writes it. The rules are imported, not restated: go.mod pins the very module version the store is built with,
// and that require line is the one place to bump it.
//
// stdin: the text (UTF-8). stdout: one JSON object
//
//	{"text": <the text, each matched span replaced by [REDACTED: <rule id>]>,
//	 "matches": [{"rule": <rule id>, "start": <byte>, "end": <byte>, "pass": <n>}, ...],
//	 "passes": <scans run>, "rules": "<module path> <version>"}
//
// start and end are byte offsets into the text pass n scanned (pass 1 scans the input as given). The output is scanned
// again after every replacement until a scan finds nothing, at most maxPasses replacement rounds; still finding something
// after that is exit 3, with nothing on stdout. Not UTF-8 or unreadable input is exit 2. A matched value is never printed:
// stdout carries only the text with every match gone, stderr only rule ids and counts.
//
// The placeholder has a space after the colon. The store's secret-assignment rule reads a value of 12 or more characters
// that are neither space nor quote, so the literal "[REDACTED:secret-assignment]" after `"token":"` is itself a match and
// a copy redacted with it would still be refused; "[REDACTED: " stops that value at 10 characters (see main_test.go).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/OneDro1d/onedroid-indie/redact"
)

const (
	redactModule = "github.com/OneDro1d/onedroid-indie"
	maxPasses    = 8
	maxInput     = 64 << 20
)

// Span is one replaced match.
type Span struct {
	Rule  string `json:"rule"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Pass  int    `json:"pass"`
}

// Result is what the command prints.
type Result struct {
	Text    string `json:"text"`
	Matches []Span `json:"matches"`
	Passes  int    `json:"passes"`
	Rules   string `json:"rules"`
}

// Placeholder is what a matched span becomes.
func Placeholder(rule string) string { return "[REDACTED: " + rule + "]" }

// NotConverged is the error of a text that still matches after maxPasses replacement rounds; it names rule ids only.
type NotConverged struct{ Rules []string }

func (e NotConverged) Error() string {
	return fmt.Sprintf("still %d credential-shaped span(s) after %d replacement rounds (rules: %s)", len(e.Rules), maxPasses,
		strings.Join(uniq(e.Rules), ", "))
}

// Redact replaces every span redact.Scan finds, scanning again until nothing is found: the text, every replaced span, and
// the number of scans run. A text Scan finds nothing in comes back as it is, with no spans and one scan.
func Redact(text string) (string, []Span, int, error) {
	spans := []Span{}
	for pass := 1; ; pass++ {
		ms := redact.Scan(text)
		if len(ms) == 0 {
			return text, spans, pass, nil
		}
		if pass > maxPasses {
			ids := make([]string, len(ms))
			for i, m := range ms {
				ids[i] = m.RuleID
			}
			return "", nil, pass, NotConverged{Rules: ids}
		}
		var b strings.Builder
		pos := 0
		for _, m := range ms { // Scan's spans are ordered and never overlap
			spans = append(spans, Span{Rule: m.RuleID, Start: m.Start, End: m.End, Pass: pass})
			b.WriteString(text[pos:m.Start])
			b.WriteString(Placeholder(m.RuleID))
			pos = m.End
		}
		b.WriteString(text[pos:])
		text = b.String()
	}
}

// RulesVersion is "<module path> <version>" of the redact module this binary was built with.
func RulesVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, d := range info.Deps {
			if d.Path == redactModule {
				if d.Replace != nil {
					return d.Path + " " + d.Version + " (replaced by " + d.Replace.Path + " " + d.Replace.Version + ")"
				}
				return d.Path + " " + d.Version
			}
		}
	}
	return redactModule + " (version not recorded in this build)"
}

func uniq(ids []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func run(in io.Reader, out, errw io.Writer) int {
	data, err := io.ReadAll(io.LimitReader(in, maxInput+1))
	if err != nil {
		fmt.Fprintln(errw, "redact-copy: stdin does not read:", err)
		return 2
	}
	if len(data) > maxInput {
		fmt.Fprintf(errw, "redact-copy: stdin is over %d bytes\n", maxInput)
		return 2
	}
	if !utf8.Valid(data) {
		fmt.Fprintln(errw, "redact-copy: stdin is not UTF-8")
		return 2
	}
	text, spans, passes, err := Redact(string(data))
	if err != nil {
		fmt.Fprintln(errw, "redact-copy:", err)
		return 3
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(Result{Text: text, Matches: spans, Passes: passes, Rules: RulesVersion()}); err != nil {
		fmt.Fprintln(errw, "redact-copy: stdout:", err)
		return 2
	}
	return 0
}

func main() { os.Exit(run(os.Stdin, os.Stdout, os.Stderr)) }
