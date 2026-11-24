// SPDX-License-Identifier: Apache-2.0

// Package redact is the one deterministic secret rule set for the agent record. The kit redacts
// summaries with it and its credential monitor raises alerts from it. The Argus suite imports the
// same package, so a secret one copy misses is never one the other also leaks (ARGUS-KIT-SPEC.md,
// K4).
//
// It is a rewrite of the Synapse recorder's secrets package (MCP-router
// internal/agentrecord/secrets at f94f4759). The rules and their ids and versions are unchanged.
//
// Standard library only: it is compiled into the kit's binary, which runs on developer machines.
package redact

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Match is one detected secret.
type Match struct {
	RuleID      string
	RuleVersion int
	Severity    string
	Start, End  int // byte offsets into the scanned text
}

type rule struct {
	id         string
	version    int
	severity   string
	re         *regexp.Regexp
	group      int            // capture group holding the secret; 0 = whole match
	minEntropy float64        // bits per character the secret must reach; 0 = no check
	notValue   *regexp.Regexp // a secret matching this is a shape the rule misreads, not a secret; nil = no check
	// notValueKey limits notValue to matches whose capture group 1 (the key word) matches it; nil = any key
	notValueKey *regexp.Regexp
}

// Order matters only as a tie-break: when two rules match the same span, the earlier wins
// (so an Anthropic key is never also reported as an OpenAI key).
var rules = []rule{
	// v2 (Loom's review D4): the whole key is the secret, not its BEGIN line. The first form runs
	// to the END line (also across JSON-escaped "\n"); the second covers a key cut off before its
	// END line — the BEGIN line plus every base64 line after it. Same id: Scan keeps the longer.
	{id: "private-key", version: 2, severity: "critical",
		re: regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)},
	// v3 (validator finding 11): also its short final line (a PEM's last line is often a few
	// characters) — the key alone is captured (group 1), never the character after it.
	{id: "private-key", version: 3, severity: "critical", group: 1,
		re: regexp.MustCompile(`(-----BEGIN [A-Z ]*PRIVATE KEY-----(?:(?:\s|\\[nr])*[A-Za-z0-9+/=]{16,})*(?:(?:\r?\n|\\n)[A-Za-z0-9+/=]{1,15})?)(?:[^A-Za-z0-9+/=]|$)`)},
	{id: "anthropic-api-key", version: 1, severity: "critical",
		re: regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	{id: "openai-api-key", version: 1, severity: "critical",
		re: regexp.MustCompile(`sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}`)},
	{id: "github-token", version: 1, severity: "critical",
		re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b`)},
	{id: "aws-access-key-id", version: 1, severity: "high",
		re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{id: "slack-token", version: 1, severity: "high",
		re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{id: "google-api-key", version: 1, severity: "high",
		re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	// Stripe secret and restricted keys (gate of 10 Nov: a `curl -H 'Authorization: Bearer sk_live_…'`
	// reached the summary whole). Listed before bearer-token so the specific label wins a tie.
	{id: "stripe-secret-key", version: 1, severity: "critical",
		re: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`)},
	{id: "jwt", version: 1, severity: "high",
		re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	// Any token after "Bearer" (same gate): the header has no key word for secret-assignment, so a
	// credential of a shape no rule knows went through. The word Bearer stays; only the token
	// (group 1) goes. After the specific rules, so a JWT or a Stripe key keeps its own label.
	{id: "bearer-token", version: 1, severity: "high", group: 1, minEntropy: 3.0,
		re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})`)},
	// v2 (Loom's review D3): the key may be quoted, as in JSON — `"password":"…"`, also with the
	// quotes escaped when the JSON sits inside a JSON string (hook payloads, tool inputs).
	// v3 (Codex parity test S-A9): in code the value has no quotes to stop it, so a token COUNT
	// (`max_output_tokens:4000}),tools.exec_command(…`) ran on into the code after it. A number
	// too short to be a secret on its own, closed by code punctuation, is that number.
	// v4 (Loom's review of #175): only under a "token" key — that is where the counts are. A
	// password, secret or key that starts with `1234,` is still a secret.
	{id: "secret-assignment", version: 4, severity: "high", group: 2, minEntropy: 3.0,
		notValue:    regexp.MustCompile(`^\d{1,11}[,;)}\]]`),
		notValueKey: regexp.MustCompile(`(?i)^token$`),
		re:          regexp.MustCompile(`(?i)\b[A-Z0-9_]*(password|passwd|secret|api[_-]?key|access[_-]?key|token)[A-Z0-9_]*\\?["']?\s*[:=]\s*\\?["']?([^\s"'\\]{12,})`)},
	// The password in a connection URL (scheme://user:password@host). Loom's review D7.
	{id: "url-credential", version: 1, severity: "high", group: 1, minEntropy: 2.5,
		re: regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.\-]{1,15}://[^\s/:@"'\\]{1,64}:([^\s/@"'\\]{8,128})@[A-Za-z0-9.\-\[\]]`)},
}

// Scan returns every secret in text, ordered by position, never overlapping.
func Scan(text string) []Match {
	var all []Match
	for _, r := range rules {
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := loc[2*r.group], loc[2*r.group+1]
			if s < 0 {
				continue
			}
			if r.minEntropy > 0 && entropy(text[s:e]) < r.minEntropy {
				continue
			}
			if r.notValue != nil && r.notValue.MatchString(text[s:e]) &&
				(r.notValueKey == nil || loc[2] >= 0 && r.notValueKey.MatchString(text[loc[2]:loc[3]])) {
				continue
			}
			all = append(all, Match{RuleID: r.id, RuleVersion: r.version, Severity: r.severity,
				Start: s, End: e})
		}
	}
	return MergeSpans(all)
}

// rulePrio orders rule ids for the tie-break (first listed wins). Ids not in the rule set — a
// caller's own spans, such as hub credentials found by fingerprint — win a tie: they name the
// exact credential, which is more useful in "[REDACTED:…]" than the pattern that also matched.
var rulePrio = func() map[string]int {
	p := map[string]int{}
	for i, r := range rules {
		if _, ok := p[r.id]; !ok {
			p[r.id] = i
		}
	}
	return p
}()

func prioOf(id string) int {
	if p, ok := rulePrio[id]; ok {
		return p
	}
	return -1
}

// MergeSpans orders spans by position and never lets two overlap: a span inside one already kept
// is dropped (at the same start the longer wins, then the earlier rule); a span that starts inside
// one already kept but runs past it is kept from where that one ends, with its own rule — so every
// byte either covered stays covered (validator finding 13: a private key starting inside a
// secret-assignment value was dropped, its body left in the clear). Scan's output is already
// merged; a caller combining it with spans of its own merges again before redacting.
func MergeSpans(ms []Match) []Match {
	all := append([]Match(nil), ms...)
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End-a.Start != b.End-b.Start {
			return a.End-a.Start > b.End-b.Start
		}
		return prioOf(a.RuleID) < prioOf(b.RuleID)
	})
	out := make([]Match, 0, len(all))
	end := -1
	for _, m := range all {
		if m.End <= end {
			continue // inside a span already kept
		}
		if m.Start < end {
			m.Start = end // partly overlapping: keep the part past the kept span
		}
		out = append(out, m)
		end = m.End
	}
	return out
}

// Redact replaces every secret with [REDACTED:<rule>].
func Redact(text string) string { return redactMatches(text, Scan(text), 0) }

func redactMatches(text string, ms []Match, offset int) string {
	var b strings.Builder
	pos := 0
	for _, m := range ms {
		s, e := m.Start-offset, m.End-offset
		b.WriteString(text[pos:s])
		b.WriteString("[REDACTED:" + m.RuleID + "]")
		pos = e
	}
	b.WriteString(text[pos:])
	return b.String()
}

// Excerpt returns up to ctx bytes of context either side of m, with every secret in the window
// redacted. A secret cut by the window edge is pulled wholly into the window first, so no
// fragment of a secret can be left behind. Control characters become spaces.
//
// It scans text itself; a caller cutting several excerpts from one text uses ExcerptOf with one
// shared scan — rescanning per excerpt made screening quadratic in the matches (Loom's review
// D1: 2,000 matches in one entry took ~42 s and stalled screening for every hub).
func Excerpt(text string, m Match, ctx int) string { return ExcerptOf(text, Scan(text), m, ctx) }

// ExcerptOf is Excerpt with the spans to hide supplied: ms must be ordered and non-overlapping
// (Scan's output, or MergeSpans of it plus the caller's own spans). Every span in the window is
// redacted, labelled with its RuleID.
func ExcerptOf(text string, ms []Match, m Match, ctx int) string {
	lo, hi := m.Start-ctx, m.End+ctx
	if lo < 0 {
		lo = 0
	}
	if hi > len(text) {
		hi = len(text)
	}
	for _, o := range ms { // widen to whole secrets that straddle an edge
		if o.Start < lo && o.End > lo {
			lo = o.Start
		}
		if o.Start < hi && o.End > hi {
			hi = o.End
		}
	}
	for lo > 0 && !utf8.RuneStart(text[lo]) {
		lo--
	}
	for hi < len(text) && !utf8.RuneStart(text[hi]) {
		hi++
	}
	var in []Match
	for _, o := range ms {
		if o.Start >= lo && o.End <= hi {
			in = append(in, o)
		}
	}
	out := redactMatches(text[lo:hi], in, lo)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, out)
}

// Entropy is the Shannon entropy of s in bits per character.
func Entropy(s string) float64 { return entropy(s) }

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
