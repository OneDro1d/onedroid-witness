package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/OneDro1d/onedroid-indie/redact"
)

// Fake values only, built at run time so no credential-shaped literal sits in the source.
func hex32(seed string) string {
	const digits = "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < 32; i++ {
		b.WriteByte(digits[(int(seed[i%len(seed)])*7+i*5)%16])
	}
	return b.String()
}

func alnum(n int, seed byte) string {
	const set = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var b strings.Builder
	x := uint32(seed) | 1
	for i := 0; i < n; i++ {
		x = x*1664525 + 1013904223 // a fixed LCG: deterministic, high entropy, not a real credential
		b.WriteByte(set[(x>>16)%uint32(len(set))])
	}
	return b.String()
}

// The shapes an ordinary PrestaShop shop page carries in its inline JS, as the audit's text copy shows them.
func prestashop() (string, []string) {
	static, tok, api := hex32("static"), hex32("token"), alnum(24, 'k')
	text := "Welcome to the shop\n" +
		`var prestashop = {"static_token":"` + static + `","token":"` + tok + `","cart":{"products":[]}};` + "\n" +
		`var consentSettings = {"ApiToken":"` + api + `","lang":"en"};` + "\n" +
		"var passwordCaptchaInterval = setInterval(function(){ check(); }, 500);\n" +
		"Free delivery from 50 EUR. Founded in 2009.\n"
	return text, []string{static, tok, api, "setInterval(function(){"}
}

func TestPrestaShopCopyIsRedactedToZeroMatches(t *testing.T) {
	in, values := prestashop()
	if len(redact.Scan(in)) == 0 {
		t.Fatal("the fixture must hold matches for the store's rules")
	}
	out, spans, passes, err := Redact(in)
	if err != nil {
		t.Fatal(err)
	}
	if ms := redact.Scan(out); len(ms) != 0 {
		t.Fatalf("the output still matches: %d span(s), first rule %s", len(ms), ms[0].RuleID)
	}
	for _, v := range values {
		if strings.Contains(out, v) {
			t.Errorf("a matched value survived (len %d)", len(v))
		}
	}
	if len(spans) < 4 {
		t.Errorf("want at least 4 replaced spans, got %d", len(spans))
	}
	for _, s := range spans {
		if s.Rule != "secret-assignment" || s.Pass != 1 || s.Start >= s.End {
			t.Errorf("unexpected span %+v", s)
		}
	}
	if passes != 2 {
		t.Errorf("one replacement round and a clean rescan: want 2 scans, got %d", passes)
	}
	for _, keep := range []string{"Welcome to the shop", "Free delivery from 50 EUR. Founded in 2009.", `"lang":"en"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("text outside the spans changed: %q is gone", keep)
		}
	}
	if !strings.Contains(out, `"static_token":"[REDACTED: secret-assignment]"`) {
		t.Errorf("the placeholder is not where the value was:\n%s", out)
	}
}

// Why the placeholder has a space: the literal "[REDACTED:<rule>]" is itself a secret-assignment value (12+ characters, no
// space or quote, entropy over 3 bits), so a copy redacted with it would still be refused by the store.
func TestTheLiteralPlaceholderWouldStillBeRefused(t *testing.T) {
	literal := `"token":"[REDACTED:secret-assignment]"`
	if len(redact.Scan(literal)) == 0 {
		t.Skip("the pinned rules no longer read the literal placeholder as a value; the space is then belt and braces")
	}
	ours := `"token":"` + Placeholder("secret-assignment") + `"`
	if ms := redact.Scan(ours); len(ms) != 0 {
		t.Fatalf("our placeholder matches %s", ms[0].RuleID)
	}
}

// Every rule of the pinned set: each sample is found, replaced, and the output scans clean.
func TestEveryRuleRedactsToZero(t *testing.T) {
	samples := map[string]string{
		"private-key":       "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + alnum(64, 'p') + "\n" + alnum(40, 'q') + "\n-----END " + "OPENSSH PRIVATE KEY-----",
		"anthropic-api-key": "key " + "sk-" + "ant-" + alnum(40, 'a') + " end",
		"openai-api-key":    "key " + "sk-" + "proj-" + alnum(40, 'o') + " end",
		"github-token":      "t " + "gh" + "p_" + alnum(36, 'g') + " end",
		"aws-access-key-id": "id " + "AKIA" + strings.ToUpper(alnum(16, 'w')) + " end",
		"slack-token":       "t " + "xo" + "xb-" + alnum(30, 's') + " end",
		"google-api-key":    "k " + "AI" + "za" + alnum(35, 'z') + " end",
		"stripe-secret-key": "k " + "sk" + "_live_" + alnum(24, 'r') + " end",
		"jwt":               "t " + "ey" + "J" + alnum(20, 'h') + ".ey" + "J" + alnum(20, 'b') + "." + alnum(20, 'c') + " end",
		"bearer-token":      "Authorization: Bearer " + alnum(32, 'x') + " end",
		"secret-assignment": `{"client_secret": "` + alnum(28, 'm') + `"}`,
		"url-credential":    "postgres://app:" + alnum(20, 'u') + "@db.example:5432/x",
	}
	for rule, text := range samples {
		ms := redact.Scan(text)
		if len(ms) == 0 {
			t.Errorf("%s: the sample is not found by the pinned rules", rule)
			continue
		}
		out, spans, _, err := Redact(text)
		if err != nil {
			t.Errorf("%s: %v", rule, err)
			continue
		}
		if left := redact.Scan(out); len(left) != 0 {
			t.Errorf("%s: output still matches %s", rule, left[0].RuleID)
		}
		found := false
		for _, s := range spans {
			found = found || s.Rule == rule
		}
		if !found {
			t.Errorf("%s: no span carries the rule id (got %+v)", rule, spans)
		}
		for _, m := range ms {
			if strings.Contains(out, text[m.Start:m.End]) {
				t.Errorf("%s: the matched value survived", rule)
			}
		}
	}
}

func TestNoMatchIsByteIdentical(t *testing.T) {
	in := "Company 0420: Acme Ltd, registered 1990.\nThe token count is 4000. Passwords are never shown.\nété — \U0001F600\n"
	out, spans, passes, err := Redact(in)
	if err != nil || out != in || len(spans) != 0 || passes != 1 {
		t.Fatalf("want the input back untouched: err %v, same %v, spans %d, passes %d", err, out == in, len(spans), passes)
	}
	var stdout, stderr bytes.Buffer
	if code := run(strings.NewReader(in), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var r Result
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Text != in || len(r.Matches) != 0 || r.Matches == nil {
		t.Fatalf("JSON: same %v, matches %v (want [] not null)", r.Text == in, r.Matches)
	}
	if !strings.HasPrefix(r.Rules, redactModule) {
		t.Errorf("rules %q", r.Rules)
	}
}

func TestRunPrintsOnlyTheRedactedText(t *testing.T) {
	in, values := prestashop()
	var stdout, stderr bytes.Buffer
	if code := run(strings.NewReader(in), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, v := range values {
		if strings.Contains(stdout.String(), v) || strings.Contains(stderr.String(), v) {
			t.Fatalf("a matched value was printed (len %d)", len(v))
		}
	}
	var r Result
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Matches) == 0 || len(redact.Scan(r.Text)) != 0 {
		t.Fatalf("matches %d, rescan %d", len(r.Matches), len(redact.Scan(r.Text)))
	}
	// pass-1 offsets are into the input as given
	for _, m := range r.Matches {
		if m.Pass == 1 && (m.End > len(in) || in[m.Start:m.End] == "") {
			t.Errorf("span %+v is not inside the input", m)
		}
	}
}

func TestNotUTF8IsRefusedWithNothingOnStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(bytes.NewReader([]byte{'a', 0xff, 'b'}), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatalf("exit %d, stdout %d bytes", code, stdout.Len())
	}
}

func TestNotConvergedNamesRuleIdsOnly(t *testing.T) {
	e := NotConverged{Rules: []string{"secret-assignment", "jwt", "secret-assignment"}}
	if got := e.Error(); !strings.Contains(got, "jwt, secret-assignment") || !strings.Contains(got, "3 credential-shaped") {
		t.Fatalf("%q", got)
	}
}
