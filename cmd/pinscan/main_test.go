package main

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yinkoshield/pinscan/internal/capture"
	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/device"
	"github.com/yinkoshield/pinscan/internal/policy"
	"github.com/yinkoshield/pinscan/internal/report"
	"github.com/yinkoshield/pinscan/internal/scan"
	"github.com/yinkoshield/pinscan/internal/target"
)

func TestRunVersion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run(-version) returned error: %v", err)
	}
	if got, want := stdout.String(), "pinscan "+version+"\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunDefault(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run(nil, &stdout, &stderr); err != nil {
		t.Fatalf("run(nil) returned error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "scan") {
		t.Errorf("stderr = %q, want usage mentioning \"scan\"", stderr.String())
	}
}

func TestRunBadFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-nope"}, &stdout, &stderr); err == nil {
		t.Error("run(-nope) = nil, want an error")
	}
}

func TestRunUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"bogus"}, &stdout, &stderr); err == nil {
		t.Error("run(bogus) = nil error, want an error")
	}
}

func TestRunSelftestPasses(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"selftest"}, &stdout, &stderr); err != nil {
		t.Fatalf("run(selftest) returned error: %v\n%s", err, stdout.String())
	}
	out := stdout.String()
	for _, want := range []string{"no-pinning", "metadata-validation", "name-validation", "spki-pinning", "passthrough", "reason=passthrough", "selftest passed"} {
		if !strings.Contains(out, want) {
			t.Errorf("selftest output missing %q\n%s", want, out)
		}
	}
}

func TestRunScanRequiresPackage(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"scan"}, &stdout, &stderr); err == nil {
		t.Error("run(scan) with no package = nil error, want an error")
	}
}

func TestRunScanRejectsBadFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"scan", "-nope"}, &stdout, &stderr); err == nil {
		t.Error("run(scan -nope) = nil error, want an error")
	}
}

func TestNewLoggerValid(t *testing.T) {
	t.Parallel()

	for _, level := range []string{"error", "warn", "info", "debug"} {
		for _, format := range []string{"text", "json"} {
			var buf bytes.Buffer
			logger, err := newLogger(level, format, &buf)
			if err != nil {
				t.Fatalf("newLogger(%q, %q) returned error: %v", level, format, err)
			}
			if logger == nil {
				t.Fatalf("newLogger(%q, %q) = nil logger", level, format)
			}
		}
	}
}

func TestNewLoggerLevelFilters(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := newLogger("warn", "text", &buf)
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}
	logger.Info("suppressed")
	logger.Warn("kept")
	out := buf.String()
	if strings.Contains(out, "suppressed") {
		t.Errorf("info record leaked at warn level: %q", out)
	}
	if !strings.Contains(out, "kept") {
		t.Errorf("warn record missing at warn level: %q", out)
	}
}

func TestNewLoggerJSONFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := newLogger("info", "json", &buf)
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}
	logger.Info("hello", "k", "v")
	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("json handler did not emit an object: %q", out)
	}
}

func TestNewLoggerInvalid(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if _, err := newLogger("loud", "text", &buf); err == nil {
		t.Error("newLogger with bad level = nil error, want an error")
	}
	if _, err := newLogger("info", "yaml", &buf); err == nil {
		t.Error("newLogger with bad format = nil error, want an error")
	}
}

func TestPrintCaptureEmpty(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := printCapture(&buf, capture.NewRecorder()); err != nil {
		t.Fatalf("printCapture: %v", err)
	}
	if !strings.Contains(buf.String(), "no exchanges") {
		t.Errorf("empty capture output = %q, want a 'no exchanges' note", buf.String())
	}
}

func TestPrintCaptureGroupsByHost(t *testing.T) {
	t.Parallel()

	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{
		Host: "secure.example.com", Method: "GET", URL: "/unleash/api/frontend",
		Status: 200, RespHeaders: http.Header{"Content-Type": {"application/json"}},
		RespBody: []byte(`{"toggles":["pkg.a"]}`),
	})
	rec.Add(capture.Exchange{
		Host: "secure.example.com", Method: "POST", URL: "/log", Err: "forward: timeout",
	})
	rec.Add(capture.Exchange{
		Host: "cdn.example.com", Method: "GET", URL: "/app.js", Status: 200,
		RespBody: []byte("payload"), RespTruncated: true,
	})

	var buf bytes.Buffer
	if err := printCapture(&buf, rec); err != nil {
		t.Fatalf("printCapture: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"== secure.example.com ==",
		"== cdn.example.com ==",
		"GET /unleash/api/frontend -> 200",
		`{"toggles":["pkg.a"]}`,
		"POST /log -> error: forward: timeout",
		"truncated",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("capture output missing %q\n---\n%s", want, out)
		}
	}
}

func TestBodyPreviewTruncatesAndFlattens(t *testing.T) {
	t.Parallel()

	got := bodyPreview([]byte("line1\nline2\ttab"), 100)
	if strings.ContainsAny(got, "\n\t") {
		t.Errorf("preview kept control chars: %q", got)
	}
	if got != "line1 line2 tab" {
		t.Errorf("preview = %q, want control chars flattened to spaces", got)
	}

	long := bodyPreview([]byte(strings.Repeat("x", 50)), 10)
	if !strings.HasSuffix(long, "…") {
		t.Errorf("over-limit preview = %q, want an ellipsis suffix", long)
	}
	if len(long) > len("…")+10+1 {
		t.Errorf("preview not capped: %q", long)
	}
}

func encodeCertPEM(t *testing.T, ca *certmint.CA) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert().Raw})
}

func TestCaModuleCommandWritesModule(t *testing.T) {
	t.Parallel()

	// Generate a CA PEM to embed.
	ca, err := certmint.NewCA("pinscan test CA")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	caPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(caPath, encodeCertPEM(t, ca), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	outDir := t.TempDir() + "/mod"

	var stdout, stderr bytes.Buffer
	if err := run([]string{"ca-module", "-ca", caPath, "-o", outDir}, &stdout, &stderr); err != nil {
		t.Fatalf("ca-module: %v\n%s", err, stderr.String())
	}
	for _, want := range []string{"module.prop", "post-fs-data.sh", "cacert.pem"} {
		if _, err := os.Stat(outDir + "/" + want); err != nil {
			t.Errorf("expected %s in module: %v", want, err)
		}
	}
	// Exactly one cacerts/<hash>.0 file.
	matches, _ := filepath.Glob(outDir + "/system/etc/security/cacerts/*.0")
	if len(matches) != 1 {
		t.Errorf("want one cacerts/<hash>.0, got %v", matches)
	}
	if !strings.Contains(stdout.String(), "/data/adb/modules/") {
		t.Errorf("ca-module should print install instructions:\n%s", stdout.String())
	}
}

func TestCaModuleCommandRejectsMissingCA(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run([]string{"ca-module", "-ca", t.TempDir() + "/nope.pem", "-o", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Error("ca-module with a missing CA = nil error, want an error")
	}
}

func TestBuildTargetSelectsDriver(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	ca, err := certmint.NewCA("buildTarget test CA")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	manual, err := buildTarget(scanOptions{driver: "manual", pkg: "x", caPath: "/ca.pem"}, ca, &buf)
	if err != nil {
		t.Fatalf("manual buildTarget: %v", err)
	}
	if _, ok := manual.(*target.Manual); !ok {
		t.Errorf("driver=manual built %T, want *target.Manual", manual)
	}
	if scan.TrustOf(manual) != scan.TrustAsserted {
		t.Errorf("manual target trust = %s, want operator-asserted", scan.TrustOf(manual))
	}

	android, err := buildTarget(scanOptions{driver: "android", pkg: "com.example.app"}, ca, &buf)
	if err != nil {
		t.Fatalf("android buildTarget: %v", err)
	}
	if _, ok := android.(*target.Android); !ok {
		t.Errorf("driver=android built %T, want *target.Android", android)
	}
	if scan.TrustOf(android) != scan.TrustUnverified {
		t.Errorf("android target trust before any probe = %s, want unverified", scan.TrustOf(android))
	}

	if _, err := buildTarget(scanOptions{driver: "bogus"}, ca, &buf); err == nil {
		t.Error("buildTarget with an invalid driver = nil error, want an error")
	}
}

func TestParseScanArgsRejectsBadDriver(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	if _, err := parseScanArgs([]string{"-driver", "nope", "com.example.app"}, &stderr); err == nil {
		t.Error("parseScanArgs with an invalid driver = nil error, want an error")
	}
}

func TestPrintChecksCountsRequiredFailures(t *testing.T) {
	t.Parallel()

	checks := []device.Check{
		{Name: "ok-required", OK: true, Required: true},
		{Name: "fail-required", OK: false, Required: true, Hint: "do the thing"},
		{Name: "fail-optional", OK: false, Required: false, Hint: "optional"},
	}
	var buf bytes.Buffer
	failed := printChecks(&buf, checks)
	if failed != 1 {
		t.Errorf("failed = %d, want 1 (only the required failure counts)", failed)
	}
	out := buf.String()
	if !strings.Contains(out, "[FAIL] fail-required") {
		t.Errorf("missing FAIL line:\n%s", out)
	}
	if !strings.Contains(out, "[warn] fail-optional") {
		t.Errorf("optional failure should be a warning:\n%s", out)
	}
	if !strings.Contains(out, "do the thing") {
		t.Errorf("hint for a failing check should be shown:\n%s", out)
	}
}

func TestHostChecksCA(t *testing.T) {
	t.Parallel()

	// A missing CA file must produce a failing, required host check.
	checks := hostChecks(t.TempDir() + "/nope.pem")
	ca, ok := func() (device.Check, bool) {
		for _, c := range checks {
			if c.Name == "research CA readable" {
				return c, true
			}
		}
		return device.Check{}, false
	}()
	if !ok {
		t.Fatal("hostChecks missing the CA check")
	}
	if ca.OK || !ca.Required {
		t.Errorf("missing CA should fail a required check: %+v", ca)
	}
}

func TestParseScanArgsPassthroughIsRepeatable(t *testing.T) {
	t.Parallel()

	opts, err := parseScanArgs([]string{"-passthrough", "login.example.com", "-passthrough", "*.auth.example", "com.example.app"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if opts.passthrough.Empty() {
		t.Fatal("passthrough matcher is empty after two -passthrough flags")
	}
	for host, want := range map[string]bool{
		"login.example.com":  true,
		"LOGIN.example.com":  true,
		"sso.auth.example":   true,
		"a.b.auth.example":   true,
		"auth.example":       false,
		"api.example.com":    false,
		"xlogin.example.com": false,
	} {
		if got := opts.passthrough.Match(host); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestParseScanArgsNoPassthroughLeavesMatcherEmpty(t *testing.T) {
	t.Parallel()

	opts, err := parseScanArgs([]string{"com.example.app"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if !opts.passthrough.Empty() {
		t.Errorf("passthrough patterns = %q without any -passthrough flag", opts.passthrough.Patterns())
	}
}

func TestParseScanArgsMergesPolicyPassthrough(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".pinscan.yaml")
	if err := os.WriteFile(path, []byte(`
hosts:
  login.bank.example:
    passthrough: true
    reason: SPKI-pinned login API
  api.bank.example:
    expect: spki
    reason: must pin
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	opts, err := parseScanArgs([]string{"-policy", path, "-passthrough", "*.cdn.example", "com.example.app"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if !opts.passthrough.Match("login.bank.example") {
		t.Error("the policy's passthrough host is not matched")
	}
	if !opts.passthrough.Match("img.cdn.example") {
		t.Error("the -passthrough flag is not matched alongside the policy")
	}
	if opts.passthrough.Match("api.bank.example") {
		t.Error("an expect-only policy host must not be passthrough")
	}
}

func TestParseScanArgsRejectsMalformedPassthrough(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{"*.", "api.*.example", ""} {
		if _, err := parseScanArgs([]string{"-passthrough", pattern, "com.example.app"}, &bytes.Buffer{}); err == nil {
			t.Errorf("parseScanArgs(-passthrough %q) = nil error, want a usage error", pattern)
		}
	}
}

func TestParseScanArgsAcceptsRelayEverything(t *testing.T) {
	t.Parallel()

	// The bare * is the explicit discovery run: every host is relayed and
	// listed, nothing is tested.
	opts, err := parseScanArgs([]string{"-passthrough", "*", "com.example.app"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseScanArgs(-passthrough *): %v", err)
	}
	if !opts.passthrough.MatchesAll() || !opts.passthrough.Match("anything.example") {
		t.Errorf("-passthrough * did not produce a relay-everything matcher: %q", opts.passthrough.Patterns())
	}
}

func TestStringListCollectsValues(t *testing.T) {
	t.Parallel()

	var l stringList
	for _, v := range []string{"a", "b"} {
		if err := l.Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	if got := l.String(); got != "a,b" {
		t.Errorf("String() = %q, want a,b", got)
	}
}

func TestPrintTallyShowsPassthroughBucket(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	if err := printTally(&out, scan.Summary{Hosts: 4, Interceptable: 1, Inconclusive: 2, Passthrough: 1}); err != nil {
		t.Fatalf("printTally: %v", err)
	}
	want := "4 host(s): 1 interceptable, 1 inconclusive (not verified), 1 passthrough (not tested), 1 hardened"
	if !strings.Contains(out.String(), want) {
		t.Errorf("tally = %q, want %q", out.String(), want)
	}

	out.Reset()
	if err := printTally(&out, scan.Summary{Hosts: 3, Interceptable: 1, Inconclusive: 1}); err != nil {
		t.Fatalf("printTally: %v", err)
	}
	if strings.Contains(out.String(), "passthrough") {
		t.Errorf("tally mentions passthrough with none: %q", out.String())
	}
	if want := "3 host(s): 1 interceptable, 1 inconclusive (not verified), 1 hardened"; !strings.Contains(out.String(), want) {
		t.Errorf("tally = %q, want %q", out.String(), want)
	}
}

func TestBelowConfidence(t *testing.T) {
	t.Parallel()

	results := []scan.HostResult{
		{Host: "a", Confidence: scan.ConfidenceHigh},
		{Host: "b", Confidence: scan.ConfidenceMedium},
		{Host: "c", Confidence: scan.ConfidenceLow},
	}
	if got := belowConfidence(results, scan.ConfidenceHigh, nil); len(got) != 2 {
		t.Errorf("below high = %v, want b and c", got)
	}
	if got := belowConfidence(results, scan.ConfidenceMedium, nil); len(got) != 1 || got[0] != "c" {
		t.Errorf("below medium = %v, want [c]", got)
	}
	if got := belowConfidence(results, scan.ConfidenceLow, nil); len(got) != 0 {
		t.Errorf("below low = %v, want none", got)
	}
}

func TestApplyGatesPolicyIgnoreExemptsCoverageGates(t *testing.T) {
	t.Parallel()

	results := []scan.HostResult{
		{Host: "legacy.example", Verdict: classify.Inconclusive, Confidence: scan.ConfidenceLow},
	}
	pol, err := policy.Load(writePolicy(t, `
hosts:
  legacy.example:
    ignore: true
    reason: deprecated, removed next release
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eval := pol.Evaluate(results)
	opts := scanOptions{failOnInconc: true, minConfidence: scan.ConfidenceHigh}

	// An ignored host is excluded from the inconclusive AND confidence gates.
	if err := applyGates(opts, results, &eval, false); err != nil {
		t.Errorf("ignored host still tripped a coverage gate: %v", err)
	}
	// Control: with no policy, both gates fire.
	if err := applyGates(opts, results, nil, false); err == nil {
		t.Error("expected a coverage-gate failure with no policy exemption")
	}
}

func TestApplyGatesAllowDoesNotExemptInconclusiveGate(t *testing.T) {
	t.Parallel()

	results := []scan.HostResult{
		{Host: "b", Verdict: classify.Inconclusive, Confidence: scan.ConfidenceLow},
	}
	// allow is scoped to the interceptable gate; it must not exempt coverage gates.
	pol, err := policy.Load(writePolicy(t, `
hosts:
  b:
    allow: true
    reason: accepted third-party
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eval := pol.Evaluate(results)
	if err := applyGates(scanOptions{failOnInconc: true}, results, &eval, false); err == nil {
		t.Error("allow must not exempt the inconclusive gate")
	}
}

func TestParseScanArgsAcceptsFlagsEitherSideOfTarget(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"-driver", "manual", "-window", "5s", "com.example.app"},
		{"com.example.app", "-driver", "manual", "-window", "5s"},
		{"-driver", "manual", "com.example.app", "-window", "5s"},
	} {
		opts, err := parseScanArgs(args, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("parseScanArgs(%q) error: %v", args, err)
		}
		if opts.pkg != "com.example.app" {
			t.Errorf("args %q -> pkg %q, want com.example.app", args, opts.pkg)
		}
		if opts.window.String() != "5s" {
			t.Errorf("args %q -> window %v, want 5s", args, opts.window)
		}
	}
}

func TestParseScanArgsRejectsWrongPositionalCount(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"-driver", "manual"},            // zero positionals
		{"com.example.app", "extra.pkg"}, // two positionals
	} {
		if _, err := parseScanArgs(args, &bytes.Buffer{}); err == nil {
			t.Errorf("parseScanArgs(%q) = nil error, want a usage error", args)
		}
	}
}

func TestCaNewWritesLoadableCA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ca.pem") // nested — also exercises MkdirAll
	var stdout, stderr bytes.Buffer
	if err := caNewCommand([]string{"-o", path}, &stdout, &stderr); err != nil {
		t.Fatalf("ca-new: %v (%s)", err, stderr.String())
	}
	if _, err := loadCAFile(path); err != nil {
		t.Fatalf("generated CA does not load back: %v", err)
	}
	if !strings.Contains(stdout.String(), "sha256:") {
		t.Errorf("ca-new output missing the fingerprint: %q", stdout.String())
	}
	// It's a private key — must not be group/other readable.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("CA file mode = %#o, want no group/other access", perm)
	}
	// Refuses to clobber an existing CA without -force.
	if err := caNewCommand([]string{"-o", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Error("ca-new overwrote an existing CA without -force")
	}
	// -force replaces it.
	if err := caNewCommand([]string{"-o", path, "-force"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Errorf("ca-new -force: %v", err)
	}
	// A stray positional (forgetting -o) is rejected, not silently ignored.
	if err := caNewCommand([]string{filepath.Join(dir, "oops.pem")}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Error("ca-new accepted a positional path argument; want a usage error")
	}
}

func TestRunHelpShowsOverviewAndExitsClean(t *testing.T) {
	t.Parallel()

	for _, arg := range []string{"-h", "--help"} {
		var stdout, stderr bytes.Buffer
		if err := run([]string{arg}, &stdout, &stderr); err != nil {
			t.Errorf("run(%q) = %v, want nil (help is a clean exit)", arg, err)
		}
		if !strings.Contains(stderr.String(), "pinscan scan <package>") {
			t.Errorf("run(%q) did not print the command overview: %q", arg, stderr.String())
		}
	}
}

func TestInterceptableCountRespectsPolicyExemptions(t *testing.T) {
	t.Parallel()

	results := []scan.HostResult{
		{Host: "a", Verdict: classify.Open}, // interceptable
		{Host: "b", Verdict: classify.Open}, // interceptable, will be allowed
		{Host: "c", Verdict: classify.SPKI}, // hardened
	}
	// No policy: both open hosts count.
	if n := interceptableCount(results, nil); n != 2 {
		t.Errorf("no-policy interceptable count = %d, want 2", n)
	}
	// Policy allowing b: only a counts.
	pol, err := policy.Load(writePolicy(t, `
hosts:
  b:
    allow: true
    reason: accepted third-party
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eval := pol.Evaluate(results)
	if n := interceptableCount(results, &eval); n != 1 {
		t.Errorf("with policy exempting b, interceptable count = %d, want 1", n)
	}
}

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := t.TempDir() + "/.pinscan.yaml"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestParseScanArgsRejectsBadPolicy(t *testing.T) {
	t.Parallel()

	// A policy with a host missing a reason must fail at parse time (fast fail).
	path := writePolicy(t, "hosts:\n  api.bank:\n    expect: spki\n")
	var stderr bytes.Buffer
	if _, err := parseScanArgs([]string{"-policy", path, "com.example.app"}, &stderr); err == nil {
		t.Error("parseScanArgs with a reason-less policy = nil error, want an error")
	}
}

func TestParseScanArgsRejectsBadConfidence(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	if _, err := parseScanArgs([]string{"-min-confidence", "bogus", "com.example.app"}, &stderr); err == nil {
		t.Error("parseScanArgs with bad -min-confidence = nil error, want an error")
	}
}

func TestReportFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path    string
		want    string
		wantErr bool
	}{
		{"out.json", "json", false},
		{"out.md", "markdown", false},
		{"out.markdown", "markdown", false},
		{"out.html", "html", false},
		{"out.htm", "html", false},
		{"OUT.HTML", "html", false},
		{"/tmp/report.json", "json", false},
		{"out.txt", "", true},
		{"noext", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			got, err := reportFormat(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Errorf("reportFormat(%q) = %q, nil; want an error", tt.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("reportFormat(%q) error: %v", tt.path, err)
			}
			if got != tt.want {
				t.Errorf("reportFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestWriteReportCreatesFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/report.html"
	results := []scan.HostResult{{Host: "secure.example.com", Verdict: classify.Open}}
	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{
		Host: "secure.example.com", Method: "GET", URL: "/x", Status: 200,
		RespBody: []byte(`{"ok":true}`),
	})

	if err := writeReport(path, report.Meta{Package: "com.example.app"}, results, rec); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	out := string(data)
	// html/template escapes the body, so the quotes appear as entities.
	for _, want := range []string{"<!doctype html>", "secure.example.com", "&#34;ok&#34;:true"} {
		if !strings.Contains(out, want) {
			t.Errorf("report HTML missing %q", want)
		}
	}
}

func writeJSONReport(t *testing.T, path string, hosts ...scan.HostResult) {
	t.Helper()
	if err := writeReport(path, report.Meta{Package: "com.example.app", Canonical: true}, hosts, nil); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
}

func TestRunDiffDetectsRegression(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	oldPath := dir + "/old.json"
	newPath := dir + "/new.json"
	writeJSONReport(t, oldPath, scan.HostResult{Host: "api.bank", Verdict: classify.SPKI})
	writeJSONReport(t, newPath, scan.HostResult{Host: "api.bank", Verdict: classify.Open})

	var stdout, stderr bytes.Buffer
	err := run([]string{"diff", oldPath, newPath}, &stdout, &stderr)
	if err == nil {
		t.Fatal("diff with a regression = nil error, want a non-zero exit")
	}
	if code := exitCodeFor(err); code != exitRegression {
		t.Errorf("exit code = %d, want %d (regression)", code, exitRegression)
	}
	if !strings.Contains(stdout.String(), "REGRESSION") {
		t.Errorf("diff output missing REGRESSION line:\n%s", stdout.String())
	}
}

func TestRunDiffCleanWhenUnchanged(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	oldPath := dir + "/old.json"
	newPath := dir + "/new.json"
	writeJSONReport(t, oldPath, scan.HostResult{Host: "api.bank", Verdict: classify.SPKI})
	writeJSONReport(t, newPath, scan.HostResult{Host: "api.bank", Verdict: classify.SPKI})

	var stdout, stderr bytes.Buffer
	if err := run([]string{"diff", oldPath, newPath}, &stdout, &stderr); err != nil {
		t.Fatalf("diff of identical reports returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no change") {
		t.Errorf("diff output = %q, want 'no change'", stdout.String())
	}
}

func TestRunDiffRequiresTwoArgs(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"diff", "only-one.json"}, &stdout, &stderr); err == nil {
		t.Error("diff with one arg = nil error, want a usage error")
	}
}

func TestWriteTranscriptJSONAndHAR(t *testing.T) {
	t.Parallel()

	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{
		Host: "secure.example.com", Method: "GET", URL: "/x", Status: 200,
		RespBody: []byte(`{"ok":true}`),
	})
	dir := t.TempDir()
	for _, ext := range []string{".json", ".har"} {
		path := dir + "/dump" + ext
		if err := writeTranscript(path, report.Meta{Package: "p"}, rec); err != nil {
			t.Fatalf("writeTranscript %s: %v", ext, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", ext, err)
		}
		if !strings.Contains(string(data), "secure.example.com") || !strings.Contains(string(data), "ok") {
			t.Errorf("%s dump missing content:\n%s", ext, data)
		}
	}
}

func TestCaptureOutImpliesCaptureAndValidatesExt(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	opts, err := parseScanArgs([]string{"-capture-out", "dump.har", "com.example.app"}, &stderr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !opts.capture {
		t.Error("-capture-out should imply -capture")
	}
	if opts.captureOut != "dump.har" {
		t.Errorf("captureOut = %q", opts.captureOut)
	}
	if _, err := parseScanArgs([]string{"-capture-out", "dump.txt", "com.example.app"}, &stderr); err == nil {
		t.Error("-capture-out with a .txt extension should be rejected")
	}
}

func TestWriteReportRejectsBadExtension(t *testing.T) {
	t.Parallel()

	err := writeReport(t.TempDir()+"/report.txt", report.Meta{Package: "p"}, nil, nil)
	if err == nil {
		t.Error("writeReport with .txt = nil error, want a format error")
	}
}
