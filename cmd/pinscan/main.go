// Command pinscan evaluates the TLS-pinning posture of Android apps.
//
// The logic lives in run and its helpers (which take their I/O as parameters)
// so they are testable without a process; main owns the only os.Exit.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yinkoshield/pinscan/internal/baseline"
	"github.com/yinkoshield/pinscan/internal/camodule"
	"github.com/yinkoshield/pinscan/internal/capture"
	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/device"
	"github.com/yinkoshield/pinscan/internal/hostmatch"
	"github.com/yinkoshield/pinscan/internal/policy"
	"github.com/yinkoshield/pinscan/internal/proxy"
	"github.com/yinkoshield/pinscan/internal/report"
	"github.com/yinkoshield/pinscan/internal/scan"
	"github.com/yinkoshield/pinscan/internal/selftest"
	"github.com/yinkoshield/pinscan/internal/target"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// Exit codes, so a CI pipeline can tell a broken tool from a policy breach.
const (
	exitUsage       = 1 // Usage or CLI error.
	exitOperational = 2 // The scan could not complete (device/adb/CA/proxy).
	exitPolicy      = 3 // A policy violation: an interceptable host.
	exitRegression  = 4 // A regression against a baseline.
	exitIncomplete  = 5 // Incomplete coverage: inconclusive hosts (opt-in).
)

// codedError carries an exit code alongside an error.
type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// coded wraps err with an exit code. A nil err returns nil.
func coded(code int, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}

// exitCodeFor returns the exit code an error carries, defaulting to usage.
func exitCodeFor(err error) int {
	var ce *codedError
	if errors.As(err, &ce) {
		return ce.code
	}
	return exitUsage
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "pinscan:", err)
		os.Exit(exitCodeFor(err))
	}
}

// run dispatches the top-level command, or handles the bare / flag-only form.
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return dispatch(args[0], args[1:], stdout, stderr)
	}
	return runTopLevel(args, stdout, stderr)
}

// dispatch routes a subcommand to its handler.
func dispatch(cmd string, args []string, stdout, stderr io.Writer) error {
	switch cmd {
	case "scan":
		return scanCommand(args, stdout, stderr)
	case "baseline":
		return baselineCommand(args, stdout, stderr)
	case "diff":
		return diffCommand(args, stdout)
	case "schema":
		_, err := stdout.Write(report.Schema())
		return err
	case "doctor":
		return doctorCommand(args, stdout, stderr)
	case "ca-new":
		return caNewCommand(args, stdout, stderr)
	case "ca-module":
		return caModuleCommand(args, stdout, stderr)
	case "selftest":
		return selftestCommand(stdout)
	default:
		return coded(exitUsage, fmt.Errorf("unknown command %q", cmd))
	}
}

// runTopLevel handles the no-subcommand form: -version, -h/--help, or usage.
func runTopLevel(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pinscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _ = printUsage(stderr) }
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // -h/--help: the overview was already printed.
		}
		return fmt.Errorf("parse flags: %w", err)
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, "pinscan", version)
		return err
	}
	return printUsage(stderr)
}

func printUsage(w io.Writer) error {
	_, err := fmt.Fprint(w, "pinscan - SSL-pinning posture scanner\n\n"+
		"usage:\n"+
		"  pinscan scan <package> [flags]\n"+
		"  pinscan baseline <package> [-o file.json] [flags]\n"+
		"  pinscan diff <baseline.json> <current.json>\n"+
		"  pinscan doctor [package]\n"+
		"  pinscan ca-new [-o file.pem]\n"+
		"  pinscan ca-module [-ca file.pem] [-o dir]\n"+
		"  pinscan schema\n"+
		"  pinscan selftest\n"+
		"  pinscan -version\n")
	return err
}

// selftestCommand runs the device-free methodology self-test and prints a line
// per posture, returning an error (non-zero exit) if any posture misclassifies.
func selftestCommand(stdout io.Writer) error {
	cases, err := selftest.Run(context.Background())
	if err != nil {
		return err
	}
	failed := 0
	for _, c := range cases {
		status := "ok"
		if !c.Pass {
			status = "FAIL"
			failed++
		}
		if _, err := fmt.Fprintf(stdout, "%-20s want=%-16s got=%-16s %-4s reason=%s\n",
			c.Posture, c.Want, c.Got, status, c.Reason); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("selftest: %d of %d postures failed", failed, len(cases))
	}
	_, err = fmt.Fprintf(stdout, "\nselftest passed: %d/%d postures classified correctly\n", len(cases), len(cases))
	return err
}

// caNewCommand generates a fresh research CA (certificate + private key) and
// writes it as a PEM bundle, so pinscan needs no external tool to create one.
func caNewCommand(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pinscan ca-new", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", defaultCAPath(), "output path for the CA PEM (certificate + private key)")
	cn := fs.String("cn", "pinscan research CA", "certificate common name")
	force := fs.Bool("force", false, "overwrite an existing CA file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return coded(exitUsage, fmt.Errorf("parse flags: %w", err))
	}
	if fs.NArg() != 0 {
		return coded(exitUsage, fmt.Errorf("ca-new takes no positional arguments; set the output path with -o"))
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return coded(exitUsage, fmt.Errorf(
			"%q already exists; use -force to replace it (replacing invalidates any device already trusting the old CA)", *out))
	}
	ca, err := certmint.NewCA(*cn)
	if err != nil {
		return coded(exitOperational, fmt.Errorf("generate CA: %w", err))
	}
	pemBytes, err := ca.EncodePEM()
	if err != nil {
		return coded(exitOperational, err)
	}
	if dir := filepath.Dir(*out); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return coded(exitOperational, fmt.Errorf("create %q: %w", dir, err))
		}
	}
	if err := os.WriteFile(*out, pemBytes, 0o600); err != nil {
		return coded(exitOperational, fmt.Errorf("write CA %q: %w", *out, err))
	}
	// WriteFile only sets the mode when creating; force 0600 so a -force overwrite
	// of a pre-existing (looser) file still protects the private key.
	if err := os.Chmod(*out, 0o600); err != nil {
		return coded(exitOperational, fmt.Errorf("chmod CA %q: %w", *out, err))
	}
	sum := sha256.Sum256(ca.Cert().Raw)
	_, err = fmt.Fprintf(stdout,
		"wrote research CA to %s\n  subject: %s\n  sha256:  %s\n\n"+
			"It is the default -ca for every command. Trust it on a device with `pinscan ca-module`.\n",
		*out, ca.Cert().Subject, hex.EncodeToString(sum[:]))
	return err
}

// caModuleCommand writes an open Magisk module that trusts the research CA
// system-wide, so an operator can use scoped/system mode without any compiled
// or proprietary component.
func caModuleCommand(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pinscan ca-module", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caPath := fs.String("ca", defaultCAPath(), "research CA PEM to embed")
	out := fs.String("o", "pinscan-ca", "output module directory")
	id := fs.String("id", "pinscan-ca", "Magisk module id")
	name := fs.String("name", "pinscan research CA (system trust)", "Magisk module name")
	if err := fs.Parse(args); err != nil {
		return coded(exitUsage, fmt.Errorf("parse flags: %w", err))
	}
	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		return coded(exitOperational, fmt.Errorf("read CA %q: %w", *caPath, err))
	}
	files, err := camodule.Generate(caPEM, *id, *name)
	if err != nil {
		return coded(exitUsage, err)
	}
	for _, f := range files {
		p := filepath.Join(*out, f.Path)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return coded(exitOperational, fmt.Errorf("create %q: %w", p, err))
		}
		mode := os.FileMode(0o644)
		if f.Executable {
			mode = 0o755
		}
		if err := os.WriteFile(p, f.Content, mode); err != nil {
			return coded(exitOperational, fmt.Errorf("write %q: %w", p, err))
		}
	}
	_, err = fmt.Fprintf(stdout,
		"wrote open Magisk module to %s/\n\n"+
			"Install on a rooted device, then reboot:\n"+
			"  adb push %s /data/local/tmp/%s\n"+
			"  adb shell su -c 'rm -rf /data/adb/modules/%s'\n"+
			"  adb shell su -c 'cp -r /data/local/tmp/%s /data/adb/modules/%s'\n"+
			"  adb shell su -c 'chmod 755 /data/adb/modules/%s/post-fs-data.sh /data/adb/modules/%s/service.sh'\n"+
			"  adb reboot\n\n"+
			"(separate su commands: a chained `su -c '... && ...'` is mangled by adb)\n\n"+
			"Then verify:  pinscan doctor <package>   (scan with -mode system)\n"+
			"The module records its own result in /data/local/tmp/pinscan-ca.log on the device.\n",
		*out, *out, *id, *id, *id, *id, *id, *id)
	return err
}

// doctorCommand checks the host and device prerequisites for a scan WITHOUT
// running one, printing a checklist, so an operator can verify their setup
// (especially on a phone) before scanning. An optional package argument adds a
// target-app-installed check.
func doctorCommand(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pinscan doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "scoped", "CA trust mode to check: scoped or system")
	caPath := fs.String("ca", defaultCAPath(), "research CA PEM bundle (cert+key) to validate")
	if err := fs.Parse(args); err != nil {
		return coded(exitUsage, fmt.Errorf("parse flags: %w", err))
	}
	if fs.NArg() > 1 {
		return coded(exitUsage, errors.New("usage: pinscan doctor [package] [flags]"))
	}
	m, err := parseMode(*mode)
	if err != nil {
		return coded(exitUsage, err)
	}

	ctrl := device.New(device.NewExec(), m)
	// Give the controller the CA's trust-store filename so the system-mode
	// check can verify that apps actually trust it, rather than assume so.
	if ca, err := loadCAFile(*caPath); err == nil {
		ctrl.SetCA(caIdentity(ca))
	}
	checks := append(hostChecks(*caPath), ctrl.Diagnostics(context.Background(), fs.Arg(0))...)
	failed := printChecks(stdout, checks)
	if failed > 0 {
		return coded(exitOperational, fmt.Errorf("%d required prerequisite(s) not met", failed))
	}
	_, err = fmt.Fprintln(stdout, "\nall required prerequisites met")
	return err
}

// hostChecks probes the prerequisites that live on the host, not the device.
func hostChecks(caPath string) []device.Check {
	adb := device.Check{Name: "adb on PATH", Required: true, Detail: "adb", Hint: "install Android platform-tools and ensure adb is on PATH"}
	if path, err := exec.LookPath("adb"); err == nil {
		adb.OK = true
		adb.Detail = path
	}

	ca := device.Check{
		Name:     "research CA readable",
		Required: true,
		Detail:   caPath,
		Hint:     "generate one with `pinscan ca-new`, or point -ca at an existing CA PEM (certificate + private key)",
	}
	if _, err := loadCAFile(caPath); err != nil {
		ca.Detail = caPath + " — " + err.Error()
	} else {
		ca.OK = true
	}
	return []device.Check{adb, ca}
}

// printChecks writes a checklist and returns the number of failing required
// checks. A failing optional check prints as a warning, not a failure.
func printChecks(w io.Writer, checks []device.Check) int {
	failed := 0
	for _, c := range checks {
		mark := "[ ok ]"
		if !c.OK {
			if c.Required {
				mark = "[FAIL]"
				failed++
			} else {
				mark = "[warn]"
			}
		}
		line := fmt.Sprintf("%s %-32s %s", mark, c.Name, c.Detail)
		if !c.OK && c.Hint != "" {
			line += "\n         ↳ " + c.Hint
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return failed
		}
	}
	return failed
}

// baselineCommand runs a scan and writes a canonical (deterministic, no-capture)
// JSON baseline that CI commits and future scans diff against.
func baselineCommand(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pinscan baseline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "", "baseline output path (.json); defaults to <package>.baseline.json")
	// Reuse the scan flags so a baseline is produced under the same parameters.
	opts, err := parseScanArgsInto(fs, args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // -h: the flag usage was already printed.
		}
		return coded(exitUsage, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	results, meta, _, err := executeScan(ctx, opts, stderr)
	if err != nil {
		return err
	}
	meta.Canonical = true
	path := *out
	if path == "" {
		path = opts.pkg + ".baseline.json"
	}
	if _, err := reportFormat(path); err != nil {
		return coded(exitUsage, err)
	}
	if err := writeReport(path, meta, results, nil); err != nil {
		return coded(exitOperational, err)
	}
	_, err = fmt.Fprintf(stdout, "baseline written: %s (%d hosts)\n", path, len(results))
	return err
}

// diffCommand compares two report JSON files and exits non-zero on a regression.
func diffCommand(args []string, stdout io.Writer) error {
	if len(args) != 2 {
		return coded(exitUsage, errors.New("usage: pinscan diff <baseline.json> <current.json>"))
	}
	old, err := loadReport(args[0])
	if err != nil {
		return coded(exitOperational, err)
	}
	current, err := loadReport(args[1])
	if err != nil {
		return coded(exitOperational, err)
	}
	diff := baseline.Diff(old, current)
	if err := printDiff(stdout, diff); err != nil {
		return err
	}
	if diff.HasRegression() {
		return coded(exitRegression, errors.New("posture regressed against the baseline"))
	}
	return nil
}

// loadReport reads and decodes a report JSON file.
func loadReport(path string) (report.Report, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G703: path is the operator's own CLI argument naming a report file to read.
	if err != nil {
		return report.Report{}, fmt.Errorf("read report %q: %w", path, err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return report.Report{}, fmt.Errorf("parse report %q: %w", path, err)
	}
	return rep, nil
}

// printDiff writes a human-readable summary of a baseline diff.
func printDiff(w io.Writer, d baseline.Result) error {
	if !d.HasRegression() && len(d.NeedsReview) == 0 && len(d.Improvements) == 0 &&
		len(d.Added) == 0 && len(d.Removed) == 0 {
		_, err := fmt.Fprintln(w, "\nbaseline: no change")
		return err
	}
	sections := []struct {
		label   string
		changes []baseline.Change
	}{
		{"REGRESSION", d.Regressions},
		{"needs-review", d.NeedsReview},
		{"improvement", d.Improvements},
		{"added", d.Added},
		{"removed", d.Removed},
	}
	if _, err := fmt.Fprintln(w, "\nbaseline diff:"); err != nil {
		return err
	}
	for _, s := range sections {
		for _, c := range s.changes {
			if err := printChange(w, s.label, c); err != nil {
				return err
			}
		}
	}
	return nil
}

// printChange writes one diff line, showing the transition when there is one.
func printChange(w io.Writer, label string, c baseline.Change) error {
	switch {
	case c.From != "" && c.To != "":
		_, err := fmt.Fprintf(w, "  %-12s %s: %s -> %s\n", label, c.Host, c.From, c.To)
		return err
	case c.To != "":
		_, err := fmt.Fprintf(w, "  %-12s %s: %s\n", label, c.Host, c.To)
		return err
	default:
		_, err := fmt.Fprintf(w, "  %-12s %s: %s\n", label, c.Host, c.From)
		return err
	}
}

type scanOptions struct {
	pkg              string
	driver           string
	mode             device.Mode
	caPath           string
	hostIP           string
	port             int
	window           time.Duration
	logger           *slog.Logger
	failOnInterc     bool
	capture          bool
	captureOut       string
	captureMax       int
	reportPath       string
	explain          bool
	transparent      bool
	failOnInconc     bool
	baselinePath     string
	failOnRegression bool
	minConfidence    scan.Confidence
	pol              *policy.Policy
	// passthrough names the hosts relayed untouched: the -passthrough flags
	// merged with the policy's passthrough rules. Empty when there are none.
	passthrough *hostmatch.Matcher
}

// scanCommand runs a scan and prints each host's verdict.
func scanCommand(args []string, stdout, stderr io.Writer) error {
	opts, err := parseScanArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // -h: the flag usage was already printed.
		}
		return coded(exitUsage, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	results, meta, cfg, err := executeScan(ctx, opts, stderr)
	if err != nil {
		return err
	}
	if err := printResults(stdout, results, opts.explain); err != nil {
		return err
	}
	if err := printTrust(stdout, results, meta.CATrust); err != nil {
		return err
	}
	return finishScan(ctx, cfg, opts, stdout, results, meta)
}

// buildTarget constructs the scan target for the selected driver. The manual
// driver prints its operator instructions to instrOut.
func buildTarget(opts scanOptions, ca *certmint.CA, instrOut io.Writer) (scan.Target, error) {
	switch opts.driver {
	case "manual":
		return target.NewManual(instrOut, opts.pkg, opts.caPath, opts.window, opts.transparent), nil
	case "android":
		ctrl := device.New(device.NewExec(), opts.mode)
		ctrl.SetLogger(opts.logger)
		ctrl.SetCA(caIdentity(ca)) // lets the target verify trust from the app's namespace
		a := target.NewAndroid(ctrl, opts.pkg, opts.transparent)
		a.SetLogger(opts.logger)
		return a, nil
	default:
		return nil, fmt.Errorf("invalid driver %q (want android or manual)", opts.driver)
	}
}

// executeScan prepares the target and runs the waves, returning the results,
// the report metadata, and the live config (for an optional capture pass).
// Failures that stop the scan from completing carry the operational exit code.
func executeScan(ctx context.Context, opts scanOptions, instrOut io.Writer) ([]scan.HostResult, report.Meta, scan.Config, error) {
	ca, err := loadCAFile(opts.caPath)
	if err != nil {
		return nil, report.Meta{}, scan.Config{}, coded(exitOperational, err)
	}
	ip, err := resolveHostIP(opts.hostIP)
	if err != nil {
		return nil, report.Meta{}, scan.Config{}, coded(exitOperational, err)
	}
	tgt, err := buildTarget(opts, ca, instrOut)
	if err != nil {
		return nil, report.Meta{}, scan.Config{}, coded(exitUsage, err)
	}
	if err := tgt.Preflight(ctx); err != nil {
		return nil, report.Meta{}, scan.Config{}, coded(exitOperational, err)
	}

	cfg := scan.Config{
		CA:         ca,
		Target:     tgt,
		Resolver:   proxy.NewResolver(),
		Logger:     opts.logger,
		HostIP:     ip,
		Port:       opts.port,
		Window:     opts.window,
		CaptureMax: opts.captureMax,
	}
	if !opts.passthrough.Empty() {
		cfg.Passthrough = opts.passthrough.Match
		opts.logger.Info("passthrough hosts relayed untouched, not tested", "patterns", opts.passthrough.Patterns())
	}
	if opts.passthrough.MatchesAll() {
		opts.logger.Warn("every host is relayed: this run tests nothing and only lists the hosts the app contacted")
	}
	opts.logger.Info("scan started",
		"target", opts.pkg, "driver", opts.driver, "host", ip, "port", opts.port,
		"mode", opts.mode.String(), "window", opts.window.String())

	startedAt := time.Now()
	results, err := scan.Run(ctx, cfg.WaveFunc())
	if err != nil {
		return nil, report.Meta{}, scan.Config{}, coded(exitOperational, err)
	}
	// A rejection is pinning evidence only if the client trusted the research
	// CA. Where that was not verified, hardened verdicts are withheld.
	trust := scan.TrustOf(tgt)
	results = scan.ApplyTrust(results, trust)
	opts.logger.Info("research CA trust", "status", trust.String())
	return results, reportMeta(opts, caFingerprint(ca), trust, startedAt), cfg, nil
}

// reportMeta builds the report metadata for a scan. Duration is left for the
// caller to stamp just before writing, so it reflects the whole run.
func reportMeta(opts scanOptions, caSHA string, trust scan.TrustStatus, startedAt time.Time) report.Meta {
	return report.Meta{
		ToolVersion: version,
		Package:     opts.pkg,
		Mode:        opts.mode.String(),
		Transparent: opts.transparent,
		Window:      opts.window,
		CASHA256:    caSHA,
		CATrust:     trust.String(),
		StartedAt:   startedAt,
	}
}

// caFingerprint is the SHA-256 of the research CA certificate, for provenance.
func caFingerprint(ca *certmint.CA) string {
	sum := sha256.Sum256(ca.Cert().Raw)
	return hex.EncodeToString(sum[:])
}

// caIdentity returns how an Android trust store names the research CA
// ("<subject_hash_old>.0") and the SHA-256 of its PEM encoding, which is what
// the on-device file holds. Both are needed to verify trust by content.
func caIdentity(ca *certmint.CA) (file, sha string) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert().Raw})
	sum := sha256.Sum256(certPEM)
	return camodule.SubjectHashOld(ca.Cert()) + ".0", hex.EncodeToString(sum[:])
}

// finishScan runs the optional capture pass, writes the optional report,
// compares against an optional baseline, and applies the fail gates. Split out
// of scanCommand to keep each function within the complexity budget.
func finishScan(ctx context.Context, cfg scan.Config, opts scanOptions, stdout io.Writer, results []scan.HostResult, meta report.Meta) error {
	sum := scan.Summarize(results)
	opts.logger.Info("scan finished",
		"hosts", sum.Hosts, "interceptable", sum.Interceptable, "inconclusive", sum.Inconclusive,
		"passthrough", sum.Passthrough)

	var rec *capture.Recorder
	if opts.capture {
		var err error
		if rec, err = runCapturePass(ctx, cfg, opts.logger, stdout, sum.Interceptable > 0); err != nil {
			return coded(exitOperational, err)
		}
	}

	if opts.captureOut != "" && rec != nil {
		if err := writeTranscript(opts.captureOut, meta, rec); err != nil {
			return coded(exitOperational, err)
		}
		opts.logger.Info("capture dump written", "path", opts.captureOut, "exchanges", len(rec.Exchanges()))
	}

	if opts.reportPath != "" {
		meta.Duration = time.Since(meta.StartedAt)
		if err := writeReport(opts.reportPath, meta, results, rec); err != nil {
			return coded(exitOperational, err)
		}
		opts.logger.Info("report written", "path", opts.reportPath)
	}

	regressed, err := checkBaseline(opts, meta, results, stdout)
	if err != nil {
		return err
	}

	var eval *policy.Evaluation
	if opts.pol != nil {
		e := opts.pol.Evaluate(results)
		if err := printPolicy(stdout, e); err != nil {
			return err
		}
		eval = &e
	}
	return applyGates(opts, results, eval, regressed)
}

// applyGates maps the honest gate outcomes to coded errors. An unmet policy
// expectation or an interceptable host fails the build; a regression fails it; a
// verdict below the required confidence, or an inconclusive host (no signal),
// fails only when the operator opts in but is always surfaced in the tally.
func applyGates(opts scanOptions, results []scan.HostResult, eval *policy.Evaluation, regressed bool) error {
	if regressed && opts.failOnRegression {
		return coded(exitRegression, errors.New("posture regressed against the baseline"))
	}
	if eval != nil && eval.HasViolation() {
		return coded(exitPolicy, fmt.Errorf("%d policy expectation(s) not met", len(eval.Violations)))
	}
	if opts.failOnInterc {
		if n := interceptableCount(results, eval); n > 0 {
			return coded(exitPolicy, fmt.Errorf("%d interceptable host(s) not covered by policy", n))
		}
	}
	if opts.minConfidence != "" {
		if weak := belowConfidence(results, opts.minConfidence, eval); len(weak) > 0 {
			return coded(exitIncomplete, fmt.Errorf("%d host(s) below required confidence %q: %s",
				len(weak), opts.minConfidence, strings.Join(weak, ", ")))
		}
	}
	if opts.failOnInconc {
		if n := inconclusiveCount(results, eval); n > 0 {
			return coded(exitIncomplete, fmt.Errorf("%d inconclusive host(s) found (coverage incomplete)", n))
		}
	}
	return nil
}

// inconclusiveCount counts inconclusive hosts, excluding any the policy excludes
// from gating (ignore). Unlike the interceptable gate, allow does not exempt
// here: allow is scoped to the interceptable gate only.
func inconclusiveCount(results []scan.HostResult, eval *policy.Evaluation) int {
	n := 0
	for _, r := range results {
		if r.Verdict != classify.Inconclusive {
			continue
		}
		if eval != nil && eval.Excluded(r.Host) {
			continue
		}
		n++
	}
	return n
}

// interceptableCount counts interceptable hosts, excluding any the policy
// exempts (allow or ignore).
func interceptableCount(results []scan.HostResult, eval *policy.Evaluation) int {
	n := 0
	for _, r := range results {
		if !r.Verdict.Defeatable() {
			continue
		}
		if eval != nil && eval.Exempt(r.Host) {
			continue
		}
		n++
	}
	return n
}

// printPolicy writes the policy evaluation: violations, accepted risks, ignored
// and unobserved hosts.
func printPolicy(w io.Writer, e policy.Evaluation) error {
	sections := []struct {
		label    string
		findings []policy.Finding
	}{
		{"VIOLATION", e.Violations},
		{"accepted-risk", e.AcceptedRisks},
		{"ignored", e.Ignored},
		{"unobserved", e.Unobserved},
	}
	empty := true
	for _, s := range sections {
		if len(s.findings) > 0 {
			empty = false
		}
	}
	if empty {
		_, err := fmt.Fprintln(w, "\npolicy: all hosts within policy")
		return err
	}
	if _, err := fmt.Fprintln(w, "\npolicy:"); err != nil {
		return err
	}
	for _, s := range sections {
		for _, f := range s.findings {
			if _, err := fmt.Fprintf(w, "  %-14s %s — %s (%s)\n", s.label, f.Host, f.Detail, f.Reason); err != nil {
				return err
			}
		}
	}
	return nil
}

// belowConfidence returns the hosts whose verdict confidence is weaker than
// floor, excluding any the policy excludes from gating (ignore).
func belowConfidence(results []scan.HostResult, floor scan.Confidence, eval *policy.Evaluation) []string {
	var hosts []string
	for _, r := range results {
		if eval != nil && eval.Excluded(r.Host) {
			continue
		}
		if r.Confidence.Below(floor) {
			hosts = append(hosts, r.Host)
		}
	}
	return hosts
}

// checkBaseline diffs the current scan against a baseline file when one is set,
// printing the differences. It reports whether the posture regressed.
func checkBaseline(opts scanOptions, meta report.Meta, results []scan.HostResult, stdout io.Writer) (bool, error) {
	if opts.baselinePath == "" {
		return false, nil
	}
	old, err := loadReport(opts.baselinePath)
	if err != nil {
		return false, coded(exitOperational, err)
	}
	canonical := meta
	canonical.Canonical = true
	current := report.Build(canonical, results, nil)
	diff := baseline.Diff(old, current)
	if err := printDiff(stdout, diff); err != nil {
		return false, err
	}
	return diff.HasRegression(), nil
}

// runCapturePass forwards and records the interceptable hosts' traffic, then
// prints a per-host summary, returning the recorder for the report. It is a
// no-op (bar a log line) when nothing is interceptable, since every handshake
// in the pass would fail.
func runCapturePass(ctx context.Context, cfg scan.Config, logger *slog.Logger, stdout io.Writer, interceptable bool) (*capture.Recorder, error) {
	if !interceptable {
		logger.Info("capture skipped", "reason", "no interceptable hosts")
		return nil, nil
	}
	rec, err := cfg.RunCapture(ctx)
	if err != nil {
		return nil, err
	}
	if err := printCapture(stdout, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// writeTranscript dumps every captured exchange to path, choosing JSON or HAR
// from the path's extension.
func writeTranscript(path string, meta report.Meta, rec *capture.Recorder) error {
	format, ok := report.TranscriptFormat(strings.ToLower(filepath.Ext(path)))
	if !ok {
		return fmt.Errorf("capture-out path %q needs a .json or .har extension", path)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create capture dump %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := report.WriteTranscript(f, format, meta, rec); err != nil {
		return err
	}
	return f.Close()
}

// writeReport builds a report from the scan and writes it to path, choosing the
// format from the path's extension.
func writeReport(path string, meta report.Meta, results []scan.HostResult, rec *capture.Recorder) error {
	format, err := reportFormat(path)
	if err != nil {
		return err
	}
	rep := report.Build(meta, results, rec)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := renderReport(f, format, rep); err != nil {
		return err
	}
	return f.Close()
}

// Report format names, keyed from a path extension by reportFormat.
const (
	fmtJSON     = "json"
	fmtMarkdown = "markdown"
	fmtHTML     = "html"
	fmtSARIF    = "sarif"
	fmtJUnit    = "junit"
)

// renderReport dispatches to the renderer for format.
func renderReport(w io.Writer, format string, rep report.Report) error {
	switch format {
	case fmtJSON:
		return report.JSON(w, rep)
	case fmtMarkdown:
		return report.Markdown(w, rep)
	case fmtHTML:
		return report.HTML(w, rep)
	case fmtSARIF:
		return report.SARIF(w, rep)
	case fmtJUnit:
		return report.JUnit(w, rep)
	default:
		return fmt.Errorf("unknown report format %q", format)
	}
}

// reportFormat maps a report path's extension to a renderer name.
func reportFormat(path string) (string, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return fmtJSON, nil
	case ".md", ".markdown":
		return fmtMarkdown, nil
	case ".sarif":
		return fmtSARIF, nil
	case ".xml", ".junit":
		return fmtJUnit, nil
	case ".html", ".htm":
		return fmtHTML, nil
	default:
		return "", fmt.Errorf("report path %q needs a .json, .md, .html, .sarif or .xml extension", path)
	}
}

func parseScanArgs(args []string, stderr io.Writer) (scanOptions, error) {
	fs := flag.NewFlagSet("pinscan scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	return parseScanArgsInto(fs, args, stderr)
}

// parsePositional parses flags that may appear before OR after the single
// positional argument. Go's flag parser stops at the first non-flag token, so
// this resumes parsing after each positional, letting `scan <pkg> -flag` and
// `scan -flag <pkg>` both work. It returns the sole positional, erroring (with
// flag.ErrHelp preserved for -h) unless exactly one is given.
func parsePositional(fs *flag.FlagSet, args []string) (string, error) {
	var positionals []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return "", err // Includes flag.ErrHelp; callers treat that as clean.
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positionals = append(positionals, rest[0])
		rest = rest[1:]
	}
	if len(positionals) != 1 {
		return "", errors.New("usage: pinscan scan <package> [flags]")
	}
	return positionals[0], nil
}

// parseScanArgsInto registers the scan flags on fs (which a caller may have
// already added its own flags to), parses args, and validates. It is shared by
// the scan and baseline commands.
func parseScanArgsInto(fs *flag.FlagSet, args []string, stderr io.Writer) (scanOptions, error) {
	driver := fs.String("driver", "android", "scan driver: android (adb) or manual (any TLS client you drive)")
	mode := fs.String("mode", "scoped", "CA trust mode (android driver): scoped or system")
	caPath := fs.String("ca", defaultCAPath(), "PEM bundle (cert+key) of the CA to sign with")
	hostIP := fs.String("host-ip", "", "host LAN IP the device reaches (auto-detected if empty)")
	port := fs.Int("port", 8080, "proxy listen port")
	window := fs.Duration("window", 60*time.Second, "scan window per wave")
	logLevel := fs.String("log-level", "info", "log level: error, warn, info, debug")
	logFormat := fs.String("log-format", "text", "log format: text or json")
	debug := fs.Bool("debug", false, "shorthand for -log-level debug")
	failOn := fs.Bool("fail-on-interceptable", false, "exit non-zero if any host is interceptable")
	failOnInc := fs.Bool("fail-on-inconclusive", false, "exit non-zero if any host is inconclusive (coverage incomplete)")
	capt := fs.Bool("capture", false, "forward and record the plaintext exchanges of interceptable hosts")
	captureOut := fs.String("capture-out", "", "dump every captured request/response to this file (.json or .har); implies -capture")
	captureMax := fs.Int("capture-max", 0, "cap each captured body in bytes (default 16384)")
	reportPath := fs.String("report", "", "write a report artifact to this path (.json, .md, .html, .sarif or .xml)")
	baselinePath := fs.String("baseline", "", "compare the scan against this baseline JSON and report regressions")
	failOnReg := fs.Bool("fail-on-regression", false, "exit non-zero if the posture regressed against the baseline")
	minConf := fs.String("min-confidence", "", "require every host's verdict to be at least this confident: low, medium or high")
	policyPath := fs.String("policy", "", "apply a .pinscan.yaml expectation/allowlist file")
	var passthrough stringList
	fs.Var(&passthrough, "passthrough", "relay this host to its real server untouched instead of testing it (repeatable; exact host, *.suffix, or * for every host); it reads inconclusive")
	explain := fs.Bool("explain", false, "print a plain-language pinning-mechanism line under each verdict")
	transparent := fs.Bool("transparent", false, "intercept via a device-side DNAT redirect (for apps that ignore the HTTP proxy)")
	pkg, err := parsePositional(fs, args)
	if err != nil {
		return scanOptions{}, err
	}
	if err := validateDriver(*driver); err != nil {
		return scanOptions{}, err
	}
	m, err := parseMode(*mode)
	if err != nil {
		return scanOptions{}, err
	}
	level := *logLevel
	if *debug {
		level = "debug"
	}
	logger, err := newLogger(level, *logFormat, stderr)
	if err != nil {
		return scanOptions{}, err
	}
	if err := validateReportPath(*reportPath); err != nil {
		return scanOptions{}, err
	}
	minConfidence, err := parseMinConfidence(*minConf)
	if err != nil {
		return scanOptions{}, err
	}
	pol, matcher, err := loadPolicyAndPassthrough(*policyPath, passthrough)
	if err != nil {
		return scanOptions{}, err
	}
	if err := validateCaptureOut(*captureOut); err != nil {
		return scanOptions{}, err
	}
	return scanOptions{
		pkg: pkg, driver: *driver, mode: m, caPath: *caPath, hostIP: *hostIP,
		port: *port, window: *window, logger: logger, failOnInterc: *failOn,
		// -capture-out implies -capture (there must be a recording to dump).
		capture: *capt || *captureOut != "", captureOut: *captureOut, captureMax: *captureMax,
		reportPath: *reportPath, explain: *explain,
		transparent: *transparent, failOnInconc: *failOnInc,
		baselinePath: *baselinePath, failOnRegression: *failOnReg,
		minConfidence: minConfidence, pol: pol, passthrough: matcher,
	}, nil
}

// stringList collects a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// loadPolicyAndPassthrough loads the optional policy and merges its passthrough
// hosts with the -passthrough flags into one matcher, so both sources follow the
// same rule. The bare "*" is accepted as the explicit relay-everything run;
// a malformed wildcard is a usage error.
func loadPolicyAndPassthrough(policyPath string, flags []string) (*policy.Policy, *hostmatch.Matcher, error) {
	pol, err := loadPolicyOpt(policyPath)
	if err != nil {
		return nil, nil, err
	}
	patterns := append([]string(nil), flags...)
	if pol != nil {
		patterns = append(patterns, pol.PassthroughHosts()...)
	}
	matcher, err := hostmatch.New(patterns...)
	if err != nil {
		return nil, nil, fmt.Errorf("passthrough: %w", err)
	}
	return pol, matcher, nil
}

// validateDriver errors on an unknown scan driver.
func validateDriver(d string) error {
	if d != "android" && d != "manual" {
		return fmt.Errorf("invalid driver %q (want android or manual)", d)
	}
	return nil
}

// validateCaptureOut errors if a non-empty capture-out path has an unknown
// extension (.json or .har).
func validateCaptureOut(path string) error {
	if path == "" {
		return nil
	}
	if _, ok := report.TranscriptFormat(strings.ToLower(filepath.Ext(path))); !ok {
		return fmt.Errorf("capture-out path %q needs a .json or .har extension", path)
	}
	return nil
}

// validateReportPath errors if a non-empty report path has an unknown format.
func validateReportPath(path string) error {
	if path == "" {
		return nil
	}
	_, err := reportFormat(path)
	return err
}

// parseMinConfidence resolves the optional -min-confidence flag.
func parseMinConfidence(s string) (scan.Confidence, error) {
	if s == "" {
		return "", nil
	}
	return scan.ParseConfidence(s)
}

// loadPolicyOpt loads the optional -policy file, or returns nil when unset.
func loadPolicyOpt(path string) (*policy.Policy, error) {
	if path == "" {
		return nil, nil
	}
	p, err := policy.Load(path)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func newLogger(level, format string, w io.Writer) (*slog.Logger, error) {
	var lvl slog.Level
	switch level {
	case "error":
		lvl = slog.LevelError
	case "warn":
		lvl = slog.LevelWarn
	case "info":
		lvl = slog.LevelInfo
	case "debug":
		lvl = slog.LevelDebug
	default:
		return nil, fmt.Errorf("invalid log level %q (want error, warn, info or debug)", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid log format %q (want text or json)", format)
	}
}

func parseMode(s string) (device.Mode, error) {
	switch s {
	case "scoped":
		return device.Scoped, nil
	case "system":
		return device.System, nil
	default:
		return 0, fmt.Errorf("invalid mode %q (want scoped or system)", s)
	}
}

func loadCAFile(path string) (*certmint.CA, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA %q: %w", path, err)
	}
	ca, err := certmint.LoadCA(pemBytes, pemBytes)
	if err != nil {
		return nil, fmt.Errorf("load CA %q: %w", path, err)
	}
	return ca, nil
}

func resolveHostIP(flagIP string) (string, error) {
	if flagIP != "" {
		return flagIP, nil
	}
	return scan.LocalIP()
}

func printResults(w io.Writer, results []scan.HostResult, explain bool) error {
	if len(results) == 0 {
		_, err := fmt.Fprintln(w, "no hosts observed")
		return err
	}
	for _, r := range results {
		note := ""
		if r.Verdict.Defeatable() {
			note = "  <- interceptable"
		}
		if _, err := fmt.Fprintf(w, "%-44s %-14s conf=%-6s%s\n",
			r.Host, r.Verdict, r.Confidence, note); err != nil {
			return err
		}
		if err := printResultNotes(w, r, explain); err != nil {
			return err
		}
	}
	return printTally(w, scan.Summarize(results))
}

// printResultNotes prints the indented lines under a host: the plain-language
// explanation when -explain is set, and the caveat when the verdict carries one.
func printResultNotes(w io.Writer, r scan.HostResult, explain bool) error {
	if explain {
		if _, err := fmt.Fprintf(w, "    %s\n", r.Verdict.Explain()); err != nil {
			return err
		}
	}
	if r.Caveat != "" {
		if _, err := fmt.Fprintf(w, "    ! %s\n", r.Caveat); err != nil {
			return err
		}
	}
	return nil
}

// printTrust states how CA trust was established, and how many hardened
// verdicts were withheld because it was not. It is printed after the tally so
// an unverified setup is never read as a clean result.
func printTrust(w io.Writer, results []scan.HostResult, status string) error {
	switch status {
	case scan.TrustVerified.String():
		_, err := fmt.Fprintln(w, "research CA trust: verified from the app's mount namespace")
		return err
	case scan.TrustAsserted.String():
		_, err := fmt.Fprintln(w, "research CA trust: asserted by the operator, not verified by pinscan; hardened verdicts rest on that setup")
		return err
	default:
		withheld := 0
		for _, r := range results {
			if r.Caveat != "" {
				withheld++
			}
		}
		_, err := fmt.Fprintf(w, "research CA trust: UNVERIFIED; %d hardened verdict(s) withheld as inconclusive (run pinscan doctor)\n", withheld)
		return err
	}
}

// printTally prints the aggregate counts, always surfacing inconclusive hosts so
// an incomplete scan never reads as a clean pass. Passthrough hosts get their
// own bucket, so a relayed host never reads as verified or as hardened.
func printTally(w io.Writer, s scan.Summary) error {
	if s.Passthrough == 0 {
		_, err := fmt.Fprintf(w, "\n%d host(s): %d interceptable, %d inconclusive (not verified), %d hardened\n",
			s.Hosts, s.Interceptable, s.NotVerified(), s.Hardened())
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d host(s): %d interceptable, %d inconclusive (not verified), %d passthrough (not tested), %d hardened\n",
		s.Hosts, s.Interceptable, s.NotVerified(), s.Passthrough, s.Hardened())
	return err
}

// capturePreviewBytes bounds the response-body preview printed per exchange.
const capturePreviewBytes = 2000

// printCapture writes a readable per-host summary of the recorded exchanges.
func printCapture(w io.Writer, rec *capture.Recorder) error {
	exchanges := rec.Exchanges()
	if len(exchanges) == 0 {
		_, err := fmt.Fprintln(w, "\ncapture: no exchanges recorded")
		return err
	}
	byHost := rec.ByHost()
	if _, err := fmt.Fprintf(w, "\ncaptured %d exchange(s) across %d host(s):\n",
		len(exchanges), len(byHost)); err != nil {
		return err
	}
	for _, host := range rec.Hosts() {
		if _, err := fmt.Fprintf(w, "\n== %s ==\n", host); err != nil {
			return err
		}
		for _, ex := range byHost[host] {
			if err := printExchange(w, ex); err != nil {
				return err
			}
		}
	}
	return nil
}

// printExchange writes one request/response line plus a bounded body preview.
func printExchange(w io.Writer, ex capture.Exchange) error {
	if ex.Err != "" {
		_, err := fmt.Fprintf(w, "  %s %s -> error: %s\n", ex.Method, ex.URL, ex.Err)
		return err
	}
	if _, err := fmt.Fprintf(w, "  %s %s -> %d  %s  (%d bytes%s)\n",
		ex.Method, ex.URL, ex.Status, ex.RespHeaders.Get("Content-Type"),
		len(ex.RespBody), truncMark(ex.RespTruncated)); err != nil {
		return err
	}
	if len(ex.RespBody) == 0 {
		return nil
	}
	_, err := fmt.Fprintf(w, "    %s\n", bodyPreview(ex.RespBody, capturePreviewBytes))
	return err
}

// bodyPreview renders up to limit bytes of a body on one indented line, with
// control characters collapsed to spaces so a terminal dump stays readable.
func bodyPreview(body []byte, limit int) string {
	s := string(body)
	truncated := false
	if len(s) > limit {
		s = s[:limit]
		truncated = true
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	if truncated {
		s += " …"
	}
	return s
}

// truncMark annotates a truncated body in the summary.
func truncMark(truncated bool) string {
	if truncated {
		return ", truncated"
	}
	return ""
}

// defaultCAPath is where `pinscan ca-new` writes the research CA and where every
// command looks for it by default. Override with -ca to use any CA PEM.
func defaultCAPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "pinscan-ca.pem"
	}
	return filepath.Join(home, ".pinscan", "ca.pem")
}
