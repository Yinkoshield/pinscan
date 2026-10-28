// Package device drives a connected Android device for a scan over adb:
// preflight checks, the HTTP proxy, launching the target app, and pointing the
// research CA at it. Device I/O goes through the [Runner] interface so the
// control logic is testable without a device.
package device

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// On-device paths for the ykzpinscan Zygisk module.
const (
	moduleDir         = "/data/adb/ykzpinscan"         // Runtime config (targets).
	moduleTargetsPath = moduleDir + "/targets"         //
	moduleInstallDir  = "/data/adb/modules/ykzpinscan" // The installed Zygisk module.
)

// packageRE matches a valid Android package name. Command strings are built by
// concatenation, so the package is validated to keep it injection-free.
var packageRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._]*$`)

// uidRE matches a numeric Linux UID. The UID is interpolated into a root
// command, so it is validated to keep it injection-free.
var uidRE = regexp.MustCompile(`^\d+$`)

// hostRE matches a shell-safe host: an IPv4/IPv6 address or a hostname, using
// only letters, digits, dot, hyphen, and colon (IPv6). The host is interpolated
// into device shell and root (su -c) commands, so it is validated to keep it
// injection-free — this rejects shell metacharacters such as $ ` ; & ( ) space.
var hostRE = regexp.MustCompile(`^[a-zA-Z0-9.:-]+$`)

// Runner runs commands on a connected Android device. The production
// implementation shells out to adb; tests supply a fake.
type Runner interface {
	// Shell runs cmd in a device shell and returns its combined output.
	Shell(ctx context.Context, cmd string) (string, error)
	// Root runs cmd as root (su -c) and returns its combined output.
	Root(ctx context.Context, cmd string) (string, error)
	// State returns the adb connection state, e.g. "device".
	State(ctx context.Context) (string, error)
}

// Mode selects how the research CA is trusted on the device.
type Mode uint8

const (
	// Scoped trusts the CA per app via the ykzpinscan Zygisk module.
	Scoped Mode = iota
	// System trusts the CA system-wide via a root-shell trust-store bind.
	System
)

// String implements [fmt.Stringer].
func (m Mode) String() string {
	switch m {
	case Scoped:
		return "scoped"
	case System:
		return "system"
	default:
		return "invalid"
	}
}

// Controller drives a device for a scan.
type Controller struct {
	runner Runner
	mode   Mode
	caFile string // "<subject_hash_old>.0", when known; enables a real trust check
	caSHA  string // SHA-256 (hex) of the expected certificate PEM
	// ipv6 records whether the last SetRedirect found ip6tables and so installed
	// the IPv6 refusals; ClearRedirect reads it to delete the same rule set.
	ipv6   bool
	logger *slog.Logger
}

// discardLogger drops all records; used when a Controller has no logger.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// SetLogger sets the logger for the controller's warnings, such as a redirect
// rule that could not be removed. Without one they are dropped.
func (c *Controller) SetLogger(logger *slog.Logger) { c.logger = logger }

// log returns the controller's logger, or one that discards when none is set.
func (c *Controller) log() *slog.Logger {
	if c.logger != nil {
		return c.logger
	}
	return discardLogger
}

// SetCA records how to recognize the research CA in a device trust store: its
// filename ("<subject_hash_old>.0") and the SHA-256 of its certificate PEM.
//
// The filename alone is not enough, because subject_hash_old covers only the
// subject: two different CAs sharing a common name collide on the same
// filename, and pinscan's own generated CAs all share one by default. Content
// comparison is what distinguishes "this CA is trusted" from "some CA with the
// same name is". Without this the check reports that it could not verify.
func (c *Controller) SetCA(name, sha256Hex string) { c.caFile, c.caSHA = name, sha256Hex }

// New returns a Controller that drives runner in the given mode.
func New(runner Runner, mode Mode) *Controller {
	return &Controller{runner: runner, mode: mode}
}

// Preflight verifies the device is connected and rooted.
func (c *Controller) Preflight(ctx context.Context) error {
	state, err := c.runner.State(ctx)
	if err != nil {
		return fmt.Errorf("device: adb state: %w", err)
	}
	if got := strings.TrimSpace(state); got != "device" {
		return fmt.Errorf("device: not connected (adb state %q)", got)
	}
	uid, err := c.runner.Root(ctx, "id -u")
	if err != nil {
		return fmt.Errorf("device: root check: %w", err)
	}
	if got := strings.TrimSpace(uid); got != "0" {
		return fmt.Errorf("device: root not available (id -u = %q)", got)
	}
	return nil
}

// SetProxy points the device's global HTTP proxy at hostPort.
func (c *Controller) SetProxy(ctx context.Context, hostPort string) error {
	if err := validateHostPort(hostPort); err != nil {
		return err
	}
	return c.shell(ctx, "settings put global http_proxy "+hostPort)
}

// ClearProxy removes the device's global HTTP proxy.
func (c *Controller) ClearProxy(ctx context.Context) error {
	return c.shell(ctx, "settings put global http_proxy :0")
}

// SetRedirect installs root iptables rules so the TLS traffic (tcp/443) of pkg
// is redirected to hostPort — the transparent-proxy path, for apps that ignore
// the global HTTP proxy. Because the proxy speaks TCP only, it also refuses
// pkg's QUIC (udp/443) and, when the device has ip6tables, its IPv6 port 443,
// so the app falls back to IPv4 TCP and is redirected rather than escaping.
// Every rule is scoped to pkg's UID so other apps are untouched. If a rule
// fails, the ones already installed are removed before the error is returned.
func (c *Controller) SetRedirect(ctx context.Context, pkg, hostPort string) error {
	uid, err := c.redirectSpec(ctx, pkg, hostPort)
	if err != nil {
		return err
	}
	c.ipv6 = c.hasBinary(ctx, "ip6tables")
	if !c.ipv6 {
		c.log().Warn("ipv6 tls not blocked", "reason", "ip6tables not found", "target", pkg)
	}
	rules := redirectRules("-A", uid, hostPort, c.ipv6)
	for i, rule := range rules {
		if _, err := c.runner.Root(ctx, rule); err != nil {
			undo := redirectRules("-D", uid, hostPort, c.ipv6)
			undoCtx := context.WithoutCancel(ctx)
			for j := i - 1; j >= 0; j-- {
				if _, uerr := c.runner.Root(undoCtx, undo[j]); uerr != nil {
					c.log().Warn("redirect rule not removed", "rule", undo[j], "error", uerr)
				}
			}
			return fmt.Errorf("device: set redirect: %w", err)
		}
	}
	return nil
}

// ClearRedirect removes the rules installed by [Controller.SetRedirect], in
// reverse order. It removes the IPv6 refusals only if the last SetRedirect on
// this Controller installed them, so call it on the same Controller. A rule
// that cannot be removed does not stop the rest; all failures are returned.
func (c *Controller) ClearRedirect(ctx context.Context, pkg, hostPort string) error {
	uid, err := c.redirectSpec(ctx, pkg, hostPort)
	if err != nil {
		return err
	}
	rules := redirectRules("-D", uid, hostPort, c.ipv6)
	var errs []error
	for i := len(rules) - 1; i >= 0; i-- {
		if _, err := c.runner.Root(ctx, rules[i]); err != nil {
			c.log().Warn("redirect rule not removed", "rule", rules[i], "error", err)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("device: clear redirect: %w", errors.Join(errs...))
	}
	return nil
}

// redirectSpec validates the inputs and resolves pkg's UID for a redirect rule.
func (c *Controller) redirectSpec(ctx context.Context, pkg, hostPort string) (string, error) {
	if err := validatePackage(pkg); err != nil {
		return "", err
	}
	if err := validateHostPort(hostPort); err != nil {
		return "", err
	}
	return c.appUID(ctx, pkg)
}

// appUID returns pkg's Linux UID by stat-ing its data directory (root).
func (c *Controller) appUID(ctx context.Context, pkg string) (string, error) {
	out, err := c.runner.Root(ctx, "stat -c %u /data/data/"+pkg)
	if err != nil {
		return "", fmt.Errorf("device: app uid: %w", err)
	}
	uid := strings.TrimSpace(out)
	if !uidRE.MatchString(uid) {
		return "", fmt.Errorf("device: unexpected uid %q for %q", uid, pkg)
	}
	return uid, nil
}

// redirectRules builds the iptables commands for a transparent redirect, in
// install order: the IPv4 DNAT, the IPv4 QUIC refusal and, with ipv6, the IPv6
// TCP and QUIC refusals. The action is "-A" to add or "-D" to delete; adding
// inserts the refusals at the top of OUTPUT (-I) so they take effect ahead of
// the system's own chains. Add and delete build otherwise identical rules,
// which iptables needs for a clean teardown. The caller has already validated
// hostPort.
func redirectRules(action, uid, hostPort string, ipv6 bool) []string {
	host, port, _ := net.SplitHostPort(hostPort)
	rejectAction := action
	if action == "-A" {
		rejectAction = "-I"
	}
	rules := []string{
		fmt.Sprintf(
			"iptables -t nat %s OUTPUT -p tcp --dport 443 -m owner --uid-owner %s -j DNAT --to-destination %s:%s",
			action, uid, host, port),
		fmt.Sprintf("iptables %s OUTPUT -p udp --dport 443 -m owner --uid-owner %s -j REJECT", rejectAction, uid),
	}
	if ipv6 {
		rules = append(rules,
			fmt.Sprintf("ip6tables %s OUTPUT -p tcp --dport 443 -m owner --uid-owner %s -j REJECT", rejectAction, uid),
			fmt.Sprintf("ip6tables %s OUTPUT -p udp --dport 443 -m owner --uid-owner %s -j REJECT", rejectAction, uid))
	}
	return rules
}

// ForceStop stops pkg.
func (c *Controller) ForceStop(ctx context.Context, pkg string) error {
	if err := validatePackage(pkg); err != nil {
		return err
	}
	return c.shell(ctx, "am force-stop "+pkg)
}

// Launch starts pkg's launcher activity.
func (c *Controller) Launch(ctx context.Context, pkg string) error {
	if err := validatePackage(pkg); err != nil {
		return err
	}
	return c.shell(ctx, "monkey -p "+pkg+" -c android.intent.category.LAUNCHER 1")
}

// Target points the research CA at pkg. In Scoped mode it writes the module's
// target file; in System mode the CA is already trusted system-wide, so this is
// a no-op.
func (c *Controller) Target(ctx context.Context, pkg string) error {
	if err := validatePackage(pkg); err != nil {
		return err
	}
	if c.mode == System {
		return nil
	}
	cmd := fmt.Sprintf("mkdir -p %s && echo %s > %s && chmod 600 %s",
		moduleDir, pkg, moduleTargetsPath, moduleTargetsPath)
	if _, err := c.runner.Root(ctx, cmd); err != nil {
		return fmt.Errorf("device: set target: %w", err)
	}
	return nil
}

// Check is one prerequisite probe result for the doctor command.
type Check struct {
	Name     string // Short name of what was checked.
	OK       bool   // Whether the prerequisite is satisfied.
	Detail   string // What was observed.
	Hint     string // How to fix it when not OK.
	Required bool   // Whether a scan cannot proceed without it.
}

// Diagnostics probes the device-side prerequisites for a scan and returns a
// check per prerequisite, so an operator can verify their setup before running.
// An empty pkg skips the target-app check.
func (c *Controller) Diagnostics(ctx context.Context, pkg string) []Check {
	checks := []Check{c.checkConnected(ctx), c.checkRoot(ctx), c.checkCATrust(ctx)}
	if pkg != "" {
		checks = append(checks, c.checkPackage(ctx, pkg))
	}
	checks = append(checks, c.checkBinary(ctx, "iptables",
		"needed only for -transparent; most rooted ROMs ship it", false))
	checks = append(checks, c.checkBinary(ctx, "ip6tables",
		"optional for -transparent; without it the app's IPv6 TLS is not blocked", false))
	return checks
}

// checkConnected verifies adb reports a connected device.
func (c *Controller) checkConnected(ctx context.Context) Check {
	state, err := c.runner.State(ctx)
	got := strings.TrimSpace(state)
	return Check{
		Name:     "device connected",
		OK:       err == nil && got == "device",
		Detail:   "adb state: " + describe(got, err),
		Hint:     "connect the device over USB, enable USB debugging, and authorize this host (adb devices)",
		Required: true,
	}
}

// checkRoot verifies root is available (the CA injection needs it).
func (c *Controller) checkRoot(ctx context.Context) Check {
	out, err := c.runner.Root(ctx, "id -u")
	got := strings.TrimSpace(out)
	return Check{
		Name:     "root (su)",
		OK:       err == nil && got == "0",
		Detail:   "id -u: " + describe(got, err),
		Hint:     "root the device (e.g. Magisk); pinscan needs root to make the research CA trusted",
		Required: true,
	}
}

// trustStorePaths are the trust stores an app may read: the Conscrypt APEX
// (Android 14+) and the legacy system store (Android <= 13).
const (
	apexTrustStore   = "/apex/com.android.conscrypt/cacerts"
	legacyTrustStore = "/system/etc/security/cacerts"
)

// checkCATrust verifies the mode's CA-trust mechanism is in place.
func (c *Controller) checkCATrust(ctx context.Context) Check {
	if c.mode == System {
		return c.checkSystemCATrust(ctx)
	}
	present := c.pathPresent(ctx, moduleInstallDir)
	return Check{
		Name:     "ykzpinscan module (scoped CA)",
		OK:       present,
		Detail:   moduleInstallDir,
		Hint:     "build and install the ykzpinscan Zygisk module from android/ykzpinscan/ (see its README), then reboot",
		Required: true,
	}
}

// checkSystemCATrust verifies the research CA is actually trusted, from the
// namespace that decides it. A mount in the global namespace does not reach
// apps: each is forked from zygote, which holds its own mount namespace, so a
// CA visible to the shell can still be invisible to the app under test. That
// mismatch is silent -- every host simply reads inconclusive -- which is why
// this is measured rather than assumed.
//
// It compares the certificate's content, not just its filename: trust-store
// names derive from the subject alone, so a different CA with the same common
// name occupies the same name and would otherwise read as trusted.
func (c *Controller) checkSystemCATrust(ctx context.Context) Check {
	const name = "system CA trust (system mode)"
	if c.caFile == "" || c.caSHA == "" {
		return Check{
			Name:     name,
			OK:       false,
			Detail:   "could not identify the research CA, so trust was not verified",
			Hint:     "pass -ca pointing at the research CA used for the scan",
			Required: false,
		}
	}
	apex := apexTrustStore + "/" + c.caFile
	legacy := legacyTrustStore + "/" + c.caFile
	// Count the zygote namespaces holding a byte-identical certificate. Single
	// quotes would break the su -c wrapping, so this uses double quotes only.
	cmd := fmt.Sprintf(`zs=$(pidof zygote64 zygote 2>/dev/null); n=0; t=0; `+
		`for p in $zs; do n=$((n+1)); `+
		`h=$(nsenter --mount=/proc/$p/ns/mnt -- sh -c "sha256sum %s 2>/dev/null || sha256sum %s 2>/dev/null" | cut -d" " -f1); `+
		`if [ "$h" = "%s" ]; then t=$((t+1)); fi; `+
		`done; `+
		`if [ "$n" = "0" ]; then h=$(sha256sum %s 2>/dev/null || sha256sum %s 2>/dev/null | cut -d" " -f1); `+
		`if [ "$h" = "%s" ]; then echo 1/1; else echo 0/1; fi; `+
		`else echo $t/$n; fi`,
		apex, legacy, c.caSHA, apex, legacy, c.caSHA)
	out, err := c.runner.Root(ctx, cmd)
	got := strings.TrimSpace(out)
	if err != nil {
		return Check{
			Name:     name,
			OK:       false,
			Detail:   "trust check failed: " + describe(got, err),
			Hint:     "ensure root is available so the trust store can be inspected",
			Required: false,
		}
	}
	trusted, total, ok := parseRatio(got)
	switch {
	case !ok:
		return Check{
			Name:     name,
			OK:       false,
			Detail:   "unexpected trust-check output: " + got,
			Hint:     "inspect " + apex + " on the device",
			Required: false,
		}
	case trusted > 0 && trusted == total:
		return Check{
			Name:     name,
			OK:       true,
			Detail:   fmt.Sprintf("%s trusted in %d/%d zygote namespace(s)", c.caFile, trusted, total),
			Required: false,
		}
	default:
		return Check{
			Name: name,
			OK:   false,
			Detail: fmt.Sprintf("this research CA is trusted in only %d/%d zygote namespace(s): apps will not trust it",
				trusted, total),
			Hint: "install the CA module (pinscan ca-module) and reboot; check " +
				"/data/local/tmp/pinscan-ca.log on the device for its result",
			Required: false,
		}
	}
}

// parseRatio parses "t/n" as produced by the system-trust probe.
func parseRatio(s string) (trusted, total int, ok bool) {
	num, den, found := strings.Cut(s, "/")
	if !found {
		return 0, 0, false
	}
	t, err1 := strconv.Atoi(strings.TrimSpace(num))
	n, err2 := strconv.Atoi(strings.TrimSpace(den))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return t, n, true
}

// checkPackage verifies the target app is installed.
func (c *Controller) checkPackage(ctx context.Context, pkg string) Check {
	ok := false
	detail := "invalid package name"
	if validatePackage(pkg) == nil {
		detail = pkg
		out, err := c.runner.Shell(ctx, "pm path "+pkg)
		ok = err == nil && strings.Contains(out, "package:")
	}
	return Check{
		Name:     "target app installed",
		OK:       ok,
		Detail:   detail,
		Hint:     "install the app you want to scan on the device",
		Required: true,
	}
}

// checkBinary verifies a device binary is present on PATH.
func (c *Controller) checkBinary(ctx context.Context, name, hint string, required bool) Check {
	return Check{
		Name:     name,
		OK:       c.hasBinary(ctx, name),
		Detail:   name,
		Hint:     hint,
		Required: required,
	}
}

// hasBinary reports whether name resolves on the device PATH.
func (c *Controller) hasBinary(ctx context.Context, name string) bool {
	out, err := c.runner.Root(ctx, "command -v "+name+" >/dev/null 2>&1 && echo PRESENT || echo ABSENT")
	return err == nil && strings.Contains(out, "PRESENT")
}

// pathPresent reports whether an absolute path exists on the device. An empty
// path is never present.
func (c *Controller) pathPresent(ctx context.Context, path string) bool {
	if path == "" {
		return false
	}
	out, err := c.runner.Root(ctx, "[ -e "+path+" ] && echo PRESENT || echo ABSENT")
	return err == nil && strings.Contains(out, "PRESENT")
}

// describe renders an observed value or the error behind its absence.
func describe(got string, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	if got == "" {
		return "(empty)"
	}
	return got
}

func (c *Controller) shell(ctx context.Context, cmd string) error {
	if _, err := c.runner.Shell(ctx, cmd); err != nil {
		return fmt.Errorf("device: %q: %w", cmd, err)
	}
	return nil
}

func validatePackage(pkg string) error {
	if !packageRE.MatchString(pkg) {
		return fmt.Errorf("device: invalid package name %q", pkg)
	}
	return nil
}

func validateHostPort(hostPort string) error {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return fmt.Errorf("device: invalid host:port %q: %w", hostPort, err)
	}
	if host == "" {
		return fmt.Errorf("device: empty host in %q", hostPort)
	}
	if !hostRE.MatchString(host) {
		return fmt.Errorf("device: invalid host %q (shell-unsafe characters)", host)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("device: invalid port in %q", hostPort)
	}
	return nil
}
