package device

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// suCandidates are the paths Root tries, in order, to obtain a root shell.
// Plain "su" (on PATH) is the common case, but Magisk does not always create
// /system/bin/su: on recent versions the binary may live only inside Magisk's
// own mount -- /debug_ramdisk/su -- which is not on the shell's PATH. Falling
// back avoids reporting an unrooted device when root is in fact available.
var suCandidates = []string{"su", "/debug_ramdisk/su", "/sbin/su", "/system/bin/su"}

// Exec is a [Runner] backed by the adb command-line tool.
type Exec struct {
	path string

	mu sync.Mutex
	su string // resolved su path, cached after the first successful probe
}

// NewExec returns a Runner that invokes the adb binary found on PATH.
func NewExec() *Exec {
	return &Exec{path: "adb"}
}

// Shell runs cmd in a device shell.
func (e *Exec) Shell(ctx context.Context, cmd string) (string, error) {
	return e.run(ctx, "shell", cmd)
}

// Root runs cmd as root via su. The command must not contain a single quote,
// which would break the su -c '...' wrapping.
func (e *Exec) Root(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "'") {
		return "", fmt.Errorf("device: root command contains a single quote: %q", cmd)
	}
	su, err := e.resolveSu(ctx)
	if err != nil {
		return "", err
	}
	return e.run(ctx, "shell", su+" -c '"+cmd+"'")
}

// resolveSu finds a working su, caching the result. It probes each candidate
// with `id` and accepts the first that actually reports uid 0, so a stub su
// that exists but cannot elevate is not mistaken for root.
func (e *Exec) resolveSu(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.su != "" {
		return e.su, nil
	}
	for _, c := range suCandidates {
		out, err := e.run(ctx, "shell", c+" -c id")
		if err == nil && strings.Contains(out, "uid=0") {
			e.su = c
			return c, nil
		}
	}
	return "", fmt.Errorf("device: no working su (tried %s): root the device, and "+
		"grant root to ADB (Magisk: Settings > Superuser > Superuser Access = \"Apps and ADB\")",
		strings.Join(suCandidates, ", "))
}

// State returns the adb connection state.
func (e *Exec) State(ctx context.Context) (string, error) {
	return e.run(ctx, "get-state")
}

func (e *Exec) run(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, e.path, args...).CombinedOutput() //nolint:gosec // adb path is fixed; higher layers validate command arguments.
	if err != nil {
		return string(out), fmt.Errorf("adb %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}
