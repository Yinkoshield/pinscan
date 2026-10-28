# Architecture

For contributors. pinscan is a small CLI over a set of focused, single-purpose
packages. The measurement core is pure and exhaustively tested; side effects
(device, proxy sockets, files) live at the edges behind interfaces.

Package-level documentation is on each package (`go doc ./internal/<pkg>`); this
document is the map and the data flow.

## Packages

```
cmd/pinscan/        CLI: flag parsing, subcommand dispatch, gates, output.
internal/classify/  the wave → verdict methodology. Pure, 100% covered.
internal/certmint/  mints the forged certificates (generic / cloned-metadata / cloned-issuer).
internal/proxy/     CONNECT + transparent TLS proxy; per-SNI cert selection; the
                    accept/reject/ambiguous observer; the capture serve-loop.
internal/capture/   forward-to-upstream + redacted, size-capped, decompressed
                    request/response recorder.
internal/device/    Android control over adb (preflight, proxy/DNAT, launch,
                    scoped-CA targeting, diagnostics).
internal/camodule/  generates the open system-CA Magisk module (ca-module).
internal/target/    scan targets: Android (adb) and Manual (any TLS client),
                    both implementing scan.Target.
internal/scan/      orchestrator: runs waves A→B→(C), classifies, computes
                    confidence; defines the Target interface; summarises.
internal/report/    the versioned JSON contract + Markdown/HTML/SARIF/JUnit
                    renderers + embedded JSON Schema; plus the capture-transcript
                    dump (JSON / HAR) written by -capture-out.
internal/baseline/  report-to-report diff: the regression lattice.
internal/policy/    .pinscan.yaml expectation/allowlist loading + evaluation.
internal/selftest/  device-free end-to-end proof of the methodology.
```

Dependency direction (no cycles): `cmd` → everything; `target` → `device`,
`scan`; `scan` → `classify`, `proxy`, `capture`, `certmint`; `report`,
`baseline` → `scan`/`classify`; `policy` → `classify`, `scan`. The pure core
(`classify`, `certmint`) depends on nothing internal.

## Data flow of a scan

```
cmd.scanCommand
  └─ parseScanArgs ────────────────────── scanOptions (validated: driver, policy, …)
  └─ executeScan
       ├─ loadCAFile ───────────────────── certmint.CA (signs forged certs)
       ├─ buildTarget ──────────────────── scan.Target  (target.Android | target.Manual)
       ├─ Target.Preflight
       └─ scan.Run(ctx, cfg.WaveFunc())
            For each wave A, B, (C if key-pinned):
              proxy.NewServer(CA, wave, resolver.Cert, observer [,WithCapture][,WithTransparent][,WithPassthrough])
                 a passthrough host is relayed to host:443 untouched and recorded Ambiguous/"passthrough"
              serveWhileDriving:
                 listen → Serve(ln) ↑goroutine
                 driveTarget:
                    Target.Route(proxyAddr)   → restore()
                    Target.Exercise           → client makes TLS connections
                    wait(window)
              observer → map[host]WaveObservation{outcome, reason, attempts, conflict}
            classifyAll:
              classify.Classify(per-host A/B/C outcomes) → Verdict
              scan.ConfidenceOf(verdict, waves)          → Confidence
              passthrough reasons                        → Caveat "not tested"
            → []scan.HostResult
  └─ finishScan
       ├─ scan.Summarize
       ├─ [capture pass] cfg.RunCapture → capture.Recorder
       ├─ [report] report.Build(meta, results, rec) → JSON/MD/HTML/SARIF/JUnit
       ├─ [baseline] baseline.Diff(old, current)
       ├─ [policy] policy.Evaluate(results)
       └─ applyGates → coded(exit 3/4/5) | nil
```

## Key design decisions

- **The methodology is a pure function.** `classify.Classify` maps three wave
  outcomes to a verdict with no I/O, so it is exhaustively table-tested and
  auditable. Everything stateful is pushed to the edges.
- **Outcomes are four-valued.** `Accepted / Rejected / Ambiguous / NotObserved`.
  Only a genuine certificate-class rejection is `Rejected`; noise is `Ambiguous`.
  This is what stops "secure from silence" — see [methodology](methodology.md).
- **Passthrough is an edge, not a verdict.** The proxy relays a listed host
  (matched by `internal/hostmatch`, fed from the CLI and the policy) and
  records it `Ambiguous`; the classifier is untouched and yields
  `inconclusive`, so a host that was not tested can never read as hardened.
  In transparent mode the SNI is parsed from the raw ClientHello
  (`internal/proxy/sni.go`) before the handshake, since the standard library
  exposes no parser for a record it has not consumed.
- **`scan.Target` abstracts the client.** The orchestrator never mentions
  Android. Android and Manual are two implementations; a new one (an emulator
  harness, another OS) is just another implementation of
  `Preflight / Transparent / Route / Exercise`.
- **The report is a versioned contract.** `report.Report` has a semver
  `schema_version` and a canonical (deterministic) mode; `baseline` diffs the
  canonical core. Renderers are pure functions of the `Report`.
- **Honesty over coverage theatre.** The device-I/O boundary
  (`scan.runWave`/`RunCapture`, the adb/su exec shims) is the documented
  uncovered edge; it is exercised on a real device, not faked to inflate a
  number. See [ENGINEERING.md](../ENGINEERING.md).

## Adding a new target

Implement `scan.Target` in `internal/target`:

```go
type Target interface {
    Preflight(ctx context.Context) error
    Transparent() bool
    Route(ctx context.Context, proxyAddr string) (restore func(), err error)
    Exercise(ctx context.Context) error
}
```

Then add a `-driver` case in `cmd/pinscan` (`buildTarget`). The waves, classifier,
capture, report and gates need no changes.

## The gate

`make` runs `fmt → lint → test → build`. `make repro` proves the build is
byte-reproducible; `make dist` cross-builds release binaries + `SHA256SUMS`. A
change isn't done until `make` is green. See [ENGINEERING.md](../ENGINEERING.md).
