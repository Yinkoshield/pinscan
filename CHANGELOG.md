# Changelog

All notable changes to pinscan are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). The JSON report has its own
`schema_version`, documented in [docs/output.md](docs/output.md).

## [Unreleased]

### Fixed

- **`key-pinned` is no longer reported as hardened.** The classifier defines
  `key-pinned` as "rejected the forged leaves, but the cloned-issuer wave did
  not separate a key check from name validation", yet the tally counted it as
  hardened, the Markdown and HTML tables printed "no" under Interceptable,
  JUnit passed it and SARIF filed it as an informational note. A safety claim
  was being asserted from a wave that returned no signal. Now: the tally has
  an "undetermined (key-pinned)" bucket and "hardened" counts `spki` only,
  computed directly rather than as a remainder; the text output marks the row
  `<- not established`; the JSON report gains a three-valued per-host
  `interceptability` (`yes`, `no`, `not-established`; schema 1.3.0, additive)
  that the Markdown and HTML tables print, with the boolean `interceptable`
  deprecated and kept for one minor version; JUnit skips a key-pinned host
  with the mechanism as the reason and SARIF files it as a warning;
  `inconclusive` likewise reads "not established" instead of "no". The README
  and methodology tables say the same. `-min-confidence high` or a policy
  `expect: spki` makes CI refuse to pass on a key-pinned host; the default
  gates are unchanged.
- The README said `pinscan selftest` runs five postures; it runs six. A test
  now pins the count to the README sentence.

### Added

- **Per-host passthrough.** `-passthrough <host>` (repeatable, `*.suffix`
  wildcards allowed, on `scan` and `baseline`) and `passthrough: true` in
  `.pinscan.yaml` name hosts the proxy relays to their real server byte for
  byte, with no forged certificate, so an app whose login API is key-pinned
  can log in and expose whether its other hosts are checked properly. In
  transparent mode the host is read from the raw ClientHello's SNI before the
  handshake. A passthrough host is not tested and never looks tested: it reads
  `inconclusive` with reason `passthrough` (`passthrough_dial_failed` when the
  real server is unreachable) and the caveat "passthrough: relayed to the real
  server, not tested"; the tally shows "N passthrough (not tested)"; the JSON
  report gains `summary.passthrough` and per-host `passthrough` and `caveat`
  (schema 1.2.0, additive); SARIF emits no result for it and JUnit a skipped
  case with the caveat. It still trips `-fail-on-inconclusive` unless the
  policy also says `ignore: true`, and a baselined verdict that turns
  passthrough is needs-review. The bare `*` relays every host: a discovery
  run that tests nothing but lists every host the app contacted, for apps
  whose first connection is pinned so tightly that no wave sees a request; it
  logs a warning at start. A malformed wildcard, or `expect` together with
  `passthrough`, is refused at load time. `pinscan selftest` has
  a sixth posture, a key-pinning client on the passthrough list, asserted to
  read `inconclusive` with reason `passthrough`, and prints each posture's
  generic-wave reason.

- **Research-CA trust is verified before a rejection counts as pinning.** On
  Android, `scan` now compares the trust-store file by SHA-256 from inside the
  zygote mount namespaces (system mode, before the waves) or the app's own
  process namespace (scoped mode, after each launch). An absent CA stops the
  scan with exit `2` and a fix. When trust cannot be checked, `spki` and
  `key-pinned` are withheld as `inconclusive` with their per-wave evidence
  kept, and the text output says how many were withheld. The manual driver
  records trust as `operator-asserted`. Reports carry `scan.ca_trust`
  (schema 1.1.0, additive); Markdown and HTML show it in the header.
- `pinscan selftest` has a fifth posture, a client that does not trust the
  research CA, and asserts it reads `inconclusive`, not `spki`.
- **Device-side validation kit.** [docs/validation.md](docs/validation.md)
  states the expected verdict, `ca_trust` and per-wave evidence for each known
  client posture (no pinning, Network Security Config pin sets correct and
  wrong, OkHttp `CertificatePinner`, a custom `TrustManager`, WebView, a
  multi-process app) and for three broken setups (research CA absent, a
  different CA with the same subject, the scoped module not covering the
  process). `android/validation-app/` is a small Gradle app with one product
  flavor per posture, and `scripts/validate-device.sh` runs `doctor`, one scan
  per posture, and compares the results, exiting non-zero on any mismatch.
  Run on Android 14 with Magisk 30.7: every row matched except one that
  records an open finding, a false `spki` in scoped mode for an app whose
  TLS client runs in a second process (`<package>:net`), which the
  `ykzpinscan` module does not bind and the trust probe does not inspect.

### Changed

- Docs: `docs/android.md` and `docs/troubleshooting.md` now say that the
  default proxy mode is device-global, so an app scanned earlier and still
  running sends its traffic through pinscan too and, in scoped mode, its hosts
  can read `spki` because it does not trust the research CA; the fix is to
  `am force-stop` it, use `-transparent`, or relay its hosts with
  `-passthrough`.

- Verdict explanations, SARIF rule texts and the docs describe observed
  behaviour rather than a mechanism: `spki` is "rejected every forged chain,
  including the cloned-issuer chain", consistent with public-key pinning or a
  private trust store, mechanism not identified.

- Toolchain: Go 1.26 (the `go` directive is now `1.26.0`; older Go installs
  download it automatically) and golangci-lint v2.15.0 with the configuration
  migrated to the v2 schema. `gosimple` is now part of `staticcheck`, `tenv` is
  replaced by `usetesting`, and `gofumpt`/`goimports` run as formatters. The
  default exclusion that waived missing doc comments is no longer applied. CI
  reads the Go version from `go.mod`.

## [1.0.0] - 2026-10-28

First public release.

### Added

- Three-wave TLS-pinning posture measurement (generic leaf, cloned-metadata
  leaf, cloned-issuer chain) with per-host verdicts `open`, `metadata`,
  `name-validation`, `key-pinned`, `spki` and `inconclusive`.
- The "never secure from silence" rules: acceptance requires an observed request,
  and only a certificate-class TLS alert counts as a rejection.
- A confidence axis (`low`, `medium`, `high`) per verdict and `-min-confidence`.
- Android driver over adb with two CA-trust modes: `system` via a generated,
  readable Magisk module (`pinscan ca-module`) and `scoped` via the `ykzpinscan`
  Zygisk module, source included.
- Transparent mode: UID-scoped iptables redirect of tcp/443, with QUIC and IPv6
  port 443 refused for that UID so the app falls back to TCP over IPv4.
- `manual` driver for any TLS client that can trust the research CA and use a
  proxy.
- Capture pass for interceptable hosts with credential-header redaction, body
  caps, and JSON or HAR dumps.
- Reports in JSON (schema 1.0.0), Markdown, HTML, SARIF 2.1.0 and JUnit.
- Canonical, byte-stable baselines; `diff` and `-fail-on-regression` on the
  strength lattice; `.pinscan.yaml` policy with mandatory reasons.
- Exit codes 0 to 5 separating usage errors, operational failures, policy
  violations, regressions and incomplete coverage.
- `pinscan doctor` prerequisite checks, including CA trust verified from inside
  each zygote mount namespace.
- `pinscan selftest`: a device-free end-to-end proof of the methodology.
- Reproducible builds (`make repro`), goreleaser release pipeline with
  SHA256SUMS and CycloneDX SBOMs.

[Unreleased]: https://github.com/yinkoshield/pinscan/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/yinkoshield/pinscan/releases/tag/v1.0.0
