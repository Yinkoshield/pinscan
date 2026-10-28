# Changelog

All notable changes to pinscan are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). The JSON report has its own
`schema_version`, documented in [docs/output.md](docs/output.md).

## [Unreleased]

### Changed

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
