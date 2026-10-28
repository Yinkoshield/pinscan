# Contributing to pinscan

Thank you for considering a contribution. This document says how to get a
change merged. The engineering bar itself is in [ENGINEERING.md](ENGINEERING.md)
and is not negotiable per pull request; please read it first.

## Ground rules

- pinscan is a posture-evaluation tool for apps and devices you are authorized
  to test. Contributions that turn it into a general interception tool for
  third-party traffic, or that weaken the safeguards listed in
  [SECURITY.md](SECURITY.md), will not be accepted.
- Report security problems privately, as described in
  [SECURITY.md](SECURITY.md), not in an issue or pull request.
- Be direct and courteous in issues and reviews. Disagree with the code, not
  the person.

## Before you start

Open an issue for anything larger than a typo fix or a one-line bug fix, and
say what you intend to change and why. A short discussion first avoids a large
pull request that cannot be merged. Good first contributions:

- a reproducible bug with a failing test attached;
- documentation that was wrong or missing when you followed it;
- a new driver for a client type (see `internal/target`);
- a new report format (see `internal/report`), with the schema version bumped.

## Development setup

You need Go 1.26 or newer; with an older Go 1.21+ install, the `go` command
downloads the toolchain `go.mod` asks for automatically. Nothing else is
required for the Go code.

```sh
git clone https://github.com/yinkoshield/pinscan.git
cd pinscan
make tools      # installs the pinned golangci-lint
make            # fmt + strict lint + race tests + build
go run ./cmd/pinscan selftest   # proves the methodology end to end, no device
```

`make` must be green before you open a pull request. CI runs the same gate plus
a reproducible-build byte-check (`make repro`).

For the Android Zygisk module in `android/ykzpinscan/` you also need the
Android NDK. `build.sh` finds it under `$ANDROID_HOME/ndk` or takes
`ANDROID_NDK_HOME`. A rooted device with Magisk and Zygisk is needed to test
anything under `internal/device`, `internal/camodule` or the module itself.

## How we work

Read [ENGINEERING.md](ENGINEERING.md). The short version:

- **Test first.** Write the failing test, then make it pass. Table-driven
  subtests with `t.Parallel()`; the linter enforces both.
- **The classifier is the specification.** Any change to how wave outcomes
  become a verdict goes through `internal/classify`, must keep that package at
  100% coverage, must update the test table so every rule is visible, and must
  update [docs/methodology.md](docs/methodology.md) in the same pull request.
  If the change alters what `pinscan selftest` should observe, update the
  selftest expectations too. A verdict is never allowed to become "secure" from
  the absence of a signal.
- **Pure core, effects at the edges.** No I/O, clock or globals in
  `internal/classify`. Device, proxy and file access live behind interfaces.
- **Report contract.** The JSON report is versioned (`report.SchemaVersion`).
  Adding a field is a minor bump; renaming, removing or changing the meaning of
  a field is a major bump. Regenerate the schema (`pinscan schema`) and update
  [docs/output.md](docs/output.md). Baselines must stay canonical and
  byte-stable: no timestamps, no captured bodies, sorted keys.
- **Shell commands sent to the device** are built only from values that passed
  the validators in `internal/device`. Do not interpolate anything else into
  `su -c`.
- **Lint is part of the build.** `make lint` must exit 0 with the committed
  `.golangci.yml`. A `//nolint` needs a specific linter and a reason that
  survives review.

## Pull requests

- One logical change per pull request. Keep refactors separate from behaviour
  changes.
- Fill in the description: what changed, why, and how you verified it. For
  anything that touches the device, say which Android version and Magisk
  version you tested on.
- Update the documentation in the same pull request. `docs/` and the command
  reference must describe the code as merged, not as planned. Add a line under
  `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for anything a user would
  notice.
- Do not commit build outputs, coverage files, a research CA, or any
  `*.0` trust-store file. `.gitignore` covers the usual paths; please keep it
  that way.
- If you change anything under `android/ykzpinscan/jni/`, rebuild the prebuilt
  `zygisk/arm64-v8a.so` with `build.sh`, and state in the pull request the NDK
  version used and the SHA-256 of the new file. Reviewers will rebuild and
  compare before merging. Do not modify `jni/zygisk.hpp`; it is the upstream
  Zygisk API header and must stay byte-identical.
- Commits should have a clear subject line in the imperative ("Fix transparent
  redirect letting QUIC escape"), with a body when the subject is not enough.

By submitting a pull request you agree that your contribution is licensed under
the Apache License 2.0, the same license as the project, and that you have the
right to submit it under that license.

## Releases

Maintainers cut releases by pushing a `v*` tag. The `release` workflow
(`.github/workflows/release.yml`) re-runs the gate on that commit and runs
goreleaser (`.goreleaser.yaml`), which produces archives, SHA256SUMS and a
CycloneDX SBOM per archive and opens a **draft** GitHub release for a human to
review and publish. Before tagging, move the `[Unreleased]` entries in
`CHANGELOG.md` under the new version. The binary's version comes from the tag.
