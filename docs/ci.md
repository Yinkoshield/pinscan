# CI integration

pinscan is built to gate a build on TLS-pinning posture: block the PR that
weakens a host, surface findings in the Security tab, and never let a broken
scan read as a clean pass.

## Exit codes

A pipeline can tell a broken tool from a policy breach by the exit code:

| Code | Meaning | Typical CI action |
|:----:|---------|-------------------|
| `0` | completed, no policy violation | pass |
| `1` | usage / CLI error | fix the invocation |
| `2` | operational error (device/adb/CA/proxy couldn't complete the scan) | **alert ops / retry** — do not fail the merge |
| `3` | policy violation: an interceptable host, or an unmet `expect` | **block the merge** |
| `4` | regression against a baseline | **block the merge** |
| `5` | incomplete coverage: inconclusive hosts, or below `-min-confidence` | investigate / rescan |

The gate flags are opt-in: `-fail-on-interceptable` (→3), `-fail-on-regression`
(→4), `-fail-on-inconclusive` and `-min-confidence` (→5). Without them a scan
reports but never fails. The tally (and the report) always show the counts, so
even a passing run surfaces inconclusive hosts.

## Baselines and the regression gate (the "JSON repo")

Commit a baseline, then fail the build the day a release weakens a host — in the
PR that caused it, not in production.

```sh
# Once, reviewed: write a canonical baseline and commit it.
pinscan baseline com.example.app -o baselines/com.example.app.json

# Every build: compare against it.
pinscan scan com.example.app \
  -baseline baselines/com.example.app.json -fail-on-regression
```

A regression is a **weakening** on the strength lattice
`open < metadata < name-validation < key-pinned < spki` (e.g. `spki → open`), or
a **newly-appeared interceptable** host → exit `4`. A host that goes from a
decided verdict to `inconclusive` is reported **needs-review**, never a silent
pass. You can also diff two reports directly:

```sh
pinscan diff baselines/com.example.app.json new.json   # exit 4 on regression
```

Baselines are canonical JSON (no timestamps, no captured bodies), so they are
byte-stable and review as clean diffs.

## Policy file (`.pinscan.yaml`)

Declare per-host expectations and accepted risks, each with a **mandatory
reason**, and enforce them. See [.pinscan.example.yaml](../.pinscan.example.yaml).

```yaml
hosts:
  secure.bank.example:
    expect: spki
    reason: "primary banking API must pin the key"
  analytics.vendor.example:
    allow: true
    reason: "third-party analytics; no credentials or PII sent from the app"
  legacy.example:
    ignore: true
    reason: "deprecated endpoint, removed next release"
```

```sh
pinscan scan com.example.app -policy .pinscan.yaml -fail-on-interceptable
```

- `expect:` — the host must be at least this strong, or it's a violation (→3).
- `allow: true` — the host may be interceptable: an **accepted risk**, surfaced
  in the output and exempt from `-fail-on-interceptable`.
- `ignore: true` — excluded from gating (still shown).

Loading fails if any entry lacks a reason or uses an unknown field, so a typo
cannot silently weaken the gate.

## Confidence gate

Require that a "hardened" pass is well-evidenced, not a one-shot fluke:

```sh
pinscan scan com.example.app -min-confidence high   # exit 5 if any verdict is weaker-evidenced
```

See [methodology](methodology.md#confidence) for how confidence is derived.

## Findings in the PR

```sh
pinscan scan com.example.app -report findings.sarif   # → upload to code scanning
pinscan scan com.example.app -report results.xml      # → JUnit test pane
```

See [output](output.md#sarif-and-junit-mapping) for the verdict→severity map.

## GitHub Actions example

pinscan needs a device, so the scan step runs on a self-hosted runner with a
connected phone (or an emulator harness). The report upload is standard:

```yaml
jobs:
  pinning:
    runs-on: [self-hosted, android]   # a runner with an adb-connected device
    steps:
      - uses: actions/checkout@v4
      - run: make build
      - name: Scan
        run: |
          ./bin/pinscan scan com.example.app \
            -policy .pinscan.yaml \
            -baseline baselines/com.example.app.json \
            -fail-on-regression -fail-on-interceptable \
            -report findings.sarif -log-format json
      - name: Upload to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
```

Treat exit `2` (operational) as a retry/alert, not a merge block — distinguish
it from `3`/`4` in your job logic if your runner's device is flaky.

## The tool's own CI

This repository ships [.github/workflows/ci.yml](../.github/workflows/ci.yml):
`go test -race`, the `selftest` methodology proof, build, a reproducible-build
byte-check, and golangci-lint — the gate that keeps pinscan itself honest.
