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
- `passthrough: true` — relayed to the real server, **not tested**; see below.

Loading fails if any entry lacks a reason, uses an unknown field, or combines
`expect` with `passthrough` (an untested host cannot meet an expectation), so a
typo cannot silently weaken the gate.

## Passthrough hosts

When an app's first connection (login, config, bootstrap) is key-pinned, every
wave presents it a forged certificate, the app refuses, and often stops there:
no session, no further hosts, and the question that matters — "the login API
pins its key, but is everything else checked properly?" — goes unanswered. A
**passthrough** host is relayed to its real server byte for byte, with no
forged certificate, so the app's own pinning check passes and the app proceeds
to the hosts the scan is after.

```yaml
hosts:
  login.bank.example:
    passthrough: true
    reason: "SPKI-pinned login API; let the app log in so the rest is exercised"
  "*.auth.bank.example":
    passthrough: true
    ignore: true
    reason: "SSO front doors, pinned; do not gate on them"
```

The same list can come from the CLI (`-passthrough login.bank.example`,
repeatable, `*.suffix` wildcards allowed); both sources merge into one list. A
wildcard host key is only valid on a passthrough rule, since every other rule
is matched by exact host. A malformed wildcard (`*.`, `api.*.example`) is
refused.

The bare `*` relays every host. That is a **discovery run**, not a scan: some
apps pin their very first connection so tightly that no wave ever sees a
request from any host, and relaying everything is the only way to learn which
hosts the app contacts at all. Every host is still recorded (from its CONNECT
target or SNI) and listed `inconclusive` with reason `passthrough`; the tally
reads "N passthrough (not tested), 0 hardened", the report carries
`summary.passthrough` equal to the host count, and a warning is logged at
start. Take the host list from it, then scan again passing through only the
pinned host. It is accepted from the CLI (`-passthrough '*'`) and from a
policy key `"*"` with `passthrough: true`, which is never listed as unobserved.

A passthrough host is **not tested**, and nothing lets it look tested:

- its verdict is `inconclusive` with reason `passthrough` in every wave it was
  seen in (`passthrough_dial_failed` when the real server could not be
  reached), and it carries the caveat "passthrough: relayed to the real server,
  not tested" in the text output, Markdown, HTML and JSON;
- the tally and the report count it separately: `4 host(s): 1 interceptable,
  1 inconclusive (not verified), 1 passthrough (not tested), 1 hardened`
  (`summary.passthrough` in JSON);
- being inconclusive, it trips `-fail-on-inconclusive` unless the rule also
  says `ignore: true`, and a host that had a verdict in the baseline and is now
  passthrough is **needs-review**, not a pass and not a regression;
- SARIF emits no result for it (nothing was found); JUnit emits a skipped case
  with the caveat as the reason.

A wildcard passthrough entry never appears as "unobserved": it names a family
of hosts, not one host to look for.

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
            -passthrough login.example.com \
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
