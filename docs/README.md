# pinscan documentation

pinscan evaluates the TLS-pinning **posture** of an Android app — or any TLS
client — per endpoint and per SDK, without instrumenting it. These guides go
deeper than the top-level [README](../README.md).

## Start here

- **[Getting started](getting-started.md)** — install, `doctor`, your first scan.
- **[Methodology](methodology.md)** — the three waves, the verdicts, confidence,
  and the honesty rules (why pinscan never reports "secure" from silence).

## Running it

- **[Scanning Android](android.md)** — rooting, the CA-injection module, scoped
  vs system mode, transparent mode, running on a phone.
- **[Trying it on an emulator](emulator.md)** — a no-physical-device walkthrough
  (validated on Android 13) that also shows CA trust taking effect.
- **[Scanning anything else](non-android.md)** — the `manual` driver for desktop
  apps, server-side SDKs and IoT clients.

## Using the results

- **[Output formats](output.md)** — the JSON contract, HTML/Markdown, SARIF and
  JUnit, and the schema-version policy.
- **[CI integration](ci.md)** — exit codes, baselines and regression gates, the
  `.pinscan.yaml` policy file, SARIF/JUnit, and a GitHub Actions example.

## Reference

- **[Command reference](commands.md)** — every subcommand and flag.
- **[Validation matrix](validation.md)** — expected verdicts per known client
  posture and per broken setup, with the device-side kit that checks them.
- **[Troubleshooting](troubleshooting.md)** — common failures and fixes.
- **[Architecture](architecture.md)** — package layout and data flow, for
  contributors.

## A note on scope and authorization

pinscan is for **authorized** security assessment: devices and apps you own or
are explicitly permitted to test. It is a posture-evaluation tool, not an
interception tool for third-party traffic. It measures only the client you point
at it, under the certificate trust you set up. See [methodology](methodology.md)
for exactly what a verdict does and does not claim.
