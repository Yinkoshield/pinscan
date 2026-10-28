# Command reference

```
pinscan scan <target> [flags]                       scan a target
pinscan doctor [package]                             check host + device prerequisites
pinscan ca-new [-o file.pem]                         generate a research CA (certificate + key)
pinscan ca-module [-ca pem] [-o dir]                 generate an open system-CA Magisk module
pinscan baseline <target> [-o file.json] [flags]     write a canonical baseline
pinscan diff <baseline.json> <current.json>          compare two reports
pinscan schema                                       print the report JSON Schema
pinscan selftest                                     prove the methodology, device-free
pinscan -version                                     print version
```

> Flags may come **before or after** the positional `<target>` — e.g. both
> `pinscan scan -capture com.example.app` and `pinscan scan com.example.app -capture`
> work.

## `scan`

Runs the waves against the target and prints each host's verdict + a tally.

| Flag | Default | Purpose |
|------|---------|---------|
| `-driver` | `android` | `android` (adb) or `manual` (any TLS client you drive) |
| `-mode` | `scoped` | android CA trust: `scoped` (Zygisk, one app) or `system` (device-wide) |
| `-ca` | `~/.pinscan/ca.pem` | research CA PEM bundle (certificate **and** key) to sign with (`pinscan ca-new` creates it) |
| `-host-ip` | auto | host LAN IP the device reaches (auto-detected if empty) |
| `-port` | `8080` | proxy listen port |
| `-window` | `60s` | scan window per wave |
| `-transparent` | off | route via device DNAT (raw TLS) instead of the HTTP proxy |
| `-capture` | off | forward + record the plaintext exchanges of interceptable hosts |
| `-capture-out` | — | dump every captured request/response to a file (`.json` / `.har`); implies `-capture` |
| `-capture-max` | `16384` | cap each captured body in bytes |
| `-explain` | off | print a plain-language mechanism line under each verdict |
| `-report` | — | write an artifact; format from the extension (`.json` `.md` `.html` `.sarif` `.xml`) |
| `-policy` | — | apply a `.pinscan.yaml` expectation/allowlist file |
| `-baseline` | — | compare against this baseline JSON and report regressions |
| `-min-confidence` | — | require every verdict to be at least `low` / `medium` / `high` |
| `-fail-on-interceptable` | off | exit `3` if any (non-exempt) host is interceptable |
| `-fail-on-regression` | off | exit `4` if the posture regressed against `-baseline` |
| `-fail-on-inconclusive` | off | exit `5` if any host is inconclusive |
| `-log-level` | `info` | `error` / `warn` / `info` / `debug` |
| `-log-format` | `text` | `text` or `json` (structured, for CI) |
| `-debug` | off | shorthand for `-log-level debug` |

For the `android` driver `<target>` is the app package; for `manual` it is any
label for the client. See [exit codes](ci.md#exit-codes).

## `doctor [package]`

Checks host and device prerequisites **without scanning**, printing a
`[ ok ] / [FAIL] / [warn]` line per check with a fix hint. Exits `2` if a
required check fails. Honours `-mode` and `-ca`. An optional package argument
adds a target-app-installed check. See [Scanning Android](android.md).

The checks, in the order they print:

| Check | Where | Required | What it verifies |
|-------|-------|:--------:|------------------|
| `adb on PATH` | host | yes | `adb` resolves on the host `PATH`; prints its location |
| `research CA readable` | host | yes | the `-ca` PEM loads and holds both a CA certificate and its private key |
| `device connected` | device | yes | `adb get-state` reports `device` (not `offline` or `unauthorized`) |
| `root (su)` | device | yes | `su -c id -u` returns `0` |
| `ykzpinscan module (scoped CA)` | device | yes, scoped mode | the `ykzpinscan` module directory is installed under `/data/adb/modules` |
| `system CA trust (system mode)` | device | warning only | the research CA is byte-identical to the file in the trust store **as seen from every zygote mount namespace**, i.e. the view an app actually gets; reports `trusted in n/n zygote namespace(s)` |
| `target app installed` | device | yes, when a package is given | the package name is valid and `pm path` finds it |
| `iptables` | device | no | present; needed only for `-transparent` |
| `ip6tables` | device | no | present; without it `-transparent` cannot block the app's IPv6 TLS |

The system-trust check compares certificate content, not just the filename:
trust-store names derive from the subject alone, so a different CA with the same
common name would otherwise read as trusted. It is a warning rather than a
failure because it needs the CA's fingerprint, which `doctor` only has when `-ca`
points at the right file.

```
$ pinscan doctor -mode system com.example.app
[ ok ] adb on PATH                      /opt/homebrew/bin/adb
[ ok ] research CA readable             /Users/me/.pinscan/ca.pem
[ ok ] device connected                 adb state: device
[ ok ] root (su)                        id -u: 0
[ ok ] system CA trust (system mode)    5f3a2c1b.0 trusted in 2/2 zygote namespace(s)
[ ok ] target app installed             com.example.app
[ ok ] iptables                         iptables
[warn] ip6tables                        ip6tables
         ↳ optional for -transparent; without it the app's IPv6 TLS is not blocked

all required prerequisites met
```

## `ca-new [-o <file.pem>]`

Generates a fresh research CA — a self-signed CA certificate and its private key
— and writes them as one PEM bundle, so pinscan needs no external tool to create
one. Flags: `-o` (output path, default `~/.pinscan/ca.pem` — the default `-ca`
for every command), `-cn` (certificate common name), `-force` (overwrite an
existing CA; replacing it invalidates any device already trusting the old one).
The file holds a private key — keep it readable only by you (`ca-new` writes it
`0600`). Any existing CA PEM works too; just pass it with `-ca`.

## `ca-module [-ca <pem>] [-o <dir>]`

Generates an **open** Magisk module that trusts the research CA system-wide, so
`-mode system` works without any compiled or proprietary component. Flags:
`-ca` (CA PEM to embed, default `~/.pinscan/ca.pem`), `-o` (output
directory, default `pinscan-ca`), `-id` / `-name` (module identity). Prints the
`adb push` + reboot install steps. See
[Scanning Android](android.md#system-mode-self-serve).

## `baseline <target> [-o file.json]`

Runs a scan and writes a **canonical** (deterministic, no-capture) JSON baseline
to `-o` (default `<target>.baseline.json`). Takes the same flags as `scan`.
Commit the output; compare future scans with `scan -baseline` or `diff`.

## `diff <baseline.json> <current.json>`

Compares two JSON reports and prints regressions, improvements, needs-review,
added and removed hosts. Exits `4` on a regression. No device needed.

## `schema`

Prints the report's JSON Schema (draft-07) to stdout — pipe it to a validator or
commit it for your consumers.

## `selftest`

Runs the methodology against in-process known-posture clients and asserts each
verdict. Prints a line per posture; exits non-zero if any misclassifies. No
device needed — suitable as a required CI check.
