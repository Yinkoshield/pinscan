# Validation matrix

> **To run it on a device.** Build pinscan (`make build`), create a research CA
> if you have none (`pinscan ca-new`), and install CA trust on the rooted phone
> as described in [Scanning Android](android.md): the `ykzpinscan` module with
> your CA in its `cacerts/` for scoped mode, or the `pinscan ca-module` output
> for system mode. Build and install the validation app, which needs the
> Android SDK, JDK 17 and Gradle 8.13+ on the host:
> `cd android/validation-app && ./build.sh --install`. Unlock the phone, then
> from the repository root run `scripts/validate-device.sh` (add `-m system`
> for system mode). It runs `pinscan doctor`, scans one posture per package,
> writes the JSON reports and the evidence to `validation/<UTC date-time>/`,
> prints a pass/fail table and exits `0` only when every row matches. About
> ten minutes at the default 20 s window. `-l` lists the rows, `-r okhttp`
> re-runs one.

`pinscan selftest` proves the methodology against in-process clients. This
matrix is the same proof on an Android device, against real TLS stacks with
known postures, including the ways a test setup goes wrong. It exists so a
reviewer can check, rather than take on trust, that each verdict means what
[the methodology](methodology.md) says, and that a broken setup is refused
rather than reported as hardened.

## What is validated

The device side is a purpose-built app,
[`android/validation-app/`](../android/validation-app/README.md): one product
flavor per client posture, each its own package
(`com.yinkoshield.pinscan.validation.<posture>`), so one `pinscan scan` measures
exactly one posture and the report's `scan.package` names it. Every flavor makes
three HTTPS requests to one public host (`example.com` by default) on launch.
The pinned flavors pin the SPKI of every certificate in that host's live chain,
read from a single file, so the pin set survives a leaf rotation and is easy to
refresh (`build.sh`). No prebuilt APK is committed; `build.sh` prints the SHA-256
of each APK it builds.

The script compares two things per row with the matrix: the host's **verdict**
and the report's **`ca_trust`**. It records the per-wave reasons, the app's own
logcat lines, and, for the multi-process row, which processes see the research
CA, as evidence next to each report.

## The matrix

Column key: A/B/C are the per-wave outcomes pinscan should record for the host
(`generic`, `cloned`, `issuer`). On Android, every certificate rejection comes
from Conscrypt, which answers a trust-manager failure with the TLS alert
`certificate_unknown` (46); pinscan labels it `tls_alert_certificate_unknown`,
and any other certificate-class alert counts the same way. "Selftest" means the
in-process `pinscan selftest` already asserts this behaviour; "device" means it
needs this kit.

### Client postures

| Row | Client | Covered by | Expected verdict | Expected `ca_trust` | Expected A / B / C | Why |
|-----|--------|-----------|------------------|---------------------|--------------------|-----|
| `nopin` | OkHttp over the platform trust manager, Network Security Config trusting the system store, no pins | selftest (`no-pinning`) and device | `open` | `verified` | A `accepted/request_observed`; B accepted too; C not run | The research CA is in the store the app reads, so every forged chain validates and the app sends its request. Acceptance in wave A decides, whatever B does. |
| `nsc-correct` | Network Security Config `<pin-set>` holding the host's real chain | selftest (`spki-pinning`) and device | `spki` | `verified` | A, B, C all `rejected/tls_alert_certificate_unknown` | NSC pins are checked inside the platform trust manager, during the handshake, against the validated chain. No forged chain carries a pinned key, not even wave C's cloned issuer, so all three are rejected with a certificate alert. Three attempts per launch give `high` confidence when all reach the proxy. |
| `nsc-wrong` | Network Security Config `<pin-set>` holding one bogus pin | device | `spki` | `verified` | A, B, C all `rejected/tls_alert_certificate_unknown` | Same evidence as `nsc-correct`: the app rejects every chain, forged or genuine. pinscan measures resistance to a trusted-CA attacker, which a broken pin set has; it cannot tell "pins the right key" from "pins nothing". See VAL-2. |
| `okhttp` | OkHttp 4 `CertificatePinner` with the real chain | device | `inconclusive` | `verified` | A, B `ambiguous/handshake_ok_no_request`; C not run | OkHttp pins after the handshake: the platform trust manager accepts the forged chain, then the pinner throws and the connection closes with no request. No certificate alert ever reaches the proxy, so by the honesty rules this is `inconclusive`, never `spki` and never `open`. This is the documented limit in the README. |
| `trustmanager` | OkHttp over a custom `X509TrustManager` (platform validation, then a pinned key required) | selftest (`spki-pinning`) and device | `spki` | `verified` | A, B, C all `rejected/tls_alert_certificate_unknown` | The pin check runs inside `checkServerTrusted`, so a mismatch aborts the handshake with a certificate alert, exactly like NSC. |
| `webview` | `WebView` loading the host, no pins | device | `open` | `verified` | A `accepted/request_observed`; C not run | Chromium on Android validates through the platform trust store and honours the global proxy; with nothing pinned it sends the page request over the generic leaf. A `spki` here would mean Certificate Transparency or another enforcement is active in this WebView build and is worth a note. |
| `netproc` (system mode) | OkHttp over the platform trust manager in a second process `<package>:net`, no pins | device | `open` | `verified` | as `nopin` | System-mode trust is device-wide, so the process name does not matter. |

Not on the device: the selftest's `metadata-validation` and `name-validation`
postures. No mainstream Android TLS stack validates certificate names only or
issuer names only; a device app with that behaviour would be a hand-written
verifier, which is what the selftest already runs. Those two rows stay
in-process by design.

### Misconfigurations

These rows reproduce a broken setup without changing anything on the device.
Two use a research CA other than the one the device trusts, passed with `-ca`;
the third uses the `netproc` flavor in scoped mode.

| Row | Setup | Covered by | Expected outcome | Expected `ca_trust` | Why |
|-----|-------|-----------|------------------|---------------------|-----|
| `ca-absent` | `-ca` points at a fresh CA with a different subject, so its `<hash>.0` file does not exist on the device | selftest (`untrusted-ca`, the withholding rule) and device (the refusal) | scan refused, exit `2`, "the research CA is not trusted", no report | n/a | System mode: `Preflight` reads the trust store from every zygote mount namespace and stops before any wave. Scoped mode: the check runs inside the app's process after the wave A launch and stops there. Without this rule the app would reject all three waves and read `spki`. |
| `ca-wrong-subject` | `-ca` points at a fresh CA with the **same** subject (same `<hash>.0` name) but different content | device | scan refused, exit `2` | n/a | Trust-store names derive from the subject alone, so a name check would pass. pinscan compares the file's SHA-256, finds a different certificate under the same name, and refuses. If your CA was not made by `pinscan ca-new`, the script warns that this row degenerates into `ca-absent`; the expectation is the same. |
| `netproc` (scoped mode) | the `ykzpinscan` module targets the package; the TLS client runs in `<package>:net`, a process the module does not bind | device | **honest:** `inconclusive` with `ca_trust: unverified`, or the scan refused with exit `2`. **Observed:** `spki` with `ca_trust: verified`, a false hardened verdict (VAL-1, confirmed) | `unverified` | An unpinned client that rejects every forged chain only because its process never got the CA must not read as hardened. The script accepts either honest outcome and fails on the observed one, so this row fails until VAL-1 is fixed. |

The script compares verdict and `ca_trust` only. A mismatch in a per-wave
reason (for example `tls_alert_bad_certificate` instead of
`tls_alert_certificate_unknown` on a non-Conscrypt stack) is printed, not
failed.

## Reading a run

`validation/<UTC date-time>/` holds, per row, `<row>.json` (the report, when
the scan completed), `<row>.log` (pinscan's output), `<row>.logcat.txt` (the
app's `PINSCAN_VALIDATION` lines and the module's `YKZPINSCAN` lines), plus
`doctor.txt`, `environment.txt` (pinscan, Android and Magisk versions),
`module-log.txt` in scoped mode, `netproc.namespaces.txt` for the multi-process
row, the two generated CAs for the misconfiguration rows, and `summary.txt`, the
table the script printed. The directory is ignored by git: it carries your LAN
address and CA fingerprints.

Background hosts (connectivity checks, push, WebView's own traffic) appear in
the reports as well; the script reads only the validation host's entry.

## Run record

| Date | Device | pinscan | Mode | Result |
|------|--------|---------|------|--------|
| 2026-10-28 | Android 14 (API 34), model A142, Magisk 30.7, Zygisk | v1.0.0-3-g0027240 | scoped, 20 s window | 8 of 9 rows matched; `netproc` read `spki`/`verified` (VAL-1 confirmed) |

In that run every client row produced exactly the per-wave evidence in the
table: `request_observed` for `nopin` and `webview`,
`tls_alert_certificate_unknown` in all three waves for `nsc-correct`,
`nsc-wrong` and `trustmanager`, `handshake_ok_no_request` for `okhttp`, and
both CA rows were refused at wave A with "the research CA is not trusted". The
pinned rows read `medium` rather than `high` confidence because the first
version of the app used the platform `HttpsURLConnection`, which let only one
attempt per launch reach the proxy after a certificate failure; the app now
uses OkHttp for those rows (see its README), and the re-run of `nsc-correct`,
`nsc-wrong`, `trustmanager` and `nopin` the same day read `high` on all four,
with the same per-wave evidence. Background hosts of the
device's Google services appeared in the same reports (`www.google.com` as
`spki`, a `googleapis.com` host as `key-pinned`), as the methodology predicts
for proxy routing; the script ignores them.

## Open findings

Findings the matrix exposes in the classifier, the trust rule or the module.
Per the contribution rules they are recorded here, not patched in this change.

### VAL-1 (confirmed): scoped mode misses a multi-process app and reads it as hardened

Status: predicted from the code, confirmed on the device on 2026-10-28.
`netproc.namespaces.txt` from that run:

```
targets file:
com.yinkoshield.pinscan.validation.netproc
process com.yinkoshield.pinscan.validation.netproc:
  pid 12619: /apex/com.android.conscrypt/cacerts/71ee3f50.0
process com.yinkoshield.pinscan.validation.netproc:net:
  pid 12649: ls: /apex/com.android.conscrypt/cacerts/71ee3f50.0: No such file or directory
```

The module logged `CA bind OK` for the main process only; the `:net` process
failed every attempt with "Trust anchor for certification path not found", and
pinscan reported `spki`, `ca_trust: verified`, confidence `medium`, for a
client that pins nothing.

The `ykzpinscan` module compares the forking process's *nice name* with the
`targets` file by exact match (`is_target` in
[`pinscan.cpp`](../android/ykzpinscan/jni/pinscan.cpp)); `pinscan scan` writes
only the package name there. An app component declared with
`android:process=":net"` forks as `<package>:net`, so the module detaches and
that process keeps the stock trust store. Meanwhile the scoped trust probe
(`VerifyTrust` in [`internal/device`](../internal/device/device.go)) runs
`pidof <package>`, which matches the main process only, finds the CA bound
there, and reports trust `verified`. The `:net` process rejects every forged
chain with `certificate_unknown`, wave C runs, and the host reads `spki`,
`ca_trust: verified`, for a client that pins nothing.

Possible fixes, for a separate change: match `<package>:<anything>` in the
module (compare up to the colon) and write nothing new to `targets`; and make
the trust probe inspect every process of the app's UID rather than
`pidof <package>`, requiring the CA in all of them. Apps that do networking in
a separate process are not exotic (push and sync services commonly do), so
until fixed, scoped-mode `spki` on such an app is not trustworthy and system
mode is the safe choice.

### VAL-2 (by design): a pin set that matches nothing reads `spki`

The `nsc-wrong` row rejects the genuine chain as well as the forged ones and
reads exactly like `nsc-correct`. pinscan measures whether a trusted-CA
attacker can intercept the host; a broken pin set resists that attacker, at
the cost of not working at all. This is the documented scope, not a defect,
but worth stating in a review: `spki` does not mean the app reaches the host.
A future reachability pass (connect to the real host through the proxy without
forging and record whether the app accepts its genuine chain) would separate
"pinned" from "broken". Not implemented here.

### VAL-3 (minor): scoped-mode `doctor` checks the module directory, not the CA in it

In scoped mode `doctor` passes when `/data/adb/modules/ykzpinscan` exists. It
does not verify that the module's trust store (`system_cacerts/`, built by
`service.sh` at boot from `cacerts/`) holds the research CA, nor that Zygisk is
enabled. The `ca-absent` row under scoped mode shows the consequence: `doctor`
passes, and the scan refuses only at wave A after launching the app. The
outcome is still correct, just later and with less precise guidance. `doctor`
could compare the SHA-256 of `system_cacerts/<hash>.0` the way the system-mode
check does.

## Limits of this kit

- It validates pinscan against known clients on one device. It is not a
  compatibility matrix across Android versions; record the version from
  `environment.txt` in the run record above and in the pull request.
- All code rows use OkHttp 4 as the HTTP client (over the platform trust
  manager, so Network Security Config applies). The platform
  `HttpsURLConnection` behaved differently after a certificate failure on
  Android 14, stalling the next attempts and later completing them outside the
  proxy; that is a property of that client's route retry, not of pinscan, and
  is not investigated further here.
- The pinned flavors depend on the validation host's chain. When the host
  changes issuer, `./build.sh` refreshes the pins; a stale pin set turns
  `nsc-correct`, `okhttp` and `trustmanager` into `nsc-wrong`-like clients,
  which still read as expected but no longer prove the correct-pin case.
- `ca_trust: unverified` with a completed scan (the withholding path, as
  opposed to the refusal) is asserted by the selftest. On a device it occurs
  when the app has no process to inspect at the moment of the check, which is
  timing-dependent, so no row forces it; the `netproc` row's honest outcome
  includes it.
- OkHttp's `inconclusive` is a limit of the method, stated in the README, not
  something this kit can turn into a positive verdict.
