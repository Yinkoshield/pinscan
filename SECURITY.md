# Security policy

pinscan forges TLS certificates, runs as root on a test device and rewrites the
device's trust store. A bug in it can therefore do more than return a wrong
answer. We want to hear about such bugs privately, and we will fix them quickly.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting: on the repository page, open the
**Security** tab and choose **Report a vulnerability**. The report goes only to
the maintainers. Include:

- what the bug lets an attacker or a careless operator do, in one or two
  sentences;
- the pinscan version (`pinscan -version`) or commit, the host OS, and, when the
  device is involved, the Android version and Magisk version;
- a reproduction: the command line, the relevant log (`-log-format json` is
  easiest to read), and a minimal client or app if one is needed.

You will get an acknowledgement within 3 business days and a fix or a reasoned
decision within 30 days for confirmed issues. We credit reporters in the release
notes unless they ask otherwise. We do not run a bounty program.

## What we consider a security issue

Anything that breaks one of these guarantees is in scope:

- **"Never secure from silence."** A code path that lets a host be reported
  `spki` or `key-pinned` without an observed certificate-class TLS rejection, or
  `open` without an observed request over a forged certificate. A wrong verdict
  that makes a weak endpoint look hardened is the most serious bug this tool can
  have.
- **Proxy exposure.** The proxy accepting connections from an address other
  than the one it was asked to bind, or the forged certificates or research CA
  being usable from outside the test setup.
- **Research CA handling.** The CA private key written with permissions looser
  than `0600`, logged, embedded in a report, or sent anywhere.
- **Root shell injection.** A package name, UID, hostname or path reaching an
  `adb shell su -c` command without passing the validation in `internal/device`.
- **Capture redaction.** Credential headers or body contents escaping the
  redaction and size cap in `internal/capture`.
- **Device safety.** The generated system-trust module (`internal/camodule`) or
  the `ykzpinscan` Zygisk module leaving the device in a boot loop, stripping
  stock certificates from the live trust store, or affecting apps other than
  the targeted package in scoped mode.
- **Transparent mode leaks.** The UID-scoped iptables rules capturing other
  apps' traffic, or not being removed on teardown.
- **Supply chain.** A prebuilt artifact in the repository (currently
  `android/ykzpinscan/zygisk/arm64-v8a.so`) that does not match its source, or
  a dependency problem in `go.sum`.

## What is not a security issue

- pinscan needing a rooted device, or an app refusing to run on one. Both are
  by design and documented.
- A host reported `inconclusive` for an app that pins at the application layer
  (OkHttp `CertificatePinner` and similar). That is the documented, deliberate
  result: pinscan will not call "hardened" what it cannot distinguish from "no
  request was made". See [docs/methodology.md](docs/methodology.md).
- Use of pinscan against apps or devices the operator is not authorized to
  test. The tool is for authorized assessment only; misuse is a matter for the
  operator, not a defect in the software.

## Supported versions

Security fixes land on `main` and in the next tagged release. Only the latest
release is supported; earlier releases are not patched.

## For operators

- Keep the research CA (`~/.pinscan/ca.pem` by default) private. It can sign
  certificates any device that trusts it will accept. Generate it with
  `pinscan ca-new` on the test host, never reuse one across teams, and remove
  the trust module from the device when the engagement ends.
- Run the proxy on a LAN you control. It binds to the host's LAN address, not
  to all interfaces, but a forged-certificate endpoint should still not be
  reachable from an untrusted network.
- Point `-capture` only at the startup, unauthenticated surface, as the
  documentation says. Redaction is defence in depth, not a reason to capture an
  authenticated session.
