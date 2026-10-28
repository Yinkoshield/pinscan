# Methodology

pinscan measures one thing: **does a TLS client trust a certificate we mint,
and does it use the connection?** It makes the client trust a research CA, then
presents forged certificates of increasing fidelity and watches what the client
does. No Frida, no hooks, no repackaging — the app runs unmodified.

## The three waves

For each host the client contacts, pinscan can present up to three forged
certificates, every one signed by the research CA the client now trusts. They
differ only in how closely they imitate the real endpoint:

| Wave | Certificate | Signed by | What acceptance reveals |
|------|-------------|-----------|-------------------------|
| **A** `generic` | leaf with a generic identity for the host | research CA | no pinning at all |
| **B** `cloned-metadata` | leaf copying the real leaf's subject + SANs, **our key** | research CA | validates certificate *names* only |
| **C** `cloned-issuer` | that leaf under an intermediate whose DN **clones the real issuer** | research CA | validates the issuer *name/chain*, **not the key** |

No forged certificate ever uses the real endpoint's private key — pinscan does
not have it. That is exactly what a key-level check detects.

Wave A and B always run. Wave C runs only when some host rejected both A and B
with a certificate alert (i.e. it looks key-pinned and C can refine the finding).

## The verdicts

| Verdict | Meaning | Interceptable by a trusted-CA attacker |
|---------|---------|:---:|
| `open` | sent a request over the generic leaf — no pinning | **yes** |
| `metadata` | rejected generic, accepted the cloned-metadata leaf | **yes** |
| `name-validation` | rejected the leaves, accepted the cloned-issuer chain | **yes** |
| `key-pinned` | rejected the forged leaves with a certificate alert; wave C inconclusive | no |
| `spki` | rejected everything, incl. the cloned issuer, with a certificate alert | no |
| `inconclusive` | no usable signal, or trust unverified (see below) | no |

Verdict names describe **behaviour under these three forgeries**, not the
mechanism that produced it. `spki` is the strongest posture pinscan can observe:
"rejected every tested chain, including one whose issuer name matches". It is
consistent with an SPKI pin set, a private trust store or Certificate
Transparency enforcement, and pinscan does not say which (see
[Scope](#scope-stated-honestly)).

"Interceptable" means: an attacker holding **any** certificate the device trusts
(a mis-issued cert, a compromised or coerced CA, an enterprise MITM root) could
read and modify that host's traffic. `open`, `metadata` and `name-validation`
are all defeated that way; only `spki` resists.

`pinscan scan -explain` prints a one-line account of each verdict's mechanism.

## The honesty rules — never "secure" from silence

A posture tool is dangerous if it reports "hardened" when it simply didn't see
anything. pinscan is built so that **an absence of signal is never a pass.**

### Acceptance requires an observed request, not just a handshake

An app can complete the TLS handshake with the research CA and then reject the
connection at the application layer (e.g. OkHttp's `CertificatePinner`, which
pins *after* the handshake). So a host is `open` only when the client actually
**sent a request** over the forged certificate. A handshake with no request is
`inconclusive`, never `open`.

### Only a genuine certificate rejection counts as pinning

A host is `spki` / `key-pinned` only when the client refused with a
**certificate-class TLS alert** (`bad_certificate`, `unknown_ca`,
`certificate_unknown`, …). Every other reason a handshake can fail —

- a timeout or a TCP reset,
- a non-certificate alert (e.g. `handshake_failure` from cipher negotiation),
- the client sending no request after the handshake,
- pinscan's own failure to present a forged certificate (e.g. it could not fetch
  the real certificate for a cloned wave),

— is recorded **`inconclusive`**, never as a false "hardened". The per-wave
evidence (outcome + reason) is carried into the [report](output.md), so a
verdict is auditable rather than a bare label.

### A rejection counts only if the client trusted the research CA

A certificate alert is pinning evidence **only** when the client would have
accepted a certificate under the research CA had it not been pinning. A client
that was never made to trust the CA rejects every forged chain with
`unknown_ca` or `bad_certificate` too — on the wire, a broken test setup and a
pinned host look identical. So pinscan verifies trust before it believes a
rejection:

- **Android, system mode.** Before the waves, `Preflight` compares the SHA-256
  of the trust-store file with the research CA's, from inside every zygote mount
  namespace (the namespace apps inherit). An absent or different CA stops the
  scan with exit `2` and a fix, rather than running waves that would read every
  host as hardened.
- **Android, scoped mode.** The `ykzpinscan` module binds the CA at app fork,
  so the check runs after each launch, from inside the app's own process
  namespace. Absent means the scan stops; no process to inspect means trust
  stays unverified for that wave.
- **Manual driver.** pinscan cannot inspect the client; trust is recorded as
  `operator-asserted` and hardened verdicts carry that caveat.

The outcome is in every report as `ca_trust`: `verified`, `unverified` or
`operator-asserted`. When it is `unverified`, `spki` and `key-pinned` are
**withheld as `inconclusive`** with their per-wave evidence kept, and the text
output says how many were withheld. `pinscan selftest` includes a client that
does not trust the CA and asserts it reads `inconclusive`, not `spki`.

### Inconclusive is surfaced, not hidden

The scan tally always reports the inconclusive count ("2 interceptable, 1
inconclusive (not verified), 0 hardened"), and the CI gates treat a
decided→inconclusive change as **needs-review**, not a silent pass. See
[CI integration](ci.md).

## Confidence

Every verdict carries a confidence — `low`, `medium`, or `high` — a separate
axis from the verdict, so a one-shot result is not mistaken for a well-tested
one:

- **high** — the deciding wave was backed by **two or more** consistent attempts.
- **medium** — a single observation, or a `key-pinned` candidate (capped at
  medium because wave C did not conclusively confirm SPKI).
- **low** — attempts conflicted (one accepted, another genuinely rejected), or
  the verdict is `inconclusive`.

`pinscan scan -min-confidence high` makes CI require that a "hardened" pass is
well-evidenced rather than a fluke.

## Scope, stated honestly

Trust-store injection answers *"does the client trust a certificate under an
injected CA?"*. It cleanly separates **not-pinned** from **hardened**, and wave
C separates key pinning from name/chain validation. It does **not** identify the
pinning *mechanism* (an SPKI pin set vs. a private baked-in trust store vs. CT
enforcement) — that is a reverse-engineering follow-up. A `spki` verdict means
"resists a trusted-CA attacker under these parameters, at this time," not "cannot
be bypassed by any means."

## Proving it

`pinscan selftest` runs the real `certmint → proxy → observer → classify` path,
then the trust rule, against in-process clients that emulate each posture
(no-pin, metadata, name-validation, key-level check, and a client that does not
trust the research CA) and asserts the resulting verdict. It demonstrates the
separation end-to-end without a device, shows that an untrusted test CA reads
`inconclusive` rather than `spki`, and catches a silent regression (e.g. a
cert-minting change that stops cloning the issuer DN) that a unit test of the
pure classifier could not see.

## Related work

pinscan assembles known techniques into one repeatable tool. The lineage, and
what pinscan takes from each:

- **Fahl et al., "Why Eve and Mallory Love Android" (CCS 2012)** and
  **Georgiev et al., "The Most Dangerous Code in the World" (CCS 2012)**
  established that non-browser TLS clients accept forged certificates at scale.
  **SMV-Hunter (Sounthiraraj et al., NDSS 2014)** automated the MITM test with UI
  automation. **Frankencerts (Brubaker et al., IEEE S&P 2014)** probed validation
  logic with mutated certificates; the "waves of forgeries" idea is in that
  spirit.
- **nogotofail (Google, 2014)**, https://github.com/google/nogotofail, is an
  on-path MITM whose `selfsigned` handler clones the upstream CN and SANs under
  its own CA (wave B here) and whose `invalidhostname` handler presents a valid
  certificate for another domain. It declares a MITM success only when the
  client sends a request or receives a response over the attacked connection.
  pinscan's observed-request rule is that rule.
- **Chothia, Garcia, Heppel and McMahon Stone, "Why Banker Bob (still) Can't
  Get TLS Right" (FC 2017)** and **McMahon Stone, Chothia and Garcia, "Spinner:
  Semi-Automatic Detection of Pinning without Hostname Verification" (ACSAC
  2017)**, https://github.com/ChrisMcMStone/spinner, showed that pinning can
  hide a missing hostname check and detected it, without root or hooks, by
  presenting real certificates from the same issuer for another name. Wave C
  tests the neighbouring family of mistakes (name matching on the chain) with a
  forged chain under the research CA, so no certificate from the real issuer is
  needed and the test runs offline.
- **Pradeep et al., "A Comparative Analysis of Certificate Pinning in Android &
  iOS" (IMC 2022)**, https://github.com/NEU-SNS/app-tls-pinning, measured
  pinning per destination across 5,079 apps with a research CA in the system
  store and a differential analysis: a destination is pinned only if it carries
  application data without interception and never does with it. "Handshake
  completed, no data" is treated as a confounder there too. pinscan's per-host
  verdicts and its insistence on application data follow that design; pinscan
  is stricter in one respect, since a TCP reset or timeout is `inconclusive`
  here and a failure signal there.
- **OWASP MASTG-TEST-0244, "Missing Certificate Pinning in Network Traffic"**,
  is the industry baseline: intercept with a trusted CA, list the domains whose
  traffic came through, judge first-party domains only.

What pinscan adds on top of that lineage is the graded verdict scale, the
explicit `inconclusive` state with its reason carried into the report, the
confidence axis, the CI contract (exit codes, canonical baselines, the
regression lattice, the policy file), the Android 14 APEX trust module with
per-namespace verification, and a self-test that proves the separation without
a device.
