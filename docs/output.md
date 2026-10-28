# Output formats

Results always print to **stdout** as a human table plus a tally; structured
logs go to **stderr** (`-log-format json` for machine ingestion), so a pipeline
can separate them. `-report <path>` additionally writes an artifact, with the
format chosen by the extension:

| Extension | Format | Use |
|-----------|--------|-----|
| `.json` | the versioned JSON contract | machine consumption, baselines, diffs |
| `.md` / `.markdown` | Markdown | PR comments, human review |
| `.html` / `.htm` | self-contained HTML | share / attach; renders captured bodies safely |
| `.sarif` | SARIF 2.1.0 | code-scanning UIs (GitHub PR **Security** tab) |
| `.xml` / `.junit` | JUnit XML | CI **test** panes |

```sh
pinscan scan -report scan.html   com.example.app
pinscan scan -report out.json    com.example.app
pinscan scan -report out.sarif   com.example.app
pinscan scan -report out.xml     com.example.app
```

## The JSON contract

The JSON report is a **versioned, stable contract** a CI can depend on. Print
its JSON Schema with `pinscan schema`.

```jsonc
{
  "schema_version": "1.0.0",
  "tool": { "name": "pinscan", "version": "1.2.3" },
  "scan": {                       // deterministic inputs
    "package": "com.example.app",
    "mode": "scoped",
    "transparent": false,
    "window_seconds": 30,
    "ca_sha256": "…",
    "waves_run": ["generic", "cloned", "issuer"]
  },
  "summary": {
    "hosts_total": 3, "interceptable": 1, "inconclusive": 1,
    "by_verdict": { "open": 1, "metadata": 0, "name-validation": 0,
                    "key-pinned": 0, "spki": 1, "inconclusive": 1 }
  },
  "hosts": [                      // sorted by host — the diffable core
    {
      "host": "api.example.com",
      "verdict": "spki",
      "confidence": "high",
      "mechanism": "Genuine public-key (SPKI) pinning: …",
      "interceptable": false,
      "waves": [
        { "wave": "generic", "outcome": "rejected", "reason": "tls_alert_bad_certificate" },
        { "wave": "cloned",  "outcome": "rejected", "reason": "tls_alert_bad_certificate" },
        { "wave": "issuer",  "outcome": "rejected", "reason": "tls_alert_bad_certificate" }
      ]
    }
  ],
  "run": {                        // volatile — omitted in canonical output
    "started_at": "2026-10-12T09:00:00Z",
    "duration_seconds": 41.2
  }
}
```

The per-host `waves` carry the **evidence** behind the verdict — which
certificate was presented, what happened, and why — so the classification is
auditable (see [methodology](methodology.md)).

### Versioning

`schema_version` is semver. A consumer must refuse a **major** it does not
recognise; additive fields are **minor** bumps. Ship your pinned expectations
against the major you tested.

### Canonical output (deterministic)

A baseline (`pinscan baseline`) and the `-baseline` comparison use **canonical**
JSON: the volatile `run` block (timestamps, duration) is omitted and keys are
stable, so two identical-posture scans are **byte-identical** and git-diffable.
This is what makes the regression gate reliable — see [CI integration](ci.md).

## Captured exchanges

With `-capture`, each interceptable host's forwarded request/response pairs are
recorded and appear in the report. They are also **logged live** as they are
intercepted (to stderr, alongside the other logs): one `intercepted` line per
exchange with the method, host, path, status and size, and — at `-debug` — a
request/response body preview:

```
level=INFO msg=intercepted host=secure.example.com method=POST url=/api/update status=200 content_type=application/json resp_bytes=16384
msg="intercepted body" response="{\"manifest\":[{\"id\":\"…"
```

As defence in depth — and only ever for the startup/unauthenticated surface:

- credential headers (`Authorization`, `Cookie`, `Set-Cookie`,
  `Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token`) are **redacted**;
- bodies are **size-capped** (16 KiB by default, see `-capture-max`) and
  decompressed for readability — gzip, deflate and **brotli** (what browsers and
  modern SDKs negotiate) — while the relay to the client stays byte-faithful;
- the HTML renderer **escapes** all embedded content, and a non-UTF-8 body is
  replaced by a `<N bytes binary>` note — the artifact is safe to open.

## Dumping all traffic (`-capture-out`)

`-capture-out <file>` writes a **standalone dump of every captured exchange** —
request and response — separate from the posture report. The format follows the
extension:

| Extension | Format | Use |
|-----------|--------|-----|
| `.json` | flat transcript `{tool, package, exchanges:[…]}` | grep, scripts, diffing |
| `.har` | HTTP Archive 1.2 | open in browser devtools, Charles, Proxyman, … |

```sh
pinscan scan com.example.app -capture-out capture.har                   # open in devtools
pinscan scan com.example.app -capture-out capture.json -capture-max 262144  # fuller bodies
```

- `-capture-out` **implies** `-capture` (there must be a recording to dump).
- `-capture-max <bytes>` raises the per-body cap (default 16384) so the dump is
  not truncated — useful for large config/manifest responses.
- The same redaction and startup-surface-only rules above apply; the dump still
  carries redacted credential headers, never cleartext secrets.

The `-report *.json` artifact also embeds these exchanges per host;
`-capture-out` is the focused, portable dump of just the traffic.

## SARIF and JUnit mapping

| Verdict | SARIF level | JUnit |
|---------|-------------|-------|
| interceptable (`open`/`metadata`/`name-validation`) | `error` | `<failure>` |
| `inconclusive` | `warning` | `<skipped>` |
| `key-pinned` / `spki` | `note` | pass |

SARIF results carry a per-host location so code-scanning UIs display them, and a
stable `partialFingerprints` entry so findings deduplicate across runs.
