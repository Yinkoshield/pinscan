# Engineering standards

This repository is a reference for how YinkoShield writes code. The bar is
deliberately high. It is not negotiable per-PR; it is the floor.

## Test-driven, always

- **Red → green → refactor.** Write the failing test first; it is the executable
  specification. The `classify` package was built this way: the test table
  defines every precedence rule and every "not observed" edge case, the
  implementation was stubbed to fail, then written to pass.
- **Tests are the spec.** If behaviour isn't in a test, it isn't guaranteed.
- **Table-driven, subtests, `t.Parallel()`.** Enforced by `paralleltest` /
  `tparallel`.
- **Race detector on every run** (`go test -race`).

## Coverage

- **100% of reachable logic in the pure core.** `internal/classify` is at 100%;
  the `classify → report` logic, header redaction, body decoding, and the CLI's
  parsing/printing/report helpers are covered directly. The uncovered remainder
  is the device-I/O boundary — `scan`'s `runWave`/`RunCapture`/`driveDevice` and
  the `adb`/`su` exec shims — which is exercised on a real device, plus the
  `os.Exit` wrapper in `main()`. We state that boundary rather than paper over
  it with a mock that only tests the mock.
- **Error paths are tested, not ignored.** `internal/certmint` injects an
  entropy failure (swapping `randReader`) and a bad certificate template to prove
  minting *propagates* failures rather than panicking or returning a half-built
  certificate.
- **We do not game the number.** `certmint`'s residual uncovered lines are
  identical `if err != nil` guards on the *secondary* step of multi-step
  functions, plus one "parse a certificate we just created" guard that is
  unreachable by construction. Hitting each would need brittle byte-counting
  fault injection — a worse test than an honest gap. Pedantry is about
  correctness and honesty, not a coverage trophy.
- Coverage is `-covermode=atomic` and every run uses `-race`.

## Pure where it matters

- The methodology (`classify`) is a **pure function** of its inputs — no I/O, no
  globals, no clock. That is what makes it exhaustively testable and auditable.
  Side effects (device, proxy, files) live at the edges, behind interfaces.

## Linting — the contract in `.golangci.yml`

Strict, but never fighting Go idiom (short receiver names stay). Enforced:

- **Correctness:** `staticcheck`, `govet`, `errcheck`, `ineffassign`, `unused`.
- **Errors:** `errorlint`, `errname`, `nilerr`, `bodyclose`, `noctx`; wrap with
  `%w` and context (`fmt.Errorf("parse flags: %w", err)`).
- **Exhaustiveness:** `exhaustive` — every `switch` over an enum handles every
  value (or an explicit `default`).
- **Clarity:** `revive` (exported/package docs, naming), `gocritic`, `gofumpt`,
  `goimports`, `godot`, `unparam`, `unconvert`, `nakedret`, `forcetypeassert`.
- **Complexity budgets:** `gocyclo` ≤ 12, `gocognit` ≤ 15.
- **Security:** `gosec`.
- **Honest suppressions:** `nolintlint` requires a specific linter and an
  explanation for every `//nolint`, and rejects unused ones.

`make lint` must exit 0. No `//nolint` without a reason that survives review.

## Documentation

- Every exported symbol has a doc comment that starts with its name and ends
  with a period (`revive` + `godot`).
- Package comments explain the *why*, not just the *what* — see `classify`'s
  description of the wave methodology.

## Reproducible builds

- `go build -trimpath -ldflags "-s -w -X main.version=..."`.
- Tool versions are pinned (`golangci-lint@v1.55.2` in the `Makefile`), never
  `@latest`, so the gate is deterministic.
- **We prove it, not just claim it.** `make repro` builds the binary twice and
  byte-compares the two; `make dist` cross-builds with `CGO_ENABLED=0` and writes
  `SHA256SUMS`. Reproducibility is enforced, matching the coverage-honesty stance.
- Two pinned runtime dependencies: `gopkg.in/yaml.v3` (the `.pinscan.yaml` policy
  file) and `github.com/andybalholm/brotli` (pure-Go brotli decoding for captured
  bodies). Both are in `go.sum`, so builds stay deterministic and verifiable;
  everything else is the standard library.

## The gate

`make` runs `fmt → lint → test → build`. A change is not done until that is
green, locally and in CI. No exceptions, no "fix the lint later".
