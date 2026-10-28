<!-- Thanks. CONTRIBUTING.md has the bar; this is the checklist. -->

## What and why

<!-- One paragraph. Link the issue if there is one. -->

## How it was verified

<!-- `make` output, and for device changes the Android + Magisk version tested. -->

## Checklist

- [ ] `make` is green (fmt, strict lint, race tests, build) and `go run ./cmd/pinscan selftest` passes.
- [ ] Tests were written first and cover the change; `internal/classify` is still at 100%.
- [ ] Documentation in `docs/` describes the code as merged, not as planned.
- [ ] If the verdict logic changed: the classifier test table, `docs/methodology.md` and the selftest expectations are updated together.
- [ ] If the JSON report changed: `report.SchemaVersion` is bumped and `docs/output.md` is updated.
- [ ] If `android/ykzpinscan/jni/` changed: `zygisk/arm64-v8a.so` is rebuilt, and the NDK version and the file's SHA-256 are stated below.
- [ ] No build outputs, coverage files, research CA or `*.0` trust-store files are committed.
