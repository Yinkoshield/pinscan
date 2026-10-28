# pinscan validation app

A deliberately small Android app whose only job is to be scanned by pinscan
with a *known* TLS-pinning posture, so the verdicts in
[`docs/validation.md`](../../docs/validation.md) can be checked on a real
device. One product flavor per posture, each its own package, so
`pinscan scan <package>` measures exactly one posture and the report's
`scan.package` says which.

| Flavor | Package suffix | Client | Pinning |
|--------|----------------|--------|---------|
| `nopin` | `.nopin` | OkHttp 4, platform trust manager | none (`nsc_plain.xml`, system store only) |
| `nscok` | `.nscok` | OkHttp 4, platform trust manager | Network Security Config pin set with the host's real chain (`nsc_pinned.xml`) |
| `nscwrong` | `.nscwrong` | OkHttp 4, platform trust manager | Network Security Config pin set with one bogus pin (`nsc_wrong.xml`) |
| `okhttp` | `.okhttp` | OkHttp 4 | `CertificatePinner` with the same pins (checked after the handshake) |
| `trustmanager` | `.trustmanager` | OkHttp 4 over a custom `SSLContext` | custom `X509TrustManager` that validates with the platform, then requires a pinned key (checked inside the handshake) |
| `webview` | `.webview` | `WebView` | none |
| `netproc` | `.netproc` | OkHttp 4 in a second process `<package>:net` | none; exists to test the scoped-mode module against a multi-process app |

"Platform trust manager" means OkHttp with no socket factory set: it uses
Android's default `X509TrustManager`, so the Network Security Config, pins
included, applies exactly as it would to `HttpsURLConnection`. The first
version of this app used `HttpsURLConnection` for those rows; on Android 14
only the first attempt of each launch reached the proxy after a certificate
failure (the next ones stalled, then went out later), which left pinscan one
attempt per wave and a `medium` confidence. OkHttp with no connection pool and
no retry makes every attempt a fresh connection through the proxy.

Full package names are `com.yinkoshield.pinscan.validation` plus the suffix.
On every launch the app makes three HTTPS requests to the validation host with
that posture's client, 1.5 s apart (two consistent attempts make a pinscan
verdict `high` confidence), shows each outcome on screen and logs it under the
logcat tag `PINSCAN_VALIDATION`. pinscan launches it with the plain LAUNCHER
intent, so nothing has to be passed in.

## The host and the pins

[`app/src/main/res/xml/nsc_pinned.xml`](app/src/main/res/xml/nsc_pinned.xml)
is the single source of truth: the host (`example.com` by default) and the
SPKI pins of every certificate in its live chain. `Pins.java` reads that file
at runtime, so the `okhttp` and `trustmanager` flavors pin exactly what the
`nscok` flavor pins. Pinning the whole chain keeps the pin set valid across a
leaf rotation; when the host changes its issuing chain, `build.sh` rewrites
the file from the live chain (and `pins.sh` lets you check the pins by hand):

```sh
./pins.sh example.com             # <pin>  <subject>, one per certificate
./build.sh --host example.org     # pin another host instead
```

The pin for a certificate is `base64(SHA-256(DER SubjectPublicKeyInfo))`, the
definition shared by Network Security Config and OkHttp.

## Build and install

Needs the Android SDK (`ANDROID_HOME`, or the default install path), JDK 17+
and Gradle 8.13+ on `PATH`. No Gradle wrapper is committed (it would add a
binary); `gradle wrapper` creates one if you prefer it, and `build.sh` uses it
when present.

```sh
cd android/validation-app
./build.sh --install     # refresh pins, build all seven flavors, install them
```

`build.sh` prints the SHA-256 of every APK it built. No prebuilt APK is
committed: the build is the artefact, and a reviewer rebuilds it. Without
`--install`, the APKs are under `app/build/outputs/apk/<flavor>/debug/`.
`--no-refresh` keeps the committed pins for an offline build.

Then run the matrix from the repository root:

```sh
scripts/validate-device.sh
```

## Reading the code

Five classes, about 300 lines:

- `MainActivity` picks the client for `BuildConfig.POSTURE` and shows the
  attempts; the WebView posture lives there too.
- `Fetchers` builds the three OkHttp clients (platform trust, `CertificatePinner`,
  a custom trust manager), each with no connection pool and no retry.
- `PinningTrustManager` is the hand-written pinner: platform validation first,
  then at least one pinned key in the presented chain.
- `Pins` reads the host and pins from `nsc_pinned.xml` and computes a
  certificate's pin.
- `Runner` runs three attempts on a background thread and logs them;
  `NetService` is the `:net`-process client of the `netproc` posture.

Every client honours the device's global HTTP proxy, which is how pinscan's
Android driver routes traffic; `-transparent` works as well.
