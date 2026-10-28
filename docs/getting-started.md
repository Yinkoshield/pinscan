# Getting started

A complete walkthrough, assuming you've not done this before. By the end you'll
have scanned a real app and understood the result.

> **Authorized testing only.** pinscan changes certificate trust on a device you
> control, to assess an app you're allowed to assess. Don't point it at software
> or people you have no permission to test.

## What pinscan does (30 seconds)

pinscan runs a tiny man-in-the-middle proxy and makes the app under test connect
through it. The proxy presents **forged TLS certificates** signed by a *research
CA* you control. For each host the app talks to, pinscan watches what happens and
assigns a **verdict**:

- `open` — the app accepted the forged cert: **interceptable** (no effective pinning).
- `metadata` / `name-validation` — weak checks a trusted-CA attacker still defeats: interceptable.
- `key-pinned` / `spki` — the app pinned the real key and **rejected** the forgery: hardened.
- `inconclusive` — the app made no classifiable request; no signal (never read as "safe").

For the app to *accept* the forgery, it must **trust your research CA**. Most of
this guide is about establishing that trust safely on a device you own.

## What you'll need

- A computer with **Go 1.26+** (an older Go 1.21+ downloads the right toolchain
  automatically on first build).
- A **research CA** (a cert + private key) — pinscan creates one for you (step 3).
- To scan an Android app: a **rooted phone** (Magisk) with **Zygisk** enabled,
  the app installed, and USB debugging on. No phone? You can still try pinscan
  device-free (see step 7) or against a desktop TLS client.

---

## 1. Install pinscan

```sh
go install github.com/yinkoshield/pinscan/cmd/pinscan@latest   # → onto PATH
pinscan -version
```

This installs into `$(go env GOBIN)` (or `$(go env GOPATH)/bin`) — make sure that
is on your `PATH`. From a clone, `make install` does the same, or `make build`
leaves a `./bin/pinscan` you can run in place:

```sh
make build && ./bin/pinscan -version
```

pinscan has two pinned runtime dependencies (`gopkg.in/yaml.v3` for policy files,
`github.com/andybalholm/brotli` for decoding captured bodies); `go install` pulls
them automatically.

## 2. Install adb (to talk to the phone)

`adb` ships in Android **platform-tools**:

```sh
# macOS
brew install android-platform-tools
# Debian/Ubuntu
sudo apt install android-tools-adb
# or download the platform-tools zip from developer.android.com and add it to PATH

adb version        # confirm it's on PATH
```

Skip this if you're only scanning a desktop client (see step 7).

## 3. Create your research CA

pinscan generates its own CA — no external tool required:

```sh
pinscan ca-new
```

```
wrote research CA to /Users/you/.pinscan/ca.pem
  subject: CN=pinscan research CA,O=pinscan research
  sha256:  57fd0ce0e324d24c7faf05dfca0f96e8495c4a68d7e78c06f1ee38c7b516bac7
```

That file (certificate **and** private key) is the default `-ca` for every
command. `ca-new` won't overwrite an existing CA unless you pass `-force`
(replacing it stops any device that trusted the old CA from trusting the new
one). Keep the file private — it can sign for any host.

Already have a CA you'd rather use (e.g. mitmproxy's
`~/.mitmproxy/mitmproxy-ca.pem`)? Skip `ca-new` and pass it to any command with
`-ca path.pem`.

## 4. How CA trust is established — pick a mode

The app only accepts the forgery if your research CA is in the trust store it
checks. Two ways to put it there, both needing a rooted phone:

- **System mode** — trust the CA **device-wide**. Zero compiling: `pinscan
  ca-module` generates a small, readable Magisk module you flash and reboot.
  **Start here.**
- **Scoped mode** — trust the CA **inside one app only** (cleaner, nothing else
  changes), via the `ykzpinscan` Zygisk module you **compile** from this repo.

Do step 5, then **either** step 6a (system) **or** step 6b (scoped).

## 5. Prepare the Android device

1. **Enable Developer options**: Settings → About phone → tap *Build number* 7×.
2. **USB debugging**: Settings → Developer options → enable *USB debugging*.
3. Plug in over USB and authorize this computer when prompted. Confirm:

   ```sh
   adb devices        # the device shows as "device" (not "unauthorized")
   ```

4. **Root with Magisk and enable Zygisk** (Magisk app → Settings → Zygisk → on,
   then reboot). pinscan needs root to make the CA trusted. Confirm root:

   ```sh
   adb shell su -c 'id'      # shows uid=0(root)
   ```

See [Scanning Android](android.md) for rooting/Zygisk background.

## 6a. System mode (easiest — no compiling)

```sh
pinscan ca-module -o pinscan-ca                 # generate the open trust module
adb push pinscan-ca /data/local/tmp/pinscan-ca
# install as SEPARATE su commands (a chained `su -c '… && …'` is mangled by adb):
adb shell su -c 'cp -r /data/local/tmp/pinscan-ca /data/adb/modules/pinscan-ca'
adb shell su -c 'chmod 755 /data/adb/modules/pinscan-ca/post-fs-data.sh /data/adb/modules/pinscan-ca/service.sh'
adb reboot
```

Every file it installs is plain text you can read first. On Android 14+ the
work is done by `service.sh` after boot; `post-fs-data.sh` is a no-op. Full
detail + what the module does: [android.md](android.md#system-mode-self-serve).
After the reboot, **unlock the phone**, then jump to step 7. If `doctor` later
reports the CA is not trusted, read `/data/local/tmp/pinscan-ca.log` on the
device: the module writes its own `OK:` or `FAIL:` line there.

## 6b. Scoped mode (per-app — compile the module)

The module source is in [`android/ykzpinscan/`](../android/ykzpinscan/). You need
the **Android NDK** (ships with Android Studio, or `sdkmanager "ndk;27.2.12479018"`).

```sh
cd android/ykzpinscan

# 1. Compile the Zygisk .so from source:
./build.sh                                      # if it can't find the NDK:
# ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/<version> ./build.sh

# 2. Put your research CA into the module:
pinscan ca-module -o /tmp/pinscan-ca
cp /tmp/pinscan-ca/system/etc/security/cacerts/*.0 cacerts/

# 3. Install — SEPARATE su commands (a chained `su -c '… && …'` fails via adb):
adb push . /data/local/tmp/ykzpinscan
adb shell su -c 'rm -rf /data/adb/modules/ykzpinscan'
adb shell su -c 'cp -r /data/local/tmp/ykzpinscan /data/adb/modules/ykzpinscan'
adb shell su -c 'chmod 755 /data/adb/modules/ykzpinscan/*.sh'
adb reboot
```

After the reboot, **unlock the phone** (the app can't be launched on a locked
screen — the scan would fail in wave A with a `monkey … exit status 252`). Full
detail: [module README](../android/ykzpinscan/README.md).

## 7. Check your setup with `doctor`

`doctor` verifies every prerequisite and prints the fix for anything missing. Run
it before your first scan; pass your app's package so it checks that too:

```sh
pinscan doctor com.example.app          # add -mode system if you used 6a
```

```
[ ok ] adb on PATH                      /usr/local/bin/adb
[ ok ] research CA readable             /Users/you/.pinscan/ca.pem
[ ok ] device connected                 adb state: device
[ ok ] root (su)                        id -u: 0
[ ok ] ykzpinscan module (scoped CA)    /data/adb/modules/ykzpinscan
[ ok ] target app installed             com.example.app
[ ok ] iptables                         iptables

all required prerequisites met
```

Don't know the app's **package name** (not its display name)? List installed
apps: `adb shell pm list packages -3` (see [android.md](android.md#finding-the-apps-package-name)).

No rooted phone? You can still see pinscan work:

- `pinscan selftest` — device-free proof of the methodology (step 8).
- Scan a desktop/other TLS client with the **manual** driver: [non-android.md](non-android.md).
- Try it on an **emulator**: [emulator.md](emulator.md).

## 8. Run your first scan

> Flags may come **before or after** the target — both
> `pinscan scan -window 30s com.example.app` and
> `pinscan scan com.example.app -window 30s` work.

```sh
pinscan scan com.example.app            # add -mode system if you used 6a
```

```
api.example.com                              spki           conf=high
cdn.example.com                              open           conf=high    <- interceptable

2 host(s): 1 interceptable, 0 inconclusive (not verified), 1 hardened
```

Read it as: each host's **verdict** + a **confidence**; the tally counts how many
are interceptable vs hardened vs inconclusive. `<- interceptable` marks the hosts
a trusted-CA attacker could read. What each verdict means: [methodology](methodology.md).

If hosts come back `inconclusive`, the app isn't trusting your CA yet (redo step
6) or made no request in the window — and if the scan errors at wave A, unlock the
phone. More fixes: [troubleshooting](troubleshooting.md).

## 9. See more, and share it

```sh
pinscan scan com.example.app -explain                 # a plain-language line per verdict
pinscan scan com.example.app -capture                 # show what interceptable hosts expose
pinscan scan com.example.app -capture-out traffic.har # dump all captured traffic
pinscan scan com.example.app -report scan.html        # a shareable artifact
```

Full flag list: [command reference](commands.md). Output formats and the capture
redaction rules: [output.md](output.md).

## 10. Prove the methodology (no device needed)

```sh
pinscan selftest
```

This stands up known-posture TLS clients in-process, runs the real waves through
them, and asserts each verdict — a device-free demonstration that the
no-pinning / metadata / name-validation / SPKI separation holds. It's also a
required CI check.

## 11. Clean up

```sh
adb shell settings put global http_proxy :0     # clear the proxy pinscan set
# scoped module: adb shell su -c 'rm -rf /data/adb/modules/ykzpinscan /data/adb/ykzpinscan' && adb reboot
# system module: adb shell su -c 'rm -rf /data/adb/modules/pinscan-ca' && adb reboot
```

pinscan restores routing itself after each scan; the above removes the CA-trust
module when you're done so the device stops trusting the research CA.

## Next

- Understand what a verdict means: [methodology](methodology.md).
- Scan deeply on Android (modes, transparent routing, package names): [android.md](android.md).
- Wire it into CI with pass/fail gates: [CI integration](ci.md).
- Scan a non-Android client: [scanning anything else](non-android.md).
- Something broke: [troubleshooting](troubleshooting.md).
