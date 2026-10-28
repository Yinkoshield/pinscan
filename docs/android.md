# Scanning Android

The default driver (`-driver android`) drives a connected, **rooted** Android
device over `adb` from a host on the same LAN. The device makes its TLS
connections to pinscan's proxy, which presents the forged certificates.

Always start with `pinscan doctor <package>` — it checks everything below and
prints a fix for anything missing.

## Prerequisites

### On the host

- **`adb`** on `PATH` (Android platform-tools).
- A **research CA** as a PEM bundle containing both the certificate and its
  private key. Generate one with `pinscan ca-new` (default `~/.pinscan/ca.pem`),
  or pass any CA with `-ca`. The proxy signs forged certificates with this CA.
- The host must be reachable from the device over the LAN, on the proxy port
  (default 8080). Allow it through the host firewall. pinscan auto-detects the
  host's LAN IP; override with `-host-ip`.

### On the phone

- **Rooted** (e.g. Magisk). Root is needed to make the research CA trusted and,
  in transparent mode, to install an iptables rule.
- **CA trust** — the target app must trust the research CA. Pick a mode
  (details and setup below):
  - **System** (`-mode system`): the CA in the **system** trust store,
    device-wide. The self-serve path — no component from this project required.
  - **Scoped** (`-mode scoped`, the default): the CA trusted *inside the target
    app only*, via the `ykzpinscan` Zygisk module, whose source ships in this
    repo at [`android/ykzpinscan/`](../android/ykzpinscan/) together with a
    prebuilt arm64 `.so`. Building it needs the Android NDK — see
    [Scoped mode](#scoped-mode-ykzpinscan-module) below. Prefer not to build a
    module? Use system mode.
- **USB debugging** enabled and this host authorized (`adb devices` shows
  `device`, not `unauthorized`).
- The **target app installed**.
- **`iptables`** present — only for `-transparent` mode; most rooted ROMs ship
  it.

## Setting up CA trust

The proxy signs its forged certificates with the research CA (`-ca`, default
`~/.pinscan/ca.pem` — run `pinscan ca-new` to create it). The app has to trust
that CA, or every handshake fails and every host comes back `inconclusive`.

### System mode (self-serve)

The simplest, fully self-serve way to trust the research CA system-wide is to let
pinscan **generate an open Magisk module** for you — no compiled or proprietary
component, nothing you can't read:

```sh
pinscan ca-module -o pinscan-ca            # generate the module (embeds -ca)
adb push pinscan-ca /data/local/tmp/pinscan-ca
# Separate su commands — a chained `su -c '… && …'` is mangled by adb and fails.
adb shell su -c 'cp -r /data/local/tmp/pinscan-ca /data/adb/modules/pinscan-ca'
adb shell su -c 'chmod 755 /data/adb/modules/pinscan-ca/post-fs-data.sh /data/adb/modules/pinscan-ca/service.sh'
adb reboot
# then (unlock the device first — the app can't launch on a locked screen):
pinscan scan -mode system <package>
```

The generated module is a directory of plain files you can inspect before
installing:

- `system/etc/security/cacerts/<hash>.0` — the CA, named by its OpenSSL
  `subject_hash_old`. On Android ≤13 Magisk overlays this directory into
  `/system` automatically, and that alone makes the CA trusted.
- `post-fs-data.sh` — a documented no-op (`exit 0`). It exists so the module
  layout is standard; it deliberately does **not** touch the Android 14+ trust
  store, because at post-fs-data the Conscrypt APEX is not mounted yet and any
  bind mount made there is silently discarded when apexd mounts it.
- `service.sh` — the Android 14+ path, run by Magisk at `late_start`. This is
  the only script that does real work as root; what it does is described below.
- `module.prop`, `cacert.pem`, `README.md`.

Both scripts are generated verbatim by
[`internal/camodule`](../internal/camodule/camodule.go), and the copies in the
directory `ca-module` wrote are the exact bytes that will run — read them there
before you push the module. On Android 14+ `service.sh` does the following:

1. Waits for `/apex/com.android.conscrypt/cacerts` to exist (if it never does,
   this is Android ≤13 and the script logs that the `system/` overlay applies,
   then exits) and for `sys.boot_completed`.
2. Builds a replacement trust store in `/data/local/tmp/pinscan-cacerts`: every
   stock certificate copied from the APEX plus the research CA, with `root:root`
   ownership, mode 644 and the `system_file` SELinux context.
3. Bind-mounts that directory over the APEX `cacerts` directory in the global
   mount namespace **and**, with `nsenter`, inside each zygote's mount
   namespace. The second step is the one that matters: apps are forked from
   zygote and do not see mounts made later in the global namespace. Without it
   the CA is visible to `adb shell` but not to the app, and every host reads
   `inconclusive`.
4. Verifies the CA is visible from every zygote namespace and writes one result
   line (`OK:` or `FAIL:`) to `/data/local/tmp/pinscan-ca.log`. `pinscan doctor`
   performs the same check from the host.
5. Watches for two minutes and re-applies the mount if apexd re-mounts the APEX
   or zygote restarts. It never rebuilds the directory while it is mounted,
   because stripping certificates from a live trust store crashes
   `system_server` and triggers a RescueParty reboot.

It touches nothing outside the Conscrypt trust store, the two files under
`/data/local/tmp` named above, and the module directory itself. `-mode system`
keeps no runtime component — delete the module directory and reboot to fully
revert. The `module.prop` it ships alongside is equally plain:

```ini
id=pinscan-ca
name=pinscan research CA (system trust)
version=v1
versionCode=1
author=generated by pinscan
description=Trusts a research CA system-wide for authorized TLS-pinning assessment. Remove when finished.
```

Prefer a maintained community system-CA module? That works too — the only
requirement is that the research CA ends up in the system store under its
`<hash>.0` name. Reboot, then confirm with `pinscan doctor` and a short scan; if
hosts come back `inconclusive`, the app isn't trusting the CA yet.

`-mode system` needs no pinscan-specific *runtime* component (the generated
module is yours to keep or remove); `pinscan doctor` skips the scoped-module
check in this mode.

### Scoped mode (`ykzpinscan` module)

Scoped mode trusts the CA inside **only the target app** — cleaner than system
mode, since no other app's trust store changes. It uses the `ykzpinscan` Zygisk
module, whose source ships in this repo at
[`android/ykzpinscan/`](../android/ykzpinscan/) (C++ source, scripts, a build
file, and a prebuilt arm64 `.so` — nothing proprietary). Build it, drop your CA
into its `cacerts/`, install, and target the app:

```sh
cd android/ykzpinscan
./build.sh                                             # or use the prebuilt zygisk/arm64-v8a.so
pinscan ca-module -o /tmp/pinscan-ca                   # your research CA, as <hash>.0
cp /tmp/pinscan-ca/system/etc/security/cacerts/*.0 cacerts/
adb push . /data/local/tmp/ykzpinscan
# Run these as SEPARATE su commands — a chained `su -c '… && …'` is mangled by adb.
adb shell su -c 'rm -rf /data/adb/modules/ykzpinscan'
adb shell su -c 'cp -r /data/local/tmp/ykzpinscan /data/adb/modules/ykzpinscan'
adb shell su -c 'chmod 755 /data/adb/modules/ykzpinscan/*.sh'
adb reboot
# After the reboot, UNLOCK the device — the app can't be launched on a locked
# screen (wave A fails with a monkey "exit status 252").
pinscan scan -mode scoped com.example.app              # sets the target + scans
```

At app fork the module bind-mounts your CA over the Conscrypt trust store for the
listed package only. Full build/install/removal detail is in
[`android/ykzpinscan/README.md`](../android/ykzpinscan/README.md). Prefer not to
build a module? **System mode** above is the zero-build path.

## Finding the app's package name

`scan` and `doctor` take the Android **package name**, not the display name.
List what's installed:

```sh
adb shell pm list packages -3            # user-installed apps only
adb shell pm list packages | grep -i bank # filter by keyword
```

Each line is `package:<name>`. For the app currently in the foreground:

```sh
adb shell dumpsys activity activities | grep -i ResumedActivity
```

## Routing: proxy vs transparent

pinscan has to get the app's TLS traffic to its proxy. Two ways:

- **Global HTTP proxy** (default). pinscan sets the device's `http_proxy`; the
  app issues `CONNECT` and pinscan terminates TLS. Works for apps that honour
  the system proxy (most do).
- **Transparent** (`-transparent`). Some apps ignore the system proxy. pinscan
  installs a root **iptables DNAT**, scoped to the target app's UID, redirecting
  its `tcp/443` to the proxy; the host is read from the TLS SNI. Because the
  proxy speaks TCP only, pinscan also refuses the app's QUIC (`udp/443`) and,
  when `ip6tables` is present, its IPv6 port 443, so the app falls back to IPv4
  TCP and is captured instead of escaping; a host reachable only over IPv6 or
  QUIC is refused, not captured; without `ip6tables` pinscan warns that IPv6
  TLS is not blocked. TLS on ports other than 443 is not redirected.
  All rules are removed on teardown. A bonus: because every rule is UID-scoped,
  transparent mode captures **only the target app**, not other apps or the
  system.

pinscan restores the proxy / removes its rules when the scan ends, even if
interrupted.

## Running a scan

```sh
# Simple posture scan (scoped CA, HTTP proxy, 60s per wave):
pinscan scan com.example.app

# Longer window, explain each verdict:
pinscan scan -window 45s -explain com.example.app

# Catch apps that ignore the proxy:
pinscan scan -transparent com.example.app

# See what interceptable hosts expose (startup/unauthenticated surface only):
pinscan scan -capture com.example.app
```

## Mobile-specific notes

- **Scan window.** Each wave restarts the app and watches for `-window` seconds.
  Give the app enough time to make its startup connections; 30–60s is typical.
- **Hosts vary between runs.** Background services (Google connectivity checks,
  push, telemetry) come and go, so the exact host list differs per run. The
  app's own hosts are stable. A host that isn't contacted in a run shows up as
  `inconclusive` (not a pass).
- **Capture is for the startup / unauthenticated surface only.** Do not point
  `-capture` at an authenticated flow. Credential headers are redacted and
  bodies capped regardless, as defence in depth — see [output](output.md).
- **Battery / doze.** Keep the screen on during a scan so the app isn't frozen.

## What pinscan changes on the device, and cleans up

| Action | When | Reverted |
|--------|------|----------|
| writes `/data/adb/ykzpinscan/targets` | scoped mode, each scan | left in place (harmless; names the app) |
| `settings put global http_proxy <host:port>` | proxy routing | reset to `:0` on teardown |
| `iptables -t nat -A OUTPUT … DNAT` (UID-scoped) | transparent routing | deleted on teardown |
| `iptables -I OUTPUT … udp/443 REJECT` and, with `ip6tables`, `ip6tables -I OUTPUT … 443 REJECT` (UID-scoped) | transparent routing | deleted on teardown |
| `am force-stop` + `monkey` launch | each wave | — |

It never installs the module or the CA for you — that is the one-time setup
above, which `doctor` checks.
