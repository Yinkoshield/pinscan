# ykzpinscan — scoped-mode Zygisk module

The Zygisk module behind `pinscan scan -mode scoped`. It trusts your research CA
inside **only the app(s) you name**, so the pinscan proxy's forged certificates
are accepted at the trust-store layer and any TLS rejection the proxy sees is a
pinning check *above* the trust store — the signal pinscan classifies.

It is the per-app alternative to **system mode** (`pinscan ca-module`, which
trusts the CA device-wide). Scoped mode is cleaner — other apps are untouched —
but needs this module installed.

> **Authorized assessment only.** This changes certificate trust inside an app
> you are authorized to test, on a device you control. Don't point it at
> software or users you have no permission to assess.

## How it works

At `preAppSpecialize` — still uid 0 with `CAP_SYS_ADMIN`, before the app is
specialised — the module checks the forking app's package against
`/data/adb/ykzpinscan/targets`. For a listed package it unshares the mount
namespace and bind-mounts a prepared trust store (the device's real roots plus
your CA) over the read-only Conscrypt APEX cacerts dir. Non-target apps are
untouched and the library detaches. Nothing persists past the app fork.

Files: [`jni/pinscan.cpp`](jni/pinscan.cpp) (the module), `service.sh` (builds
the trust store at boot), `post-fs-data.sh` + `apply-sepolicy.sh` +
`sepolicy.rule` (SELinux rules for the bind), `set-target.sh` (host helper to
set the target package), `cacerts/` (where your CA goes).

## Build

Needs the Android NDK and a Magisk/Zygisk device. The prebuilt `zygisk/arm64-v8a.so`
in this directory is produced from `jni/pinscan.cpp` by:

```sh
./build.sh        # or: ANDROID_NDK_HOME=/path/to/ndk ./build.sh
```

Rebuild it yourself to verify it matches the source. Only `arm64-v8a` is shipped
prebuilt; add other ABIs in `jni/Application.mk`.

Prebuilt file as committed, for comparison after your own build:

```
SHA-256  bf683cdd1dcd4b095796e1d35b223b5a80679ab466709596a3727607e36a5865  zygisk/arm64-v8a.so
```

Built with NDK r27 (`27.2.12479018`, clang 18.0.3). A different NDK produces a
different binary, so a byte mismatch is expected across versions; a mismatch
with the same NDK is not. Any change to `jni/` must ship a rebuilt `.so`, with
the new hash recorded here and in the pull request.

## Install

```sh
# 1. Put your research CA in cacerts/ (see cacerts/README.md):
pinscan ca-module -o /tmp/pinscan-ca
cp /tmp/pinscan-ca/system/etc/security/cacerts/*.0 cacerts/

# 2. Push the module and install it. Run the su steps as SEPARATE commands — a
#    single chained/line-continued `su -c '… && …'` gets mangled by adb's shell
#    and fails at `cp`.
adb push . /data/local/tmp/ykzpinscan
adb shell su -c 'rm -rf /data/adb/modules/ykzpinscan'
adb shell su -c 'cp -r /data/local/tmp/ykzpinscan /data/adb/modules/ykzpinscan'
adb shell su -c 'chmod 755 /data/adb/modules/ykzpinscan/*.sh'
adb reboot

# 3. Unlock the device after the reboot (the app can't launch on a locked
#    screen), then point the module at the app under test:
./set-target.sh com.example.app

# 4. Scan:
pinscan scan -mode scoped com.example.app
```

Verify with `pinscan doctor com.example.app`. If hosts come back `inconclusive`,
the app isn't trusting the CA yet — check `/data/adb/modules/ykzpinscan/log.txt`
and that your CA landed in `cacerts/`.

`pinscan scan -mode scoped <package>` also sets the target for you, so step 3 is
optional unless you want to launch the app yourself.

## Remove

```sh
adb shell su -c 'rm -rf /data/adb/modules/ykzpinscan /data/adb/ykzpinscan'
adb reboot
```

Scoped mode leaves no other on-device state.

## Licensing

Module code is Apache-2.0 with the rest of pinscan. `jni/zygisk.hpp` is the
upstream Zygisk API header (© John "topjohnwu" Wu, ISC-style permissive license);
its notice is kept in the file.
