# Trying pinscan on an emulator

You can exercise pinscan end-to-end on an Android emulator — no physical device,
no Magisk — which is the easiest way to learn the tool and to see CA trust take
effect. This walkthrough was run as-is on an Android 13 (API 33) arm64 Google
APIs image.

The one difference from a phone: an emulator has no Magisk, so you install the
research CA into the system store with `adb root` + `adb remount` instead of
flashing the `ca-module` output. The cert itself — name, placement, content — is
exactly what `pinscan ca-module` produces; you're just delivering it a different
way. On a physical device you flash the module (see [android.md](android.md)).

## 1. Pick a rootable, pre-APEX image

Use a **`google_apis`** image (not `google_apis_playstore` — Play images are not
rootable) at **API ≤ 33** (Android ≤ 13), where system CAs live in
`/system/etc/security/cacerts`. Match your host CPU (arm64 on Apple Silicon,
x86_64 on Intel).

```sh
export ANDROID_SDK_ROOT=$HOME/Library/Android/sdk
sdkmanager "system-images;android-33;google_apis;arm64-v8a"
avdmanager create avd -n pinscan-emu -k "system-images;android-33;google_apis;arm64-v8a" -d pixel
```

## 2. Boot with a writable system

```sh
emulator -avd pinscan-emu -writable-system -no-snapshot &
adb wait-for-device
# (use `adb -s emulator-5554 …` if a physical device is also attached)
```

## 3. Install the research CA into the system store

Generate the cert file with `ca-module`, then push it into the system store:

```sh
pinscan ca-new                           # once: creates the research CA (~/.pinscan/ca.pem)
pinscan ca-module -o pinscan-ca          # produces system/etc/security/cacerts/<hash>.0 from it
adb root
adb remount
HASH_FILE=$(ls pinscan-ca/system/etc/security/cacerts/*.0)
adb push "$HASH_FILE" /data/local/tmp/ca.0
adb shell "cp /data/local/tmp/ca.0 /system/etc/security/cacerts/$(basename "$HASH_FILE") && \
  chmod 644 /system/etc/security/cacerts/$(basename "$HASH_FILE") && \
  restorecon /system/etc/security/cacerts/$(basename "$HASH_FILE")"
adb reboot            # let the writable-system overlay settle
adb wait-for-device
```

After reboot the cert persists with the correct SELinux context
(`u:object_r:system_security_cacerts_file:s0`) and is trusted system-wide. (On a
phone, `pinscan ca-module` + flashing the module in Magisk does the same thing,
and survives reboots as a module overlay.)

## 4. Route the emulator at pinscan and scan

The emulator reaches your host at the special address **`10.0.2.2`**. Point the
emulator's proxy there and scan with the `manual` driver (an emulator has no
`su`, so the android driver's root-shell path does not apply; the manual driver
fits, and the methodology is identical):

```sh
adb shell settings put global http_proxy 10.0.2.2:8080
pinscan scan -driver manual -host-ip 10.0.2.2 -window 20s -explain emulator-chrome
```

Inside the emulator `10.0.2.2` is an alias for the host's loopback interface, so
with `-host-ip 10.0.2.2` pinscan binds the proxy to `127.0.0.1` only: the
emulator reaches it and the rest of your network does not.

In each wave's window, drive a TLS client. Chrome (`com.android.chrome`, present
on Google APIs images) honours the system proxy and the system CA store:

```sh
for i in $(seq 1 20); do
  adb shell am start -a android.intent.action.VIEW -d "https://example.com/?t=$i" >/dev/null
  sleep 3
done
```

## 5. Read the result

```
clientservices.googleapis.com     open   conf=medium   <- interceptable
optimizationguide-pa.googleapis.com  open   conf=medium  <- interceptable

2 host(s): 2 interceptable, 0 inconclusive (not verified), 0 hardened
```

`open` here is the proof that trust took effect: the client **accepted**
certificates pinscan minted under the research CA, which it only does because
that CA is now in the system store. Remove the CA (delete the `<hash>.0` file, or
uninstall the module on a phone) and the same hosts go back to `inconclusive` —
the client no longer trusts the forged certificate.

## See the actual intercepted traffic (`-capture`)

A verdict says "accepted"; `-capture` shows the decrypted bytes behind it, so you
can see it is real interception and not a mislabel. Add `-capture` and re-run:

```sh
pinscan scan -driver manual -host-ip 10.0.2.2 -capture -window 20s emulator-chrome
```

Captured from the emulator's Chrome hitting `https://example.com` — a real,
decrypted request/response (bodies are decompressed, including Chrome's brotli):

```
== example.com ==
  GET /?t=19 -> 200  text/html; charset=utf-8  (577 bytes)
    <!doctype html><html lang=en><head><meta charset=utf-8>...<title>Example Domain</title>
    ...<p>This domain is for use in documentation examples without needing
    permission...</p><script src=/s.js></script></body></html>
```

Credential headers are redacted and bodies capped (see
[output](output.md#captured-exchanges)); point `-capture` only at the startup /
unauthenticated surface.

## 6. Clean up

```sh
adb shell settings put global http_proxy :0
adb emu kill
avdmanager delete avd -n pinscan-emu     # optional
```

## Notes

- **Android 14+ (API 34+)** moved the trust store into the read-only Conscrypt
  APEX; the simple `/system` remount no longer applies. That is exactly what the
  `ca-module` `service.sh` handles on a real (Magisk) device, including the
  per-zygote mount-namespace step — what it does is described in
  [Scanning Android](android.md#system-mode-self-serve). For a quick emulator
  try, stick to API ≤ 33.
- **No acceleration?** The emulator needs host virtualization (HVF on macOS, KVM
  on Linux); check with `emulator -accel-check`. Without it an image will not
  boot usefully.
- This path also demonstrates the **manual driver** against a real Android TLS
  client (Chrome), not just a desktop client.
