# Troubleshooting

Run `pinscan doctor <package>` first — it diagnoses most setup problems and
prints the fix. The rest are behaviours worth understanding.

## "usage: pinscan scan <package> [flags]" even though I passed a package

You passed more than one positional argument — pass exactly one `<package>`.
Flags may appear before or after it, so both of these work:

```sh
pinscan scan com.example.app -window 30s   # ✓
pinscan scan -window 30s com.example.app   # ✓
```

## The scan looks stuck after "wave started"

It isn't — that's the **scan window**. The default is `-window 1m0s` **per wave**,
and each wave sits capturing for that long. You'll see a
`scanning window — capturing traffic` line with the duration, then
`wave finished` when it ends. A full run is wave A, wave B, and (only if a host
looks key-pinned) wave C — so up to ~3 minutes at the default.

To go faster while trying things out, shorten the window; add `-debug` to see
every step:

```sh
pinscan scan -window 15s -debug com.example.app
```

Use a longer window for a thorough run so the app has time to make all its
startup connections.

## `doctor` says the module / CA is missing

- **`ykzpinscan module (scoped CA)` FAIL** — install the Zygisk module at
  `/data/adb/modules/ykzpinscan` and reboot, or use `-mode system` with the CA
  in the system trust store. See [Scanning Android](android.md).
- **`research CA readable` FAIL** — generate a CA with `pinscan ca-new` (it
  writes the default `~/.pinscan/ca.pem`), or point `-ca` at any PEM bundle
  containing **both** the certificate and its private key (pinscan signs with it).
- **`root (su)` FAIL** — the device must be rooted; pinscan needs root to make
  the CA trusted.

## Every host comes back `inconclusive`

`inconclusive` means pinscan saw no classifiable request, or saw rejections it
is not allowed to trust. Read the line after the tally first:

- **`research CA trust: UNVERIFIED; N hardened verdict(s) withheld`** — the
  hosts rejected the forged certificates, but pinscan could not confirm the app
  trusts the research CA, and an untrusted CA produces exactly the same
  rejections as pinning. Run `pinscan doctor <package>` (system mode: the CA
  must be trusted in every zygote namespace; scoped mode: the app must be
  running with the `ykzpinscan` module active for it). If `scan` stops with
  "the research CA is not trusted", that is the same cause, caught earlier.
- **Window too short** — the app didn't finish its startup connections. Raise
  `-window` (e.g. `-window 60s`) and keep the screen on.
- **App ignores the HTTP proxy** — try `-transparent` (needs `iptables` + root).
- **Scoped mode, no process to inspect** — the app exited right after launch
  (root detection, crash). Trust stays unverified and nothing is observed.
- **Host-not-reachable from the device** — the device must reach `-host-ip` on
  the proxy port over the LAN; check the host firewall.

`inconclusive` is deliberate: pinscan will not report "hardened" when it saw
nothing, nor when the test setup itself could explain the rejections (see
[methodology](methodology.md#the-honesty-rules--never-secure-from-silence)).

## A host I expected to be pinned shows `open`

That is the finding: the app sent a request over a forged certificate signed by
the injected CA. Confirm with `-capture` what that host exposes, and with
`-explain` the mechanism. If instead it shows `inconclusive`, the app may pin at
the application layer (handshake completes, no request follows) — pinscan
reports that as inconclusive, not a false `open`.

## `scan` exits non-zero but found no interceptable hosts

Check which gate fired — the message names it, and the [exit code](ci.md#exit-codes)
tells you the class:

- `2` operational — the scan could not complete (device/adb/CA/proxy). Not a
  posture failure; retry or re-check `doctor`.
- `3` policy — an interceptable host or an unmet `expect:`.
- `4` regression — weaker than the baseline.
- `5` incomplete — inconclusive hosts (`-fail-on-inconclusive`) or below
  `-min-confidence`.

## `-min-confidence high` fails on a host that looks fine

A verdict backed by a single observation is `medium`; `key-pinned` is capped at
`medium`; a host that conflicted or was inconclusive is `low`. Raise `-window`
so the deciding wave gets multiple consistent attempts, or lower the threshold.
See [confidence](methodology.md#confidence).

## Transparent mode changed which hosts appear

Expected. The DNAT is scoped to the target app's UID, so transparent mode
captures **only** that app — system/background hosts (connectivity checks, push)
that the global-proxy mode swept in no longer appear.

## Manual driver: nothing was recorded

The `manual` driver doesn't drive the client for you. You must exercise the
client **in each wave's window** (each wave opens a new one). A continuously
running client covers them all. Confirm the client trusts the CA and is actually
routed through the proxy. See [Scanning anything else](non-android.md).

## The device is left with a proxy / iptables rule after a crash

pinscan restores routing on teardown, including after Ctrl-C. If a hard kill
left state behind:

```sh
adb shell settings put global http_proxy :0
```

and, after a transparent scan, delete pinscan's leftover rules: the
UID-scoped port-443 DNAT and the QUIC and IPv6 refusals. Only rules matching
that shape are touched, so the system's own chains stay intact; a missing
`ip6tables` just prints `not found`.

```sh
adb shell "su -c 'for t in \"iptables -t nat\" iptables ip6tables; do \$t -S OUTPUT | grep -e \"--dport 443 \" | grep -e \"--uid-owner \" | grep -e \"-j DNAT\" -e \"-j REJECT\" | sed s/^-A/-D/ | while read -r r; do \$t \$r; done; done'"
```

## `device: "monkey … LAUNCHER": … exit status 252` (scan fails in wave A)

pinscan launches the target app to generate traffic, and the launcher can't
foreground an app while the screen is **locked** — common right after a reboot.
Wake and unlock the device, then rescan:

```sh
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard        # only clears a swipe lock, not a PIN
```

For a PIN/pattern/password lock, unlock the phone by hand first. Scoped mode in
particular needs a reboot to load the module, so unlock before the first scan.

## Scoped mode: `set-target.sh` says "Permission denied"

`pinscan scan -mode scoped <package>` sets the target itself (over adb, as root)
— you don't need to run `set-target.sh` first. If you do run it by hand and hit a
redirect error, it's a shell-quoting artifact of your own `adb shell su -c '… >
file'` invocation, not a device lock; pinscan's own path writes
`/data/adb/ykzpinscan/targets` fine (confirm with `adb shell su -c 'cat
/data/adb/ykzpinscan/targets'` after a scan).
