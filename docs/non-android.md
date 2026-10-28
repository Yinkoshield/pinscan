# Scanning anything else (`-driver manual`)

The methodology is not Android-specific. The `manual` driver scans **any TLS
client** you can (a) make trust the research CA and (b) point at the proxy — a
desktop application, a server-side SDK, a CLI, an IoT device. Everything
downstream (the three waves, the classifier, confidence, capture, report and
gates) is identical to an Android scan.

pinscan automates nothing on the client in this mode. It prints what to do and
holds each wave's window open while **you** exercise the client.

## How it works

```sh
pinscan scan -driver manual -window 30s my-service
```

pinscan prints, to stderr:

```
manual driver: scanning "my-service".
Make the client trust the research CA before scanning:
  /Users/you/.pinscan/ca.pem

Point the client at the HTTP proxy 192.168.1.5:8080 — e.g. HTTPS_PROXY=http://192.168.1.5:8080.
Exercise the client now — make it perform its HTTPS requests. Capturing for 30s...
```

While that window is open, drive the client so it makes its HTTPS requests. Each
wave opens its own window, so **exercise the client in every window** — a
continuously-running client (a loop, a service under load) covers them all.

For raw-TLS routing instead of an HTTP proxy, add `-transparent`; pinscan then
tells you to redirect the client's `tcp/443` to the proxy (iptables/pf DNAT or a
VPN), and reads the host from the SNI.

## Two things you must do

1. **Trust the CA in the client's own trust store.** The CA is the one pinscan
   signs with (`pinscan ca-new` creates `~/.pinscan/ca.pem`, or your `-ca`).
   Trusting it is client-specific:
   - `curl`: `--cacert ~/.pinscan/ca.pem`
   - Python `requests`: `REQUESTS_CA_BUNDLE=/path/ca.pem` or `verify=`
   - Node.js: `NODE_EXTRA_CA_CERTS=/path/ca.pem`
   - Java/JVM: import into the JVM/app truststore
   - Go: add it to the client's `tls.Config.RootCAs`
   A client that does its own pinning (ignores the system trust store) will be
   classified `spki` / `key-pinned` — which is the point.
2. **Route its traffic to the proxy** — the `HTTPS_PROXY`/routing line pinscan
   printed.

## Worked example — a curl client

Terminal 1 — run the scan (two waves, 8s each here):

```sh
pinscan scan -driver manual -host-ip 127.0.0.1 -window 8s -explain example-curl
```

Terminal 2 — drive curl through the proxy, trusting the CA, for the duration:

```sh
end=$((SECONDS+20))
while [ $SECONDS -lt $end ]; do
  curl -s --max-time 3 \
    --cacert ~/.pinscan/ca.pem \
    --proxy http://127.0.0.1:8080 \
    https://example.com/ -o /dev/null
  sleep 1
done
```

A client that trusts the CA accepts the forged certificate and is reported
interceptable — exactly as an unpinned app would be.

## What the manual driver can and cannot do

- **Can**: classify any TLS client's pinning posture, capture what interceptable
  hosts expose, and produce the same reports and CI gates as an Android scan.
- **Cannot**: set up CA trust or routing for you, or restart the client between
  waves. That's the operator's job — which is why it is called *manual*.

## Where this fits

The Android driver is one implementation of the `scan.Target` interface; the
manual driver is another (see [architecture](architecture.md)). Adding a new
automated target — a different OS, an emulator harness, a test fixture — is a
matter of implementing that interface; the measurement core does not change.
