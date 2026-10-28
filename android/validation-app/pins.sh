#!/usr/bin/env bash
# pins.sh — print the SPKI pin of every certificate a host presents, as Network
# Security Config and OkHttp define it: base64(SHA-256(DER SubjectPublicKeyInfo)).
#
#   ./pins.sh example.com            # one line per certificate: <pin> <subject>
#   ./pins.sh example.com 443 --pins # pins only, comma-separated
#
# Needs openssl. The chain is read live, so run it on a network that reaches
# the host directly (not through the pinscan proxy).
set -euo pipefail

host=${1:?usage: pins.sh <host> [port] [--pins]}
port=${2:-443}
mode=${3:-}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

openssl s_client -connect "$host:$port" -servername "$host" -showcerts </dev/null 2>/dev/null \
  | awk -v dir="$tmp" '/-----BEGIN CERTIFICATE-----/{n++; inside=1} inside{print >> (dir "/" n ".pem")} /-----END CERTIFICATE-----/{inside=0}'

count=$(find "$tmp" -name '*.pem' | wc -l | tr -d ' ')
if [ "$count" -eq 0 ]; then
  echo "pins.sh: no certificate received from $host:$port" >&2
  exit 1
fi

pins=()
subjects=()
for i in $(seq 1 "$count"); do
  f="$tmp/$i.pem"
  pin=$(openssl x509 -in "$f" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64)
  subject=$(openssl x509 -in "$f" -noout -subject | sed 's/^subject= *//')
  pins+=("$pin")
  subjects+=("$subject")
done

if [ "$mode" = "--pins" ]; then
  IFS=,; echo "${pins[*]}"
else
  for i in "${!pins[@]}"; do
    printf '%s  %s\n' "${pins[$i]}" "${subjects[$i]}"
  done
fi
