#!/usr/bin/env bash
# validate-device.sh — run the pinscan validation matrix (docs/validation.md)
# against the connected, rooted device: `pinscan doctor`, then one scan per
# posture of the validation app (android/validation-app), each written as a
# JSON report under validation/<UTC date-time>/, and compare every verdict and
# ca_trust with the matrix. Prints a pass/fail table; exits non-zero on any
# mismatch.
#
# Usage: scripts/validate-device.sh [-m scoped|system] [-w 20s] [-c ca.pem]
#                                   [-b bin/pinscan] [-o validation] [-H host]
#                                   [-r row,row,...] [-t] [-l] [-h]
#   -m  CA-trust mode passed to pinscan (default: scoped)
#   -w  scan window per wave (default: 20s; the app finishes its attempts in ~5s)
#   -c  research CA PEM bundle (default: ~/.pinscan/ca.pem)
#   -b  pinscan binary (default: bin/pinscan, built with go if missing)
#   -o  output root; this run writes to <root>/<UTC date-time>/ (default: validation)
#   -H  validation host (default: the <domain> in the app's nsc_pinned.xml)
#   -r  run only these rows, comma-separated (see -l)
#   -t  pass -transparent to pinscan
#   -l  list the rows with their expectations and exit
#
# Every root step is its own `adb shell su -c '…'`: a chained `su -c '… && …'`
# is mangled by adb. Exit status: 0 when every row matches, 1 on any mismatch,
# 2 when the kit could not run (doctor failed, app not installed, tool missing).
set -euo pipefail

cd "$(dirname "$0")/.."

MODE=scoped
WINDOW=20s
CA=${PINSCAN_CA:-$HOME/.pinscan/ca.pem}
PINSCAN=bin/pinscan
OUT_ROOT=validation
HOST=""
ROWS=""
TRANSPARENT=""
PKG_BASE=com.yinkoshield.pinscan.validation
NSC_PINNED=android/validation-app/app/src/main/res/xml/nsc_pinned.xml

ALL_ROWS="nopin nsc-correct nsc-wrong okhttp trustmanager webview netproc ca-absent ca-wrong-subject"

usage() { sed -n '2,25p' "$0"; }

# row_spec prints "<flavor>|<expected verdict>|<expected ca_trust>|<accepted exit codes>|<CA variant>|<why>"
# for a row. A "-" verdict means no report is expected (the scan must refuse).
row_spec() {
  case "$1" in
    nopin)            echo "nopin|open|verified|0|real|HttpsURLConnection, no pins: sends a request over the generic forged leaf" ;;
    nsc-correct)      echo "nscok|spki|verified|0|real|NSC pin set with the real chain: certificate alert in every wave, C included" ;;
    nsc-wrong)        echo "nscwrong|spki|verified|0|real|NSC pin set with a bogus pin: rejects every chain; indistinguishable from a correct pin set" ;;
    okhttp)           echo "okhttp|inconclusive|verified|0|real|CertificatePinner checks after the handshake: handshake_ok_no_request, never a certificate alert" ;;
    trustmanager)     echo "trustmanager|spki|verified|0|real|custom X509TrustManager pins inside the handshake: certificate alert in every wave" ;;
    webview)          echo "webview|open|verified|0|real|WebView, no pins: sends a request over the generic forged leaf" ;;
    netproc)
      if [ "$MODE" = scoped ]; then
        echo "netproc|inconclusive|unverified|0 2|real|TLS from a :net process the module does not bind: an unpinned client must not read hardened (see VAL-1)"
      else
        echo "netproc|open|verified|0|real|TLS from a :net process; system-mode trust is device-wide, so it reads like nopin"
      fi ;;
    ca-absent)        echo "nopin|-|-|2|absent|a research CA the device does not hold: pinscan must refuse to scan (exit 2), not report hardened" ;;
    ca-wrong-subject) echo "nopin|-|-|2|wrong-subject|a different CA with the same subject name (same <hash>.0 file name): refused by content, not by name" ;;
    *) return 1 ;;
  esac
}

list_rows() {
  printf '%-18s %-14s %-13s %-11s %-5s %s\n' ROW FLAVOR VERDICT CA_TRUST EXIT WHY
  for row in $ALL_ROWS; do
    IFS='|' read -r flavor verdict trust exits _ why <<<"$(row_spec "$row")"
    printf '%-18s %-14s %-13s %-11s %-5s %s\n' "$row" "$flavor" "$verdict" "$trust" "$exits" "$why"
  done
}

while getopts 'm:w:c:b:o:H:r:tlh' opt; do
  case "$opt" in
    m) MODE=$OPTARG ;;
    w) WINDOW=$OPTARG ;;
    c) CA=$OPTARG ;;
    b) PINSCAN=$OPTARG ;;
    o) OUT_ROOT=$OPTARG ;;
    H) HOST=$OPTARG ;;
    r) ROWS=${OPTARG//,/ } ;;
    t) TRANSPARENT=-transparent ;;
    l) list_rows; exit 0 ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
case "$MODE" in scoped|system) ;; *) echo "validate-device: -m must be scoped or system" >&2; exit 2 ;; esac
[ -n "$ROWS" ] || ROWS=$ALL_ROWS
for row in $ROWS; do row_spec "$row" >/dev/null || { echo "validate-device: unknown row '$row' (see -l)" >&2; exit 2; }; done

# ---- helpers ---------------------------------------------------------------

say()  { printf '%s\n' "$*"; }
die()  { printf 'validate-device: %s\n' "$*" >&2; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }

# root runs one command as root on the device. One su -c per call, always.
root() { adb shell su -c "'$*'"; }

# json_host_field prints a host's verdict (field 1), confidence (2) or per-wave
# evidence (3) from a report; json_trust prints scan.ca_trust. jq if present,
# else python3.
json_host_field() { # <report> <host> <field>
  if have jq; then
    jq -r --arg h "$2" --argjson f "$3" '
      .hosts[] | select(.host == $h) |
      if $f == 1 then .verdict
      elif $f == 2 then .confidence
      else ([.waves[] | "\({generic: "A", cloned: "B", issuer: "C"}[.wave] // .wave)=\(.outcome)/\(.reason)"] | join(" "))
      end' "$1"
  else
    python3 -I -c '
import json, sys
rep = json.load(open(sys.argv[1]))
hosts = [h for h in rep["hosts"] if h["host"] == sys.argv[2]]
if hosts:
    h = hosts[0]; f = sys.argv[3]
    if f == "1": print(h["verdict"])
    elif f == "2": print(h["confidence"])
    else:
        letter = {"generic": "A", "cloned": "B", "issuer": "C"}
        print(" ".join("%s=%s/%s" % (letter.get(w["wave"], w["wave"]), w["outcome"], w["reason"]) for w in h.get("waves", [])))
' "$1" "$2" "$3"
  fi
}
json_trust() { # <report>
  if have jq; then jq -r '.scan.ca_trust // ""' "$1"
  else python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["scan"].get("ca_trust",""))' "$1"
  fi
}

# ---- preconditions ---------------------------------------------------------

have adb || die "adb not on PATH"
have openssl || die "openssl not on PATH (needed to compare CA subject hashes)"
have jq || have python3 || die "need jq or python3 to read the JSON reports"
[ -r "$CA" ] || die "research CA not readable: $CA (run: pinscan ca-new)"
if [ ! -x "$PINSCAN" ]; then
  have go || die "$PINSCAN is missing and go is not on PATH; run make build"
  say "building $PINSCAN"
  go build -trimpath -o "$PINSCAN" ./cmd/pinscan
fi
if [ -z "$HOST" ]; then
  HOST=$(sed -n 's/.*<domain[^>]*>\([^<]*\)<\/domain>.*/\1/p' "$NSC_PINNED" | head -1)
  [ -n "$HOST" ] || die "could not read the validation host from $NSC_PINNED; pass -H"
fi
state=$(adb get-state 2>/dev/null | tr -d '\r' || true)
[ "$state" = device ] || die "no device connected (adb get-state: ${state:-none}); connect it, enable USB debugging, authorize this host"

STAMP=$(date -u +%Y-%m-%dT%H%M%SZ)
DIR=$OUT_ROOT/$STAMP
mkdir -p "$DIR"
say "pinscan validation matrix  mode=$MODE window=$WINDOW host=$HOST  -> $DIR/"

{
  say "date_utc=$STAMP"
  say "mode=$MODE window=$WINDOW transparent=${TRANSPARENT:-no} host=$HOST ca=$CA"
  say "pinscan=$("$PINSCAN" -version 2>&1 | head -1)"
  say "android=$(adb shell getprop ro.build.version.release | tr -d '\r') sdk=$(adb shell getprop ro.build.version.sdk | tr -d '\r') device=$(adb shell getprop ro.product.model | tr -d '\r')"
  say "magisk=$(root magisk -v 2>/dev/null | tr -d '\r' || echo unknown)"
} >"$DIR/environment.txt"
cat "$DIR/environment.txt"

say ""
say "== doctor"
if ! "$PINSCAN" doctor -mode "$MODE" -ca "$CA" "$PKG_BASE.nopin" | tee "$DIR/doctor.txt"; then
  die "pinscan doctor failed; fix the prerequisites it lists and re-run"
fi

say ""
say "== validation app"
for row in $ROWS; do
  flavor=$(row_spec "$row" | cut -d'|' -f1)
  pkg="$PKG_BASE.$flavor"
  if ! adb shell pm path "$pkg" | grep -q '^package:'; then
    die "$pkg is not installed; run: (cd android/validation-app && ./build.sh --install)"
  fi
done
say "all required flavors installed"

# The app cannot be launched on a locked screen; a swipe lock is cleared here,
# a PIN or pattern must be entered by hand.
adb shell input keyevent KEYCODE_WAKEUP >/dev/null
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true

if [ "$MODE" = scoped ]; then
  root cat /data/adb/modules/ykzpinscan/log.txt >"$DIR/module-log.txt" 2>&1 || true
fi

# ---- CA variants for the misconfiguration rows -------------------------------
# Neither touches the device: the absent CA has a different subject (so a
# different <hash>.0 file name), the wrong-subject CA has the same subject (so
# the same file name) but different content. pinscan must refuse both.
ca_for_variant() { # <variant> -> path
  case "$1" in
    real) echo "$CA" ;;
    absent) echo "$DIR/ca-absent.pem" ;;
    wrong-subject) echo "$DIR/ca-wrong-subject.pem" ;;
  esac
}
needs_variant() { for row in $ROWS; do [ "$(row_spec "$row" | cut -d'|' -f5)" = "$1" ] && return 0; done; return 1; }
if needs_variant absent; then
  "$PINSCAN" ca-new -o "$DIR/ca-absent.pem" -cn "pinscan validation absent CA $STAMP" >/dev/null
fi
if needs_variant wrong-subject; then
  real_cn=$(openssl x509 -in "$CA" -noout -subject -nameopt RFC2253 | sed -n 's/.*CN=\([^,]*\).*/\1/p')
  "$PINSCAN" ca-new -o "$DIR/ca-wrong-subject.pem" -cn "$real_cn" >/dev/null
  h_real=$(openssl x509 -in "$CA" -noout -subject_hash_old)
  h_wrong=$(openssl x509 -in "$DIR/ca-wrong-subject.pem" -noout -subject_hash_old)
  if [ "$h_real" != "$h_wrong" ]; then
    say "warning: subject hash differs ($h_real vs $h_wrong): the research CA was not made by pinscan ca-new, so"
    say "         ca-wrong-subject degenerates into ca-absent (different file name). Expectation unchanged: refused."
  fi
fi

# ---- the scans ---------------------------------------------------------------

pass=0
fail=0
summary=()   # one "row|flavor|expected|got|result|detail" per row

record() { # <row> <flavor> <expected> <got> <PASS|FAIL> <detail>
  summary+=("$1|$2|$3|$4|$5|$6")
  if [ "$5" = PASS ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
  printf '   %-5s %s\n' "$5" "$6"
}

# netproc_evidence records, for the netproc row in scoped mode, which of the
# app's processes see the research CA, from inside each process's own mount
# namespace. This is the raw fact behind VAL-1 in docs/validation.md.
netproc_evidence() { # <pkg> <outfile>
  local hashfile pid
  hashfile="$(openssl x509 -in "$CA" -noout -subject_hash_old).0"
  {
    say "targets file:"
    root cat /data/adb/ykzpinscan/targets 2>&1 || true
    for name in "$1" "$1:net"; do
      say "process $name:"
      for pid in $(root pidof "$name" 2>/dev/null | tr -d '\r'); do
        say "  pid $pid: $(root nsenter --mount=/proc/"$pid"/ns/mnt -- ls /apex/com.android.conscrypt/cacerts/"$hashfile" 2>&1 | tr -d '\r')"
      done
    done
  } >"$2"
}

for row in $ROWS; do
  IFS='|' read -r flavor exp_verdict exp_trust exp_exits variant _ <<<"$(row_spec "$row")"
  pkg="$PKG_BASE.$flavor"
  ca=$(ca_for_variant "$variant")
  report="$DIR/$row.json"
  log="$DIR/$row.log"
  if [ "$exp_verdict" = "-" ]; then expected="refused (exit 2)"; else expected="$exp_verdict/$exp_trust"; fi

  say ""
  say "== $row  ($pkg, ca=$(basename "$ca"))  expect: $expected"
  adb logcat -c >/dev/null 2>&1 || true

  set +e
  # shellcheck disable=SC2086 # TRANSPARENT is intentionally empty or one flag.
  "$PINSCAN" scan -mode "$MODE" -window "$WINDOW" -ca "$ca" -report "$report" $TRANSPARENT "$pkg" >"$log" 2>&1
  rc=$?
  set -e
  grep -E '^[^ ]|^$' "$log" | grep -vE '^time=|level=' | sed 's/^/   | /' | head -20 || true
  adb logcat -d -s PINSCAN_VALIDATION:I YKZPINSCAN:I >"$DIR/$row.logcat.txt" 2>&1 || true
  if [ "$row" = netproc ] && [ "$MODE" = scoped ]; then
    netproc_evidence "$pkg" "$DIR/$row.namespaces.txt"
    sed 's/^/   ns: /' "$DIR/$row.namespaces.txt"
  fi

  accepted=0
  for e in $exp_exits; do [ "$rc" = "$e" ] && accepted=1; done
  if [ "$accepted" = 0 ]; then
    record "$row" "$flavor" "$expected" "exit $rc" FAIL "exit $rc, wanted one of: $exp_exits (see $log)"
    continue
  fi
  if [ "$rc" != 0 ]; then
    # A refusal must be the trust refusal, not an unrelated operational failure.
    if grep -qi 'not trusted' "$log"; then
      record "$row" "$flavor" "$expected" "refused (exit $rc)" PASS "refused: $(grep -i 'not trusted' "$log" | head -1 | sed 's/.*msg=//' | cut -c1-110)"
    else
      record "$row" "$flavor" "$expected" "exit $rc (other)" FAIL "exit $rc but not the trust refusal: $(tail -1 "$log" | cut -c1-110)"
    fi
    continue
  fi
  if [ "$exp_verdict" = "-" ]; then
    record "$row" "$flavor" "$expected" "scan completed" FAIL "pinscan scanned with a CA it should have refused"
    continue
  fi
  [ -s "$report" ] || { record "$row" "$flavor" "$expected" "no report" FAIL "exit 0 but no report at $report"; continue; }
  got_verdict=$(json_host_field "$report" "$HOST" 1)
  got_conf=$(json_host_field "$report" "$HOST" 2)
  got_waves=$(json_host_field "$report" "$HOST" 3)
  got_trust=$(json_trust "$report")
  [ -n "$got_verdict" ] || got_verdict="(host not observed)"
  got="$got_verdict/$got_trust"
  if [ "$got_verdict" = "$exp_verdict" ] && [ "$got_trust" = "$exp_trust" ]; then
    record "$row" "$flavor" "$expected" "$got" PASS "conf=$got_conf  $got_waves"
  else
    record "$row" "$flavor" "$expected" "$got" FAIL "conf=$got_conf  $got_waves"
  fi
done

# ---- the table ---------------------------------------------------------------

{
  say ""
  say "pinscan validation matrix  mode=$MODE host=$HOST  $DIR/"
  printf '%-18s %-14s %-24s %-24s %-5s %s\n' ROW FLAVOR EXPECTED GOT RESULT EVIDENCE
  for line in "${summary[@]}"; do
    IFS='|' read -r r f e g res d <<<"$line"
    printf '%-18s %-14s %-24s %-24s %-5s %s\n' "$r" "$f" "$e" "$g" "$res" "$d"
  done
  say ""
  say "$pass passed, $fail failed"
} | tee "$DIR/summary.txt"

[ "$fail" -eq 0 ] || exit 1
exit 0
