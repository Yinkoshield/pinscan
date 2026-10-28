#!/system/bin/sh
# ykzpinscan — build the per-app trust store (real roots + research CA) after boot.
MODDIR=${0%/*}
APEX=/apex/com.android.conscrypt/cacerts
DST=$MODDIR/system_cacerts
CFG=/data/adb/ykzpinscan

i=0
while [ "$(getprop sys.boot_completed)" != 1 ]; do /system/bin/sleep 1; i=$((i+1)); [ $i -ge 120 ] && exit 0; done
/system/bin/sleep 2

# Config dir + an example targets file (one package per line; '#' comments ok).
# `pinscan scan -mode scoped` and set-target.sh overwrite this with the real
# target; a missing file is also safe (pinscan.cpp treats it as "no targets").
mkdir -p "$CFG"
[ -f "$CFG/targets" ] || {
  echo "# ykzpinscan targets — one Android package per line. e.g.:" > "$CFG/targets"
  echo "# com.example.bank" >> "$CFG/targets"
}
chmod 600 "$CFG/targets" 2>/dev/null

# trust store: the live APEX roots plus whatever research CA(s) you dropped into
# cacerts/ (named <subject_hash_old>.0 — exactly what `pinscan ca-module` emits).
[ -d "$APEX" ] || exit 0
rm -rf "$DST"; mkdir -p "$DST"
cp "$APEX"/* "$DST"/ 2>/dev/null
cp "$MODDIR"/cacerts/* "$DST"/ 2>/dev/null
chown root:root "$DST" "$DST"/* 2>/dev/null
chmod 755 "$DST"; chmod 644 "$DST"/* 2>/dev/null
chcon u:object_r:system_security_cacerts_file:s0 "$DST" "$DST"/* 2>/dev/null
echo "store built: $(ls "$DST" | wc -l) certs; targets: $(grep -cvE '^\s*#|^\s*$' "$CFG/targets" 2>/dev/null)" > "$MODDIR/log.txt"
