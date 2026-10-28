#!/system/bin/sh
# ykzpinscan — apply the per-app-bind SELinux rules to the live policy at boot.
# The rule set lives in apply-sepolicy.sh (shared with the host harness). Stagger first:
# if another module also calls `magiskpolicy --live` at post-fs-data, concurrent access
# to /sys/fs/selinux/policy can fail with "Device or resource busy".
MODDIR=${0%/*}
LOG=$MODDIR/postfsdata.log
echo "post-fs-data @ uptime=$(cat /proc/uptime 2>/dev/null)" > "$LOG"
/system/bin/sleep 3
sh "$MODDIR/apply-sepolicy.sh" >> "$LOG" 2>&1
echo "done" >> "$LOG"
