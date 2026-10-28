#!/system/bin/sh
# Apply the ykzpinscan SELinux rules to the LIVE kernel policy (idempotent).
# Called at boot by post-fs-data.sh, and on demand by the host harness before a scan
# (belt-and-suspenders: if the boot-time apply raced with another module's magiskpolicy
# and failed, the scan-time apply fixes it without a reboot).
apply() {
  i=0
  while [ $i -lt 5 ]; do
    magiskpolicy --live "$1" 2>/dev/null && return 0
    i=$((i+1)); /system/bin/sleep 1
  done
  echo "FAIL $1"
  return 1
}
apply "allow zygote system_security_cacerts_file dir { mounton search read open getattr }"
apply "allow zygote system_security_cacerts_file file { read open getattr }"
apply "allow zygote adb_data_file dir search"
apply "allow zygote adb_data_file file { read open getattr }"
apply "allow zygote system_file dir search"
exit 0
