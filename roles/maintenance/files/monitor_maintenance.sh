#!/bin/bash
# Scheduled maintenance with a single lock, bounded resource use and no reboot.
source /opt/monitoring/lib/monitor_common.sh

action="${1:-}"
exec 9>/run/monitor-maintenance.lock
flock -n 9 || exit 0

run_update() {
    log_info "$LOG_MAINTENANCE" "daily package update started"
    args=(-y --refresh upgrade)
    [ "${MAINTENANCE_SECURITY_ONLY:-no}" = "yes" ] && args=(-y --security upgrade)
    if timeout 7200 dnf "${args[@]}" >>"$LOG_MAINTENANCE" 2>&1; then
        log_info "$LOG_MAINTENANCE" "daily package update completed; reboot was not requested"
    else
        rc=$?
        log_incident "maintenance" "ERROR" "daily update failed" "dnf rc=$rc"
        return "$rc"
    fi
}

run_cleanup() {
    retention="${LOG_RETENTION_DAYS:-30}"
    log_info "$LOG_MAINTENANCE" "weekly log cleanup started, retention=${retention}d"
    journalctl --vacuum-time="${retention}d" >>"$LOG_MAINTENANCE" 2>&1 || true
    find /var/log -xdev -type f \
        \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.[0-9].gz' \) \
        -mtime +"$retention" -delete 2>/dev/null || true
    dnf clean all >>"$LOG_MAINTENANCE" 2>&1 || true
    log_info "$LOG_MAINTENANCE" "weekly log cleanup completed"
}

run_fscheck() {
    log_info "$LOG_MAINTENANCE" "monthly online filesystem integrity check started"
    failed=0
    while read -r source fstype target; do
        case "$fstype" in
            xfs)
                if command -v xfs_scrub >/dev/null 2>&1; then
                    xfs_scrub -n "$target" >>"$LOG_MAINTENANCE" 2>&1 || failed=1
                else
                    log_warn "$LOG_MAINTENANCE" "xfs_scrub unavailable for $target"
                fi
                ;;
            btrfs)
                btrfs scrub start -B -R "$target" >>"$LOG_MAINTENANCE" 2>&1 || failed=1
                ;;
            ext2|ext3|ext4)
                if command -v e2scrub >/dev/null 2>&1; then
                    e2scrub "$source" >>"$LOG_MAINTENANCE" 2>&1 || failed=1
                else
                    # Running e2fsck against a mounted filesystem is unsafe.
                    log_warn "$LOG_MAINTENANCE" "online ext check unavailable for $source; boot-time fsck remains enabled"
                    fsck -N "$source" >>"$LOG_MAINTENANCE" 2>&1 || true
                fi
                ;;
        esac
    done < <(findmnt -rn -o SOURCE,FSTYPE,TARGET -t xfs,btrfs,ext2,ext3,ext4)
    if [ "$failed" -ne 0 ]; then
        log_incident "maintenance" "CRITICAL" "filesystem integrity check found errors" "see $LOG_MAINTENANCE"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} Filesystem check failed" \
            "Host: $(hostname)
The monthly read-only/online filesystem check reported an error.
See: $LOG_MAINTENANCE" "${ALERT_TO}" || true
    fi
    log_info "$LOG_MAINTENANCE" "monthly filesystem integrity check completed"
}

case "$action" in
    update) run_update ;;
    cleanup) run_cleanup ;;
    fscheck) run_fscheck ;;
    *) echo "usage: $0 {update|cleanup|fscheck}" >&2; exit 2 ;;
esac
