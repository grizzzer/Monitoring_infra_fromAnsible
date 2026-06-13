#!/bin/bash
source /opt/monitoring/lib/monitor_common.sh
mkdir -p "$MON_ARCHIVE_DIR"
month="$(date -d 'last month' +%Y-%m 2>/dev/null || date +%Y-%m)"
archive="$MON_ARCHIVE_DIR/reports_${month}.tar.gz"
find "$MON_REPORT_DIR" -maxdepth 1 -type f -mtime -31 -print0 |
    tar --null -czf "$archive" --files-from=- 2>>"$MON_INCIDENT_LOG" || exit 1
chmod 0640 "$archive"
find "$MON_ARCHIVE_DIR" -type f -name 'reports_*.tar.gz' \
    -mtime "+$(( ${REPORT_ARCHIVE_KEEP_MONTHS:-12} * 31 ))" -delete
log_info "$MON_INCIDENT_LOG" "monthly report archive created: $archive"
