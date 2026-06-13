#!/bin/bash
# Report entry point adapted from PLAYBOOKS_FINAL_v1.
source /opt/monitoring/lib/monitor_common.sh

kind="${1:-daily}"
case "$kind" in daily|weekly|hourly) ;; *) kind=daily ;; esac

# Запуск render_report.py — генерирует HTML+PDF+TXT+JSON
# stderr содержит "PDF engine used: …" — записываем в журнал
gen_log="$(mktemp /tmp/render_report.XXXXXX.log)"
result="$("${MON_BASE_DIR}/bin/render_report.py" "$kind" 2>"$gen_log")" || {
    err="$(cat "$gen_log" 2>/dev/null | tail -5 | tr '\n' ' ')"
    log_incident "reporting" "ERROR" "report generation failed" "type=$kind | $err"
    rm -f "$gen_log"
    exit 1
}
pdf_engine="$(grep -E "PDF engine used:" "$gen_log" 2>/dev/null | tail -1)"
rm -f "$gen_log"
log_info "$MON_INCIDENT_LOG" "report generated: $result"
[ -n "$pdf_engine" ] && log_info "$MON_INCIDENT_LOG" "$pdf_engine"

# Reports are sent only through the strict STARTTLS sender.
# ВАЖНО: захватываем stderr — там реальная причина если что-то падает,
# а не наша захардкоженная фраза. Это нужно для отладки.
if [ "$kind" = "daily" ] || [ "$kind" = "weekly" ]; then
    html="${result%%|*}"
    rest="${result#*|}"
    pdf="${rest%%|*}"
    txt="${result##*|}"

    send_log="$(mktemp /tmp/send_report.XXXXXX.log)"
    if /usr/local/bin/monitor_send_report.py \
            "${ALERT_SUBJECT_PREFIX:-[MON]} ${kind^} report $(date +%F)" \
            "$txt" "$html" "$pdf" >"$send_log" 2>&1; then
        ok_msg="$(grep -E "^OK:" "$send_log" | tail -1)"
        [ -z "$ok_msg" ] && ok_msg="report sent (no detailed message)"
        log_info "$MON_INCIDENT_LOG" "reporting | $ok_msg"
    else
        # Реальная причина (вместо захардкоженной "STARTTLS is required")
        last_err="$(tail -5 "$send_log" 2>/dev/null | tr '\n' ' | ')"
        log_incident "reporting" "ERROR" "report delivery failed" "$last_err"
    fi
    rm -f "$send_log"
fi

printf '%s\n' "$result"
