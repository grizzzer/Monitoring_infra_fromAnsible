#!/bin/bash
# Lightweight HTTPS download measurement. Deploy this role to student hosts to
# measure their connection directly; each host writes its own state snapshot.
source /opt/monitoring/lib/monitor_common.sh

url="${SPEEDTEST_URL:-https://speedtest.selectel.ru/100MB}"
threshold="${THRESHOLD_INTERNET_MBPS:-0.8}"
speed_bps=0
curl_rc=1
http_code=0

# Делаем замер. ВАЖНО:
#   --max-time 15      — успеваем замерить скорость, но не качаем 100МБ полностью
#   без --fail         — partial transfer (28) считается нормальным, у нас важна СКОРОСТЬ, не полнота
#   -L                 — следуем редиректам
#   -w speed+http_code — измеряем оба параметра одним запросом
if command -v curl >/dev/null 2>&1; then
    result="$(curl -L --silent --show-error --max-time 15 \
        --output /dev/null \
        --write-out '%{speed_download} %{http_code}' \
        "$url" 2>/dev/null)"
    curl_rc=$?
    speed_bps="$(echo "$result" | awk '{print $1}')"
    http_code="$(echo "$result" | awk '{print $2}')"
fi
case "$speed_bps" in ''|*[!0-9.]*) speed_bps=0 ;; esac
speed_mbps="$(LANG=C awk -v b="$speed_bps" 'BEGIN { printf "%.3f", (b * 8) / 1000000 }')"

# Логика определения статуса:
#   1. Скорость >= порога → OK (даже если curl вернул 28 partial-transfer — главное замерили)
#   2. Скорость измерена (> 0), но < порога → slow
#   3. Скорость = 0 И HTTP-код не в 2xx/3xx → unreachable (реально не подключились)
status=ok
above_threshold=$(awk -v s="$speed_mbps" -v t="$threshold" 'BEGIN { print (s >= t) ? "1" : "0" }')
zero_speed=$(awk -v s="$speed_mbps" 'BEGIN { print (s == 0) ? "1" : "0" }')

if [ "$zero_speed" = "1" ]; then
    # Скорость 0 — проверяем код. 2xx/3xx = просто пустой ответ, иначе unreachable.
    case "$http_code" in
        2*|3*) status=slow ;;   # ответ был, но скорость 0 (странно)
        *)     status=unreachable ;;
    esac
elif [ "$above_threshold" = "0" ]; then
    status=slow
fi

if [ "$status" != "ok" ]; then
    severity="CRITICAL"
    [ "$status" = "slow" ] && severity="WARN"
    log_incident "performance" "$severity" "internet $status" "${speed_mbps} Mbit/s (threshold ${threshold}) on $(hostname)"
    if alert_should_send "internet_${status}" "${ALERT_THROTTLE_MIN:-15}"; then
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} Internet ${status}: ${speed_mbps} Mbit/s" \
            "REDOS Monitoring Alert — Internet
=================================

Host:      $(hostname)
Status:    $status
Measured:  ${speed_mbps} Mbit/s
Threshold: ${threshold} Mbit/s
HTTP code: ${http_code}
URL:       ${url}
Time:      $(date '+%Y-%m-%d %H:%M:%S')" "${ALERT_TO}"
        alert_mark_sent "internet_${status}"
    fi
fi

cat > "${STATE_INTERNET}.tmp" <<EOF
{"timestamp":"$(date -Iseconds)","host":"$(hostname)","status":"$status","speed_mbps":$speed_mbps,"threshold_mbps":$threshold,"http_code":"$http_code","curl_rc":$curl_rc}
EOF
mv -f "${STATE_INTERNET}.tmp" "$STATE_INTERNET"
chmod 0640 "$STATE_INTERNET" 2>/dev/null || true
log_info "$LOG_PERFORMANCE" "internet check: status=$status speed=${speed_mbps}Mbit/s http=$http_code"
exit 0
