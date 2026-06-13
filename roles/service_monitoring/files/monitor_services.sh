#!/bin/bash
# ============================================================
#  monitor_services.sh — мониторинг сервисов + автореакция
#
#  Запускается systemd-таймером каждые 5 минут (требование задания).
#
#  ЛОГИКА (требование задания, п.2):
#    1. Проверка статуса каждого критичного сервиса
#    2. Если сервис не active:
#       - попытка systemctl restart
#       - email-уведомление администратору
#       - запись инцидента в /var/log/infrastructure_monitor.log
#       - если рестарт не помог 3 раза подряд — временный карантин хоста
# ============================================================

# shellcheck disable=SC1091
source /opt/monitoring/lib/monitor_common.sh

autorespond="${ALERT_AUTORESPONSE:-yes}"
max_attempts="${RESTART_MAX_ATTEMPTS:-3}"

RESTART_COUNT_DIR="${MON_STATE_DIR}/restart_count"
ISOLATION_DIR="${MON_STATE_DIR}/isolation"
mkdir -p "$RESTART_COUNT_DIR" "$ISOLATION_DIR" 2>/dev/null

# Service -> port/protocol is generated from group_vars/monitoring.yml.
declare -A SERVICE_PORTS
declare -A SERVICE_PROTOCOLS
IFS=',' read -r -a PORT_MAP <<< "${SERVICE_PORT_MAP:-}"
for mapping in "${PORT_MAP[@]}"; do
    IFS=':' read -r map_name map_port map_protocol <<< "$mapping"
    [ -z "$map_name" ] && continue
    SERVICE_PORTS["$map_name"]="${map_port:-0}"
    SERVICE_PROTOCOLS["$map_name"]="${map_protocol:-tcp}"
done

single_service=""
demo_port="65534"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --service) single_service="${2:-}"; shift 2 ;;
        --port) demo_port="${2:-65534}"; shift 2 ;;
        --isolation-seconds) ISOLATION_SECONDS="${2:-120}"; shift 2 ;;
        *) shift ;;
    esac
done
if [ -n "$single_service" ]; then
    SERVICE_PORTS["$single_service"]="$demo_port"
    SERVICE_PROTOCOLS["$single_service"]="tcp"
fi

# Структуры результата
declare -A SERVICE_STATUS
declare -A SERVICE_ENABLED
declare -A SERVICE_ACTIONS

service_port_is_listening() {
    local svc="$1"
    local port="${SERVICE_PORTS[$svc]:-0}"
    local protocol="${SERVICE_PROTOCOLS[$svc]:-tcp}"
    [ "$port" = "0" ] || [ -z "$port" ] && return 0
    command -v ss >/dev/null 2>&1 || return 0
    if [ "$protocol" = "udp" ]; then
        ss -lunH 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"
    else
        ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"
    fi
}

# NextCloud — это виртуальный «сервис»: реально работает Apache, но мы
# дополнительно проверяем что приложение отвечает на HTTP /nextcloud.
# Для имени "nextcloud" используем особую логику.
nextcloud_is_healthy() {
    # Возвращает 0 если статус OK, иначе 1
    if ! command -v curl >/dev/null 2>&1; then
        return 0   # нет curl — не валим алертом, оставляем active
    fi
    local url="${NEXTCLOUD_CHECK_URL:-http://127.0.0.1/nextcloud/status.php}"
    local code
    code="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || echo 000)"
    # 200 — OK, 401 — установлен но требует auth, тоже считаем работоспособным
    case "$code" in
        200|301|302|401) return 0 ;;
        *) return 1 ;;
    esac
}

# ============================================================
#  Temporary host quarantine.
#  firewall mode rejects the classroom subnet while preserving management SSH.
#  interface mode schedules reconnect first, then disconnects the default NIC.
# ============================================================
isolate_host() {
    local svc="$1"
    local iso_seconds="${ISOLATION_SECONDS:-1800}"
    local iso_file="${ISOLATION_DIR}/host"

    if [ -f "$iso_file" ]; then
        expires="$(awk -F= '/^expires=/{print $2}' "$iso_file" 2>/dev/null)"
        if [ -n "$expires" ] && [ "$(date +%s)" -ge "$expires" ]; then
            rm -f "$iso_file"
        else
            return 0
        fi
    fi

    if [ "${ISOLATION_MODE:-firewall}" = "interface" ]; then
        local iface
        iface="$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')"
        [ -z "$iface" ] && return 1
        systemd-run --unit=monitor-host-reconnect --on-active="${iso_seconds}s" \
            /usr/bin/nmcli device connect "$iface" >/dev/null 2>&1 || return 1
        date +%s > "$iso_file"
        log_critical "$LOG_SERVICES" "HOST QUARANTINE: disconnecting $iface for ${iso_seconds}s after $svc failures"
        log_incident "service" "CRITICAL" "host quarantined" "$svc failed 3 times; interface=$iface; ttl=${iso_seconds}s"
        nmcli device disconnect "$iface" >/dev/null 2>&1
        return $?
    fi

    systemctl is-active firewalld >/dev/null 2>&1 || return 1
    local network="${ISOLATION_NETWORK:-192.168.254.0/24}"
    local management="${MANAGEMENT_IP:-192.168.254.1}"
    local allow_rule="rule priority=\"-100\" family=\"ipv4\" source address=\"${management}/32\" accept"
    local reject_rule="rule priority=\"100\" family=\"ipv4\" source address=\"${network}\" reject"

    firewall-cmd --add-rich-rule="$allow_rule" --timeout="$iso_seconds" >/dev/null 2>&1 || return 1
    if ! firewall-cmd --add-rich-rule="$reject_rule" --timeout="$iso_seconds" >/dev/null 2>&1; then
        firewall-cmd --remove-rich-rule="$allow_rule" >/dev/null 2>&1 || true
        return 1
    fi

    {
        echo "service=$svc"
        echo "expires=$(( $(date +%s) + iso_seconds ))"
        echo "allow_rule=$allow_rule"
        echo "reject_rule=$reject_rule"
    } > "$iso_file"
    log_critical "$LOG_SERVICES" "HOST QUARANTINE for ${iso_seconds}s after 3 consecutive $svc failures"
    log_incident "service" "CRITICAL" "host quarantined" "$svc failed 3 times; network=$network; management=$management; ttl=${iso_seconds}s"
    return 0
}

quarantine_after_limit() {
    local svc="$1" cnt="$2"
    if [ "${ISOLATION_ENABLED:-yes}" = "yes" ]; then
        isolate_host "$svc" || log_error "$LOG_SERVICES" "host quarantine failed for $svc"
    fi
    if alert_should_send "svc_${svc}_isolated" 30; then
        local journ
        journ="$(journalctl -u "$svc" -n 20 --no-pager 2>&1 | tail -20)"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} CRITICAL: host quarantined after repeated $svc failures" \
            "Host: $(hostname)
Service: $svc
Consecutive outage detections: $cnt
Quarantine mode: ${ISOLATION_MODE:-firewall}
Duration: ${ISOLATION_SECONDS:-1800}s
Management IP kept allowed: ${MANAGEMENT_IP:-unknown}
Time: $(date '+%Y-%m-%d %H:%M:%S')

$journ" "${ALERT_TO}"
        alert_mark_sent "svc_${svc}_isolated"
    fi
}

# ============================================================
#  Проверка одного сервиса
# ============================================================
check_service() {
    local svc="$1" critical="$2"

    # Особый случай: nextcloud — это HTTP-приложение, а не systemd-сервис.
    # Проверяем через curl /nextcloud/status.php.
    if [ "$svc" = "nextcloud" ]; then
        if nextcloud_is_healthy; then
            SERVICE_STATUS["$svc"]="active"
            SERVICE_ENABLED["$svc"]="enabled"
            SERVICE_ACTIONS["$svc"]="ok"
            rm -f "$RESTART_COUNT_DIR/$svc" 2>/dev/null
            return 0
        fi
        SERVICE_STATUS["$svc"]="http-down"
        SERVICE_ENABLED["$svc"]="enabled"
        # Дальше идёт общая логика рестарта httpd как back-сервиса
        # (рестартим httpd для оживления Nextcloud)
        active="http-down"
        enabled="enabled"
        local restart_target="httpd"
    fi

    # systemctl is-active: stdout=status, exit code не используем (см. фикс \n)
    local active enabled
    if [ "$svc" != "nextcloud" ]; then
        active="$(systemctl is-active "$svc" 2>/dev/null | head -n1)"
        active="${active:-unknown}"
        enabled="$(systemctl is-enabled "$svc" 2>/dev/null | head -n1)"
        enabled="${enabled:-unknown}"
        SERVICE_STATUS["$svc"]="$active"
        SERVICE_ENABLED["$svc"]="$enabled"
    fi

    # Сервис установлен? (надёжная проверка через list-unit-files).
    # nextcloud пропускаем — это виртуальный сервис, не systemd-юнит.
    if [ "$svc" != "nextcloud" ]; then
        local unit_exists=0
        if LANG=C systemctl list-unit-files --no-legend 2>/dev/null \
                | awk '{print $1}' | grep -qE "^${svc}\\.service$"; then
            unit_exists=1
        elif LANG=C systemctl list-units --all --no-legend 2>/dev/null \
                | awk '{print $1}' | grep -qE "^${svc}\\.service$"; then
            unit_exists=1
        fi

        if [ "$unit_exists" = "0" ]; then
            SERVICE_ACTIONS["$svc"]="not-installed"
            SERVICE_STATUS["$svc"]="not-installed"
            return 0
        fi
    fi

    if [ "$active" = "active" ] && service_port_is_listening "$svc"; then
        SERVICE_ACTIONS["$svc"]="ok"
        rm -f "$RESTART_COUNT_DIR/$svc" 2>/dev/null
        return 0
    elif [ "$active" = "active" ]; then
        active="active-port-closed"
        SERVICE_STATUS["$svc"]="$active"
        log_error "$LOG_SERVICES" "$svc is active but ${SERVICE_PROTOCOLS[$svc]:-tcp}/${SERVICE_PORTS[$svc]:-0} is not listening"
    fi

    # Сервис не работает
    if [ "$critical" != "yes" ]; then
        SERVICE_ACTIONS["$svc"]="alert-only"
        log_incident "service" "WARN" "$svc is $active" "non-critical, no auto-restart"
        if alert_should_send "svc_${svc}" "${ALERT_THROTTLE_MIN:-15}"; then
            local body="REDOS Monitoring Alert
======================

Service:  $svc
Host:     $(hostname)
Status:   $active
Enabled:  $enabled
Priority: NON-CRITICAL (alert only)
Time:     $(date '+%Y-%m-%d %H:%M:%S')"
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} WARN: $svc is $active" \
                "$body" "${ALERT_TO}"
            alert_mark_sent "svc_${svc}"
        fi
        return 1
    fi

    # Критичный — пробуем рестарт
    log_error "$LOG_SERVICES" "CRITICAL $svc is $active"

    if [ "$autorespond" != "yes" ]; then
        SERVICE_ACTIONS["$svc"]="alert-only(autorespond-off)"
        if alert_should_send "svc_${svc}" "${ALERT_THROTTLE_MIN:-15}"; then
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} CRITICAL: $svc is $active" \
                "Service $svc on $(hostname) is $active. Auto-response disabled." "${ALERT_TO}"
            alert_mark_sent "svc_${svc}"
        fi
        return 1
    fi

    # Счётчик попыток
    local cnt_file="$RESTART_COUNT_DIR/$svc" cnt=0
    [ -f "$cnt_file" ] && cnt="$(cat "$cnt_file" 2>/dev/null || echo 0)"

    # Попытка рестарта
    cnt=$(( cnt + 1 ))
    echo "$cnt" > "$cnt_file"
    log_warn "$LOG_SERVICES" "restarting $svc (attempt $cnt/$max_attempts)"

    local restart_out
    # Для виртуального nextcloud — рестартим httpd (несущий сервис)
    if [ "$svc" = "nextcloud" ]; then
        restart_out="$(systemctl restart httpd 2>&1)"
        sleep 3
        if nextcloud_is_healthy; then
            after="active"
            SERVICE_STATUS["$svc"]="active"
        else
            after="http-down"
        fi
    else
        restart_out="$(systemctl restart "$svc" 2>&1)"
        sleep 3
        after="$(systemctl is-active "$svc" 2>/dev/null | head -n1)"
        after="${after:-unknown}"
    fi

    if [ "$after" = "active" ] && service_port_is_listening "$svc"; then
        SERVICE_ACTIONS["$svc"]="restarted-ok(attempt-$cnt)"
        SERVICE_STATUS["$svc"]="active"
        log_info "$LOG_SERVICES" "$svc restarted successfully (attempt $cnt)"
        log_incident "service" "INFO" "$svc restarted" "attempt $cnt/$max_attempts"

        # Do not reset here: the counter represents consecutive monitoring
        # cycles that found the service down. A naturally healthy cycle resets it.
        if [ "$cnt" -ge "$max_attempts" ]; then
            SERVICE_ACTIONS["$svc"]="restarted-ok+host-quarantine(after-$cnt-outages)"
            log_incident "service" "CRITICAL" "$svc failed repeatedly" "$cnt consecutive outage detections"
            quarantine_after_limit "$svc" "$cnt"
        fi

        if alert_should_send "svc_${svc}_recover" "${ALERT_THROTTLE_MIN:-15}"; then
            local body="REDOS Monitoring — Service RECOVERED
====================================

Service:  $svc
Host:     $(hostname)
Action:   Auto-restarted (attempt $cnt of $max_attempts)
Time:     $(date '+%Y-%m-%d %H:%M:%S')"
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} RECOVERED: $svc" \
                "$body" "${ALERT_TO}"
            alert_mark_sent "svc_${svc}_recover"
        fi
        return 0
    fi

    SERVICE_ACTIONS["$svc"]="restart-failed(attempt-$cnt)"
    log_critical "$LOG_SERVICES" "$svc restart FAILED (attempt $cnt): $restart_out"
    log_incident "service" "CRITICAL" "$svc restart failed" "attempt $cnt"

    if [ "$cnt" -ge "$max_attempts" ]; then
        SERVICE_ACTIONS["$svc"]="host-quarantine(after-$cnt-failures)"
        quarantine_after_limit "$svc" "$cnt"
        return 1
    fi

    if alert_should_send "svc_${svc}_fail" 10; then
        local body="REDOS Monitoring Alert — CRITICAL
=================================

Service:  $svc
Host:     $(hostname)
Status:   $after
Attempt:  $cnt of $max_attempts
Time:     $(date '+%Y-%m-%d %H:%M:%S')

Restart FAILED:
$restart_out

Next attempt at next check (5 minutes).
After $max_attempts consecutive monitoring cycles with an outage the host is quarantined."
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} CRITICAL: $svc restart failed" \
            "$body" "${ALERT_TO}"
        alert_mark_sent "svc_${svc}_fail"
    fi
    return 1
}

# ============================================================
#  Main
# ============================================================
log_info "$LOG_SERVICES" "service check started"

IFS=',' read -r -a CRIT <<< "${CRITICAL_SERVICES:-}"
IFS=',' read -r -a OPT <<< "${OPTIONAL_SERVICES:-}"

if [ -n "$single_service" ]; then
    CRIT=("$single_service")
    OPT=()
fi

for svc in "${CRIT[@]}"; do
    [ -z "$svc" ] && continue
    check_service "$svc" "yes" || true
done

for svc in "${OPT[@]}"; do
    [ -z "$svc" ] && continue
    check_service "$svc" "no" || true
done

# Запись state JSON
{
    printf '{\n  "timestamp": "%s",\n  "host": "%s",\n  "services": [' \
        "$(date -Iseconds)" "$(hostname)"
    first=1
    for svc in "${!SERVICE_STATUS[@]}"; do
        [ "$first" = "1" ] || printf ","
        first=0
        action_esc="$(printf '%s' "${SERVICE_ACTIONS[$svc]:-}" | sed 's/\\/\\\\/g; s/"/\\"/g')"
        printf '\n    {"name":"%s","status":"%s","enabled":"%s","action":"%s"}' \
            "$svc" "${SERVICE_STATUS[$svc]:-unknown}" "${SERVICE_ENABLED[$svc]:-unknown}" "$action_esc"
    done
    [ "$first" = "0" ] && printf '\n  '
    printf ']\n}\n'
} > "$STATE_SERVICES.tmp"

if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import json; json.load(open('$STATE_SERVICES.tmp'))" 2>/dev/null; then
        mv -f "$STATE_SERVICES.tmp" "$STATE_SERVICES"
    else
        log_error "$LOG_SERVICES" "state_services.json malformed"
        rm -f "$STATE_SERVICES.tmp"
    fi
else
    mv -f "$STATE_SERVICES.tmp" "$STATE_SERVICES"
fi
chmod 0640 "$STATE_SERVICES" 2>/dev/null || true

log_info "$LOG_SERVICES" "service check finished (${#SERVICE_STATUS[@]} tracked)"
exit 0
