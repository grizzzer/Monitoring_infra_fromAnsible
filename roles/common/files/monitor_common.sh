#!/bin/bash
# ============================================================
#  monitor_common.sh — общая библиотека для скриптов мониторинга
#
#  Подключается через `source /opt/monitoring/lib/monitor_common.sh`
#  ВНИМАНИЕ: НЕ используем set -u — мониторинг должен переживать
#            отсутствие переменных, а не падать. Все дефолты через ${var:-...}.
# ============================================================

# Параметры по умолчанию (перезаписываются из /etc/monitoring/monitor.env)
MON_BASE_DIR="${MON_BASE_DIR:-/opt/monitoring}"
MON_LOG_DIR="${MON_LOG_DIR:-/var/log/monitoring}"
MON_STATE_DIR="${MON_STATE_DIR:-/var/lib/monitoring}"
MON_CONFIG_DIR="${MON_CONFIG_DIR:-/etc/monitoring}"
MON_REPORT_DIR="${MON_REPORT_DIR:-/var/log/monitoring/reports}"
MON_ARCHIVE_DIR="${MON_ARCHIVE_DIR:-/var/log/monitoring/archive}"
MON_INCIDENT_LOG="${MON_INCIDENT_LOG:-/var/log/infrastructure_monitor.log}"

# Load configuration before deriving log and state paths.
if [ -f "${MON_CONFIG_DIR}/monitor.env" ]; then
    set -a
    # shellcheck disable=SC1090
    . "${MON_CONFIG_DIR}/monitor.env" 2>/dev/null || true
    set +a
fi

# Лог-файлы по типам
LOG_SERVICES="${MON_LOG_DIR}/services.log"
LOG_PERFORMANCE="${MON_LOG_DIR}/performance.log"
LOG_SECURITY="${MON_LOG_DIR}/security.log"
LOG_ALERTS="${MON_LOG_DIR}/alerts.log"
LOG_MAINTENANCE="${MON_LOG_DIR}/maintenance.log"
LOG_LOAD="$LOG_PERFORMANCE"
LOG_INCIDENTS="$MON_INCIDENT_LOG"

# State JSON-снимки (для отчётов и расширения)
STATE_SERVICES="${MON_STATE_DIR}/state_services.json"
STATE_PERFORMANCE="${MON_STATE_DIR}/state_performance.json"
STATE_SECURITY="${MON_STATE_DIR}/state_security.json"
STATE_INTERNET="${MON_STATE_DIR}/state_internet.json"
STATE_INCIDENTS="${MON_STATE_DIR}/state_incidents.json"
METRICS_HISTORY="${MON_STATE_DIR}/history/metrics.csv"
STATE_LOAD="$STATE_PERFORMANCE"

# Throttling
THROTTLE_DIR="${MON_STATE_DIR}/throttle"

# ============================================================
#  ЛОГИРОВАНИЕ
# ============================================================
log_msg() {
    local logfile="$1" level="$2"
    shift 2
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    [ -d "$(dirname "$logfile")" ] || mkdir -p "$(dirname "$logfile")" 2>/dev/null
    printf '%s [%s] %s\n' "$ts" "$level" "$msg" >> "$logfile" 2>/dev/null || true
}
log_info()     { log_msg "$1" "INFO" "${@:2}"; }
log_warn()     { log_msg "$1" "WARN" "${@:2}"; }
log_error()    { log_msg "$1" "ERROR" "${@:2}"; }
log_critical() { log_msg "$1" "CRITICAL" "${@:2}"; }

# Запись инцидента в ЦЕНТРАЛЬНЫЙ лог (требование задания)
# log_incident <category> <severity> <subject> <details>
log_incident() {
    local category="$1" severity="$2" subject="$3" details="$4"
    log_msg "$MON_INCIDENT_LOG" "$severity" "$category | $subject | $details"
}

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])' 2>/dev/null
}

# ============================================================
#  THROTTLING — не слать один и тот же алерт чаще раза в TTL мин
# ============================================================
alert_should_send() {
    local key="$1" ttl_min="${2:-15}"
    local stamp="${THROTTLE_DIR}/${key}"
    [ -d "$THROTTLE_DIR" ] || mkdir -p "$THROTTLE_DIR" 2>/dev/null
    [ ! -f "$stamp" ] && return 0
    local last now diff
    last="$(cat "$stamp" 2>/dev/null || echo 0)"
    now="$(date +%s)"
    diff=$(( now - last ))
    [ "$diff" -ge $(( ttl_min * 60 )) ] && return 0
    return 1
}
alert_mark_sent() {
    local key="$1"
    [ -d "$THROTTLE_DIR" ] || mkdir -p "$THROTTLE_DIR" 2>/dev/null
    date +%s > "${THROTTLE_DIR}/${key}" 2>/dev/null
}

# ============================================================
#  ОТПРАВКА АЛЕРТОВ
#  send_alert <subject> <body> [recipient]
# ============================================================
send_alert() {
    local subject="$1" body="$2"
    local recipient="${3:-${ALERT_TO:-sysadmin@redos.test}}"

    log_msg "$LOG_ALERTS" "ALERT" "$subject -> $recipient"

    # Способ 1 — наш универсальный отправитель
    if [ -x /usr/local/bin/monitor_send_mail.sh ]; then
        /usr/local/bin/monitor_send_mail.sh "$subject" "$body" "$recipient" \
            >> "$LOG_ALERTS" 2>&1
        return $?
    fi

    # Способ 2 — sendmail (postfix)
    if command -v sendmail >/dev/null 2>&1; then
        {
            echo "From: ${ALERT_FROM:-monitoring@$(hostname -d 2>/dev/null || echo localhost)}"
            echo "To: $recipient"
            echo "Subject: $subject"
            echo "Content-Type: text/plain; charset=UTF-8"
            echo ""
            echo "$body"
        } | sendmail -t -i >> "$LOG_ALERTS" 2>&1
        return $?
    fi

    log_msg "$LOG_ALERTS" "WARN" "no MTA available, alert NOT sent: $subject"
    return 1
}

# ============================================================
#  АТОМАРНАЯ ЗАПИСЬ JSON (через временный файл)
# ============================================================
safe_write_json() {
    local target="$1" content="$2"
    local tmp
    [ -d "$(dirname "$target")" ] || mkdir -p "$(dirname "$target")" 2>/dev/null
    tmp="$(mktemp "${target}.XXXXXX")" || return 1
    printf '%s' "$content" > "$tmp"
    chmod 0640 "$tmp" 2>/dev/null || true

    # Валидация JSON через python (если есть)
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import json,sys; json.load(open('$tmp'))" 2>/dev/null; then
            mv -f "$tmp" "$target"
        else
            log_error "$MON_INCIDENT_LOG" "JSON malformed, kept tmp: $tmp"
            return 1
        fi
    else
        mv -f "$tmp" "$target"
    fi
}

require_cmd() {
    local rc=0
    for c in "$@"; do
        if ! command -v "$c" >/dev/null 2>&1; then
            log_warn "$MON_INCIDENT_LOG" "missing command: $c"
            rc=1
        fi
    done
    return $rc
}
