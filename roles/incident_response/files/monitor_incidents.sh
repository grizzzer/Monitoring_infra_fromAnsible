#!/bin/bash
# ============================================================
#  monitor_incidents.sh — расширенное реагирование на инциденты
#
#  Закрывает «белые пятна», которые не покрыты другими скриптами:
#
#    1. NETWORK   — состояние линков, IP forwarding, NetworkManager,
#                   проверка дефолтного шлюза. Авто-восстановление
#                   через `ip link set up` + перезапуск NetworkManager.
#
#    2. DNS       — резолвинг известных имён (внешний и внутренний).
#                   Если DNS не отвечает → samba (или named) рестартим.
#
#    3. TIME      — рассинхронизация времени критична для Kerberos/AD
#                   и SSL. Проверяем chronyc tracking; при drift > 60с
#                   форсируем синхронизацию.
#
#    4. CERTS     — SSL-сертификаты samba/iredmail — алерт если
#                   осталось <30 дней.
#
#    5. OOM       — детект OOM-killer событий за окно. Алерт если
#                   ядро убивало процессы.
#
#    6. MAIL      — состояние postfix mail queue. При переполнении —
#                   flush очереди, алерт.
#
#    7. SOCKETS   — детект аномального числа CLOSE_WAIT / TIME_WAIT
#                   (часто признак утечки соединений или DoS).
#
#    8. SELF      — самоконтроль: проверка что monitor_services и др.
#                   реально запускались за последний период. Если нет —
#                   рестарт таймера + критический алерт.
#
#  Все действия безопасные и идемпотентные.
# ============================================================

# НЕ set -u: скрипт должен переживать отсутствие переменных
# shellcheck disable=SC1091
source /opt/monitoring/lib/monitor_common.sh

autorespond="${ALERT_AUTORESPONSE:-yes}"
window_min="${SECURITY_WINDOW_MIN:-10}"

declare -a ACTIONS
declare -a INCIDENTS

incident() {
    local cat="$1" sev="$2" subj="$3" detail="$4"
    INCIDENTS+=("$cat|$sev|$subj|$detail")
    log_incident "$cat" "$sev" "$subj" "$detail"
}

# ============================================================
#  1. NETWORK — link state, gateway, NetworkManager
# ============================================================
check_network() {
    local rc_total=0

    # Список ethernet-интерфейсов (без lo/virbr/docker)
    local ifaces
    ifaces="$(ip -o link show 2>/dev/null \
              | awk -F': ' '{print $2}' \
              | grep -Ev '^(lo|virbr|docker|veth|cni)' \
              | sed 's/@.*//')"

    for ifc in $ifaces; do
        local state operstate
        operstate="$(cat /sys/class/net/"$ifc"/operstate 2>/dev/null)"
        if [ "$operstate" != "up" ]; then
            log_warn "$LOG_INCIDENTS" "interface $ifc operstate=$operstate"
            incident "network" "WARN" "interface down" "$ifc=$operstate"

            if [ "$autorespond" = "yes" ]; then
                # Попытка поднять без перезапуска NetworkManager (мягкое восст.)
                if ip link set "$ifc" up 2>/dev/null; then
                    sleep 2
                    operstate="$(cat /sys/class/net/"$ifc"/operstate 2>/dev/null)"
                    if [ "$operstate" = "up" ]; then
                        ACTIONS+=("network: ip link set $ifc up — OK")
                        log_info "$LOG_INCIDENTS" "interface $ifc recovered"
                    else
                        ACTIONS+=("network: ip link set $ifc up — FAILED, $operstate")
                        rc_total=$((rc_total+1))
                    fi
                fi
            fi
        fi
    done

    # IP forwarding (нужно для шлюза)
    local fwd
    fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
    if [ "$fwd" = "0" ]; then
        log_warn "$LOG_INCIDENTS" "ip_forward disabled"
        if [ "$autorespond" = "yes" ]; then
            sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 && \
                ACTIONS+=("sysctl: ip_forward=1 восстановлен")
        fi
        incident "network" "WARN" "ip_forward off" "восстановлено: $autorespond"
    fi

    # Дефолтный шлюз
    if ! ip route show default 2>/dev/null | grep -q default; then
        log_warn "$LOG_INCIDENTS" "no default route"
        incident "network" "WARN" "no default route" "проверьте NetworkManager"
        # Не пытаемся «угадать» шлюз — слишком опасно
    fi

    # NetworkManager сам активен?
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files --no-pager 2>/dev/null | grep -q '^NetworkManager.service'; then
            local nm_state
            nm_state="$(systemctl is-active NetworkManager 2>/dev/null)"
            if [ "$nm_state" != "active" ]; then
                log_warn "$LOG_INCIDENTS" "NetworkManager $nm_state"
                if [ "$autorespond" = "yes" ]; then
                    systemctl restart NetworkManager 2>/dev/null && \
                        ACTIONS+=("NetworkManager restart")
                fi
                incident "network" "CRITICAL" "NetworkManager $nm_state" "восстанавливаем"
            fi
        fi
    fi

    return $rc_total
}

# ============================================================
#  2. DNS — резолвинг
# ============================================================
check_dns() {
    local rc=0

    # Внутренний домен — должен резолвиться через samba
    local server_host="${SERVER_HOST:-admin.redos.test}"
    local internal_ok=0
    if command -v host >/dev/null 2>&1; then
        host -W 3 "$server_host" 127.0.0.1 >/dev/null 2>&1 && internal_ok=1
    elif command -v getent >/dev/null 2>&1; then
        getent hosts "$server_host" >/dev/null 2>&1 && internal_ok=1
    fi

    if [ "$internal_ok" = "0" ]; then
        log_warn "$LOG_INCIDENTS" "internal DNS not resolving $server_host"
        incident "dns" "WARN" "internal DNS fail" "$server_host через 127.0.0.1"

        if [ "$autorespond" = "yes" ]; then
            # samba предоставляет DNS на 53 порту — рестартим её
            if systemctl is-active samba >/dev/null 2>&1; then
                systemctl restart samba 2>/dev/null && \
                    ACTIONS+=("samba restart (DNS-backend)") && \
                    sleep 5
            elif systemctl is-active named >/dev/null 2>&1; then
                systemctl restart named 2>/dev/null && \
                    ACTIONS+=("named restart")
            fi
        fi

        if alert_should_send "inc_dns_internal" "${ALERT_THROTTLE_MIN:-15}"; then
            body="REDOS Monitoring Alert — DNS
============================

Host:    $(hostname)
Event:   Internal DNS resolution failed
Target:  $server_host
Server:  127.0.0.1 (samba/named)
Time:    $(date '+%Y-%m-%d %H:%M:%S')

Auto-action: restarting samba/named DNS backend"
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} DNS internal fail" \
                "$body" \
                "${ALERT_TO}"
            alert_mark_sent "inc_dns_internal"
        fi
        rc=$((rc+1))
    fi

    # Внешний резолвинг через 8.8.8.8 — нужен для dnf, ssl, smtp relay
    local external_ok=0
    if command -v host >/dev/null 2>&1; then
        host -W 3 redos.red-soft.ru 8.8.8.8 >/dev/null 2>&1 && external_ok=1
    fi
    if [ "$external_ok" = "0" ]; then
        log_warn "$LOG_INCIDENTS" "external DNS fail (8.8.8.8 не отвечает)"
        incident "dns" "WARN" "external DNS fail" "8.8.8.8 unreachable"
        # внешний DNS НЕ восстанавливаем — это проблема провайдера
        if alert_should_send "inc_dns_external" 30; then
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} DNS external fail" \
                "Внешний DNS (8.8.8.8) не отвечает с $(hostname). Проверьте маршрутизацию." \
                "${ALERT_TO}"
            alert_mark_sent "inc_dns_external"
        fi
    fi

    return $rc
}

# ============================================================
#  3. TIME SYNC — критично для Kerberos/AD
# ============================================================
check_time() {
    # Допустимый drift: 60 секунд (Kerberos requirement по умолчанию — 5 минут,
    # но 60с — это запас для безопасности)
    local max_drift=60

    if command -v chronyc >/dev/null 2>&1 && systemctl is-active chronyd >/dev/null 2>&1; then
        # chronyc tracking → ищем Last offset
        local offset
        offset="$(chronyc tracking 2>/dev/null | awk -F: '/Last offset/{gsub(/[ ]+seconds.*/,"",$2); print $2}')"
        # offset может быть в формате "+0.000000123" или "-0.5"
        local offset_abs
        offset_abs="$(awk -v o="$offset" 'BEGIN{ o=(o<0)?-o:o; printf "%.3f", o }')"
        local drift_int="${offset_abs%.*}"
        [ -z "$drift_int" ] && drift_int=0

        if [ "$drift_int" -ge "$max_drift" ]; then
            log_warn "$LOG_INCIDENTS" "time drift: ${offset}s"
            incident "time" "CRITICAL" "time drift" "${offset}s (max ${max_drift}s)"

            if [ "$autorespond" = "yes" ]; then
                # makestep — принудительная синхронизация
                chronyc makestep 2>/dev/null && \
                    ACTIONS+=("chronyc makestep — sync forced")
            fi
            if alert_should_send "inc_time_drift" 30; then
                body="REDOS Monitoring Alert — TIME
=============================

Host:        $(hostname)
Event:       Clock drift detected
Drift:       ${offset}s
Max allowed: ${max_drift}s
Time:        $(date '+%Y-%m-%d %H:%M:%S')

WARNING: Time drift breaks Kerberos, Active Directory, and SSL.

Auto-action: chronyc makestep (force sync)"
                send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} TIME drift ${offset}s" \
                    "$body" \
                    "${ALERT_TO}"
                alert_mark_sent "inc_time_drift"
            fi
        fi
    elif command -v timedatectl >/dev/null 2>&1; then
        # Fallback: systemd-timesyncd
        local sync
        sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
        if [ "$sync" != "yes" ]; then
            log_warn "$LOG_INCIDENTS" "NTP not synchronized"
            incident "time" "WARN" "NTP not sync" "timedatectl: $sync"
            if [ "$autorespond" = "yes" ]; then
                systemctl restart systemd-timesyncd 2>/dev/null && \
                    ACTIONS+=("systemd-timesyncd restart")
            fi
        fi
    fi
}

# ============================================================
#  4. CERTS — SSL expiration
# ============================================================
check_certs() {
    local warn_days=30

    local cert_paths=(
        "/etc/pki/tls/certs/admin.redos.test.crt"          # samba (полуфинал)
        "/etc/pki/tls/certs/iRedMail.crt"                  # iRedMail
        "/etc/nginx/ssl/iRedMail.crt"                      # iRedMail Nginx
        "/etc/pki/tls/certs/localhost.crt"                 # дефолтный httpd
    )

    if ! command -v openssl >/dev/null 2>&1; then
        return 0
    fi

    for cert in "${cert_paths[@]}"; do
        [ -f "$cert" ] || continue
        local end_date end_ts now_ts days_left
        end_date="$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)"
        [ -z "$end_date" ] && continue
        end_ts="$(date -d "$end_date" +%s 2>/dev/null)"
        now_ts="$(date +%s)"
        days_left=$(( (end_ts - now_ts) / 86400 ))

        if [ "$days_left" -lt 0 ]; then
            log_warn "$LOG_INCIDENTS" "cert EXPIRED: $cert (${days_left}d)"
            incident "cert" "CRITICAL" "cert expired" "$cert (${days_left}d ago)"
            if alert_should_send "inc_cert_$(basename "$cert")" 720; then  # раз в 12 часов
                body="REDOS Monitoring Alert — CERT EXPIRED
=====================================

Host:         $(hostname)
Certificate:  $cert
Status:       EXPIRED
Expired:      ${days_left} days ago
Time:         $(date '+%Y-%m-%d %H:%M:%S')

CRITICAL: TLS connections to this service will fail.
Please renew the certificate immediately."
                send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} CERT EXPIRED" \
                    "$body" \
                    "${ALERT_TO}"
                alert_mark_sent "inc_cert_$(basename "$cert")"
            fi
        elif [ "$days_left" -lt "$warn_days" ]; then
            log_warn "$LOG_INCIDENTS" "cert expiring: $cert (${days_left}d)"
            incident "cert" "WARN" "cert expires soon" "$cert (${days_left}d)"
            if alert_should_send "inc_cert_$(basename "$cert")" 1440; then  # раз в сутки
                body="REDOS Monitoring Alert — CERT expiring soon
===========================================

Host:           $(hostname)
Certificate:    $cert
Days remaining: ${days_left}
Warning at:     ${warn_days} days
Time:           $(date '+%Y-%m-%d %H:%M:%S')

Please schedule renewal before expiration."
                send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} CERT expires in ${days_left}d" \
                    "$body" \
                    "${ALERT_TO}"
                alert_mark_sent "inc_cert_$(basename "$cert")"
            fi
        fi
    done
}

# ============================================================
#  5. OOM — out-of-memory killer события
# ============================================================
check_oom() {
    local since="${window_min:-10} minutes ago"
    local oom_lines oom_count
    oom_lines="$(journalctl -k --since "$since" --no-pager 2>/dev/null \
                   | grep -iE 'killed process|out of memory' \
                   | tail -20)"
    oom_count="$(printf '%s\n' "$oom_lines" | grep -cE 'killed process|out of memory' 2>/dev/null || echo 0)"

    if [ "$oom_count" -gt 0 ]; then
        log_warn "$LOG_INCIDENTS" "OOM events: $oom_count"
        incident "oom" "CRITICAL" "OOM-killer triggered" "$oom_count events"
        if alert_should_send "inc_oom" 30; then
            body="REDOS Monitoring Alert — OOM
============================

Host:        $(hostname)
Event:       OOM-killer triggered
Window:      Last ${window_min} minutes
Kill count:  ${oom_count}
Time:        $(date '+%Y-%m-%d %H:%M:%S')

Kernel killed processes due to out-of-memory:

$oom_lines"
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} OOM-killer triggered" \
                "$body" \
                "${ALERT_TO}"
            alert_mark_sent "inc_oom"
        fi
    fi
}

# ============================================================
#  6. MAIL QUEUE — постфикс
# ============================================================
check_mail_queue() {
    # Только если postfix установлен
    if ! command -v postqueue >/dev/null 2>&1; then
        return 0
    fi
    if ! systemctl is-active postfix >/dev/null 2>&1; then
        return 0
    fi

    local queue_count
    queue_count="$(postqueue -p 2>/dev/null | tail -1 | awk '{print $5}')"
    [ -z "$queue_count" ] && queue_count=0
    # формат "-- N Kbytes in M Requests" → берём M (Requests)
    queue_count="$(postqueue -p 2>/dev/null | tail -1 | grep -oE '[0-9]+ Request' | grep -oE '[0-9]+' | head -1)"
    [ -z "$queue_count" ] && queue_count=0

    local queue_threshold=100
    if [ "$queue_count" -ge "$queue_threshold" ]; then
        log_warn "$LOG_INCIDENTS" "mail queue: $queue_count messages"
        incident "mail" "WARN" "mail queue overflow" "$queue_count messages"
        if [ "$autorespond" = "yes" ]; then
            postqueue -f >/dev/null 2>&1 && \
                ACTIONS+=("postqueue -f: flush attempt")
        fi
        if alert_should_send "inc_mailq" 30; then
            body="REDOS Monitoring Alert — MAIL QUEUE
==================================

Host:        $(hostname)
Event:       Postfix queue overflow
Queue size:  ${queue_count} messages
Threshold:   ${queue_threshold}
Time:        $(date '+%Y-%m-%d %H:%M:%S')

Auto-action: postqueue -f (flush queue)"
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} MAIL queue ${queue_count}" \
                "$body" \
                "${ALERT_TO}"
            alert_mark_sent "inc_mailq"
        fi
    fi
}

# ============================================================
#  7. SOCKETS — состояния TCP
# ============================================================
check_sockets() {
    if ! command -v ss >/dev/null 2>&1; then
        return 0
    fi

    local close_wait time_wait
    close_wait="$(ss -tan state close-wait 2>/dev/null | tail -n +2 | wc -l)"
    time_wait="$(ss -tan state time-wait 2>/dev/null | tail -n +2 | wc -l)"

    local cw_threshold=200
    local tw_threshold=2000

    if [ "$close_wait" -ge "$cw_threshold" ]; then
        log_warn "$LOG_INCIDENTS" "CLOSE_WAIT: $close_wait"
        incident "sockets" "WARN" "CLOSE_WAIT high" "$close_wait sockets — возможна утечка"
        if alert_should_send "inc_close_wait" 30; then
            top="$(ss -tan state close-wait 2>/dev/null | awk '{print $4}' | sort | uniq -c | sort -rn | head -5)"
            body="REDOS Monitoring Alert — SOCKETS
================================

Host:       $(hostname)
Event:      Excessive CLOSE_WAIT sockets
Count:      ${close_wait}
Threshold:  ${cw_threshold}
Time:       $(date '+%Y-%m-%d %H:%M:%S')

CLOSE_WAIT spike often means an application is not closing
connections properly (connection leak). Investigate.

Top local addresses:
$top"
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} CLOSE_WAIT ${close_wait}" \
                "$body" \
                "${ALERT_TO}"
            alert_mark_sent "inc_close_wait"
        fi
    fi
    if [ "$time_wait" -ge "$tw_threshold" ]; then
        log_warn "$LOG_INCIDENTS" "TIME_WAIT: $time_wait"
        incident "sockets" "WARN" "TIME_WAIT high" "$time_wait sockets"
    fi
}

# ============================================================
#  8. SELF — мониторинг работает?
# ============================================================
check_self() {
    # Проверяем что state_services.json свежий (моложе 5 минут).
    # Если нет — таймер сломался или скрипт висит.
    local max_age=600
    local now_ts age
    now_ts="$(date +%s)"

    for state_file in "$STATE_SERVICES" "$STATE_LOAD" "$STATE_SECURITY"; do
        [ -f "$state_file" ] || continue
        local mtime
        mtime="$(stat -c %Y "$state_file" 2>/dev/null)"
        [ -z "$mtime" ] && continue
        age=$((now_ts - mtime))
        if [ "$age" -gt "$max_age" ]; then
            local short="$(basename "$state_file")"
            log_warn "$LOG_INCIDENTS" "stale state file: $short age=${age}s"
            incident "self" "WARN" "stale monitoring" "$short ${age}s old"

            # Попробуем рестартить соответствующий таймер
            local timer=""
            case "$short" in
                state_services.json) timer="monitor-services.timer" ;;
                state_load.json|state_performance.json) timer="monitor-performance.timer" ;;
                state_security.json) timer="monitor-security.timer" ;;
            esac
            if [ -n "$timer" ] && [ "$autorespond" = "yes" ]; then
                systemctl restart "$timer" 2>/dev/null && \
                    ACTIONS+=("self-heal: $timer restart")
            fi
            if alert_should_send "inc_self_$short" 60; then
                body="REDOS Monitoring Alert — SELF-CHECK
==================================

Host:           $(hostname)
Event:          Monitoring data stale
State file:     $short
Age:            ${age}s
Max allowed:    ${max_age}s
Time:           $(date '+%Y-%m-%d %H:%M:%S')

The monitoring timer for this check appears stuck.
Auto-action: restart $timer"
                send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} self-monitoring stale" \
                    "$body" \
                    "${ALERT_TO}"
                alert_mark_sent "inc_self_$short"
            fi
        fi
    done
}

# ============================================================
#  MAIN — запуск всех проверок последовательно, ловим любые ошибки
# ============================================================
log_info "$LOG_INCIDENTS" "incident check started"

check_network    || true
check_dns        || true
check_time       || true
check_certs      || true
check_oom        || true
check_mail_queue || true
check_sockets    || true
check_self       || true

# JSON состояния
incidents_json=""
for inc in "${INCIDENTS[@]:-}"; do
    [ -z "$inc" ] && continue
    IFS='|' read -r cat sev sbj det <<< "$inc"
    incidents_json="${incidents_json}{\"category\":\"$cat\",\"severity\":\"$sev\",\"subject\":\"$sbj\",\"detail\":\"$det\"},"
done
incidents_json="[${incidents_json%,}]"

actions_json=""
for a in "${ACTIONS[@]:-}"; do
    [ -z "$a" ] && continue
    ae="$(printf '%s' "$a" | sed 's/\"/\\\"/g')"
    actions_json="${actions_json}\"${ae}\","
done
actions_json="[${actions_json%,}]"

STATE_INCIDENTS="${MON_STATE_DIR}/state_incidents.json"
cat > "$STATE_INCIDENTS.tmp" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "host": "$(hostname)",
  "incidents": ${incidents_json},
  "actions_taken": ${actions_json}
}
EOF
mv -f "$STATE_INCIDENTS.tmp" "$STATE_INCIDENTS" 2>/dev/null
chmod 0640 "$STATE_INCIDENTS" 2>/dev/null || true

log_info "$LOG_INCIDENTS" "incident check finished | incidents=${#INCIDENTS[@]} actions=${#ACTIONS[@]}"
exit 0
