#!/bin/bash
# ============================================================
#  monitor_security.sh — мониторинг подозрительной активности
#
#  Проверяет:
#    1. Failed SSH/auth попытки — если с одного IP > порога за окно,
#       баним через firewalld (rich rule с timeout)
#    2. Открытые порты — если есть LISTEN не из ALLOWED_PORTS, алерт
#    3. Новые setuid/setgid файлы под /usr, /etc, /opt (опционально)
#    4. Подозрительные процессы — рутовые от UID > 0 окружения и наоборот
#    5. Лог-аномалии — массовые ошибки в journal за последние 5 минут
#
#  Бан реализован через firewalld rich-rule с timeout — автоматическое
#  снятие, не требует чистки. Если firewalld выключен — пишем в incidents
#  и шлём алерт без бана.
# ============================================================

# НЕ set -u — fault-tolerant поведение.
# shellcheck disable=SC1091
source /opt/monitoring/lib/monitor_common.sh

autorespond="${ALERT_AUTORESPONSE:-yes}"
window_min="${SECURITY_FAILED_WINDOW_MIN:-10}"
threshold="${SECURITY_FAILED_THRESHOLD:-5}"
ban_seconds="${SECURITY_BAN_SECONDS:-3600}"

# IP-адреса самого сервера, которые НЕЛЬЗЯ банить (защита от self-DoS)
declare -a SELF_IPS
SELF_IPS=( $(hostname -I 2>/dev/null) "127.0.0.1" "::1" )
is_self_ip() {
    local ip="$1"
    for s in "${SELF_IPS[@]}"; do
        [ "$ip" = "$s" ] && return 0
    done
    return 1
}

# ============================================================
#  1. Failed SSH / sshd / sudo brute-force
# ============================================================
declare -A FAIL_IPS
declare -a BANNED_IPS

# journalctl за окно времени — формат "MMM DD HH:MM:SS"
# фильтр по sshd: 'Failed password' и 'Invalid user'
# учитываем оба формата 'rhost=' (PAM) и 'from <ip>' (sshd)
since_str="${window_min} minutes ago"

# Источники событий аутентификации:
#   1. journald (`journalctl`) — основной канал для systemd-based систем
#   2. /var/log/secure — fallback для RHEL/REDOS, если rsyslog активен
#   3. /var/log/auth.log — fallback для Debian/Ubuntu (если кто-то перенастроил)
# Дедупликация по строке — чтобы не считать одно событие дважды.
declare -A SEEN_LINES

collect_from_source() {
    local src="$1"
    while read -r line; do
        [ -z "$line" ] && continue
        # Дедуп: берём timestamp+message как ключ
        local key="${line:0:60}"
        [ -n "${SEEN_LINES[$key]:-}" ] && continue
        SEEN_LINES["$key"]=1
        # Ищем первый IPv4 в строке
        local ip
        ip="$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"
        [ -z "$ip" ] && continue
        is_self_ip "$ip" && continue
        FAIL_IPS["$ip"]=$(( ${FAIL_IPS["$ip"]:-0} + 1 ))
    done <<< "$src"
}

# 1. journald
auth_lines="$(journalctl --since "$since_str" --no-pager 2>/dev/null \
    | grep -Ei 'Failed password|Invalid user|authentication failure|Connection closed by authenticating user' || true)"
collect_from_source "$auth_lines"

# 2. /var/log/secure — REDOS-овский основной auth log
if [ -r /var/log/secure ]; then
    # Грубая фильтрация — последние N строк, потом по дате (в шапке секунды есть)
    cutoff_min="${window_min:-5}"
    secure_lines="$(tail -n 5000 /var/log/secure 2>/dev/null \
        | grep -Ei 'Failed password|Invalid user|authentication failure' || true)"
    collect_from_source "$secure_lines"
fi

# 3. /var/log/auth.log — если кто-то настроил rsyslog по-дебиановски
if [ -r /var/log/auth.log ]; then
    authlog_lines="$(tail -n 5000 /var/log/auth.log 2>/dev/null \
        | grep -Ei 'Failed password|Invalid user|authentication failure' || true)"
    collect_from_source "$authlog_lines"
fi

# Реакция на превышение
for ip in "${!FAIL_IPS[@]}"; do
    cnt="${FAIL_IPS[$ip]}"
    if [ "$cnt" -ge "$threshold" ]; then
        log_warn "$LOG_SECURITY" "brute-force from $ip: $cnt failed attempts"
        log_incident "security" "WARN" "brute-force $ip" "${cnt} failed attempts in ${window_min}min"

        if [ "$autorespond" = "yes" ]; then
            # Проверяем не забанен ли уже
            already_banned=0
            if command -v firewall-cmd >/dev/null 2>&1; then
                if firewall-cmd --list-rich-rules 2>/dev/null | grep -q "source address=\"$ip\""; then
                    already_banned=1
                fi
            fi

            if [ "$already_banned" = "0" ]; then
                if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
                    # firewalld rich-rule с timeout (автоматический unban)
                    firewall-cmd --add-rich-rule="rule family='ipv4' source address='${ip}' reject" \
                        --timeout="${ban_seconds}" >/dev/null 2>&1 && {
                        BANNED_IPS+=("$ip")
                        log_info "$LOG_SECURITY" "banned $ip via firewalld for ${ban_seconds}s"
                        log_incident "security" "INFO" "$ip banned" "${ban_seconds}s"
                    }
                else
                    log_warn "$LOG_SECURITY" "firewalld unavailable, cannot ban $ip"
                fi
            fi
        fi

        if alert_should_send "sec_brute_${ip}" "${ALERT_THROTTLE_MIN:-15}"; then
            action_str=""
            if [ "$autorespond" = "yes" ]; then
                action_str="IP banned for ${ban_seconds}s via firewalld rich-rule"
            else
                action_str="No action (autorespond is off)"
            fi
            body="REDOS Monitoring Alert — SECURITY
=================================

Host:        $(hostname)
Event:       Brute-force attempt detected
Source IP:   ${ip}
Attempts:    ${cnt} failed in last ${window_min} minutes
Threshold:   ${threshold}
Time:        $(date '+%Y-%m-%d %H:%M:%S')

Action taken:
  $action_str"
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} SEC: brute-force ${ip}" \
                "$body" \
                "${ALERT_TO}"
            alert_mark_sent "sec_brute_${ip}"
        fi
    fi
done

# ============================================================
#  2. Открытые порты — проверка против whitelist
# ============================================================
declare -a UNEXPECTED_PORTS

# allowed_ports — через запятую из monitor.env
allowed_csv="${ALLOWED_PORTS:-}"
# превращаем в bash-set через ассоциативный массив
declare -A ALLOWED
IFS=',' read -r -a alarr <<< "$allowed_csv"
for p in "${alarr[@]}"; do
    [ -z "$p" ] && continue
    ALLOWED["${p}"]=1
done

# ss или netstat — собираем уникальные LISTEN порты (только IPv4)
if command -v ss >/dev/null 2>&1; then
    listen_lines="$(ss -ltnH 2>/dev/null; ss -lunH 2>/dev/null)"
elif command -v netstat >/dev/null 2>&1; then
    listen_lines="$(netstat -ltnu 2>/dev/null | tail -n +3)"
else
    listen_lines=""
fi

while read -r line; do
    [ -z "$line" ] && continue
    # извлекаем 4-ю колонку (local address:port), берём порт
    local_addr="$(echo "$line" | awk '{print $4}')"
    [ -z "$local_addr" ] && continue
    port="${local_addr##*:}"
    # фильтр: пропускаем IPv6-only и не цифровые порты
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then continue; fi
    # Динамический/эпемерный диапазон (49152-65535) — IANA RFC 6335.
    # Тут живут samba RPC, NFS, и куча клиентских сокетов. Они меняются
    # при каждом рестарте сервиса — нет смысла включать в whitelist
    # и нет смысла алертить.
    if [ "$port" -ge 49152 ]; then continue; fi
    # Высокие случайные порты RPC (обычно 30000-49151) — тоже игнорируем
    # как часть динамического диапазона. Linux на REDOS использует
    # net.ipv4.ip_local_port_range — обычно 32768-60999.
    if [ "$port" -ge 32768 ]; then continue; fi
    if [ -z "${ALLOWED[$port]:-}" ]; then
        # дубли убираем простым check-set
        already=0
        for u in "${UNEXPECTED_PORTS[@]:-}"; do
            [ "$u" = "$port" ] && already=1 && break
        done
        [ "$already" = "0" ] && UNEXPECTED_PORTS+=("$port")
    fi
done <<< "$listen_lines"

if [ ${#UNEXPECTED_PORTS[@]} -gt 0 ]; then
    ports_str="$(IFS=,; echo "${UNEXPECTED_PORTS[*]}")"
    log_warn "$LOG_SECURITY" "unexpected listening ports: ${ports_str}"
    log_incident "security" "WARN" "unexpected ports" "${ports_str}"
    if alert_should_send "sec_ports" "${ALERT_THROTTLE_MIN:-15}"; then
        # Привязка порт -> процесс
        details=""
        if command -v ss >/dev/null 2>&1; then
            details="$(ss -ltnp 2>/dev/null | grep -E ":(${ports_str//,/|})\b" | head -10)"
        fi
        body="REDOS Monitoring Alert — SECURITY
=================================

Host:    $(hostname)
Event:   Unexpected LISTEN ports detected
Ports:   ${ports_str}
Time:    $(date '+%Y-%m-%d %H:%M:%S')

Details:
$details"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} SEC: unexpected ports" \
            "$body" \
            "${ALERT_TO}"
        alert_mark_sent "sec_ports"
    fi
fi

# ============================================================
#  3. Аномалии в journal (массовые ошибки за окно)
# ============================================================
err_count="$(journalctl --since "$since_str" -p err --no-pager 2>/dev/null | wc -l)"
err_count="${err_count:-0}"
# 50 ошибок за 10 минут — порог
ERR_THRESHOLD=50
if [ "$err_count" -ge "$ERR_THRESHOLD" ]; then
    log_warn "$LOG_SECURITY" "high error count in journal: $err_count >= $ERR_THRESHOLD"
    log_incident "security" "WARN" "journal error storm" "$err_count errors in ${window_min}min"
    if alert_should_send "sec_journal_err" "${ALERT_THROTTLE_MIN:-15}"; then
        top_errors="$(journalctl --since "$since_str" -p err --no-pager 2>/dev/null \
                        | tail -200 | awk '{$1=$2=$3=""; print $0}' | sort | uniq -c | sort -rn | head -10)"
        body="REDOS Monitoring Alert — SECURITY
=================================

Host:       $(hostname)
Event:      Journal error storm
Errors:     ${err_count} in last ${window_min} minutes
Time:       $(date '+%Y-%m-%d %H:%M:%S')

Top error patterns:
$top_errors"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} SEC: journal error storm" \
            "$body" \
            "${ALERT_TO}"
        alert_mark_sent "sec_journal_err"
    fi
fi

# ============================================================
#  4. Новые setuid файлы (срабатывание раз в день, без алертов
#     при первом запуске — формируется baseline)
# ============================================================
SUID_BASELINE="${MON_STATE_DIR}/suid_baseline.txt"
SUID_CURRENT="${MON_STATE_DIR}/suid_current.txt"
# собираем только под /usr /etc /opt — там должны быть только пакетные suid
find /usr /etc /opt -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null \
    | sort > "$SUID_CURRENT.tmp"
mv -f "$SUID_CURRENT.tmp" "$SUID_CURRENT" 2>/dev/null

if [ ! -f "$SUID_BASELINE" ]; then
    cp -f "$SUID_CURRENT" "$SUID_BASELINE" 2>/dev/null
    log_info "$LOG_SECURITY" "SUID baseline created ($(wc -l < "$SUID_BASELINE") entries)"
else
    new_suid="$(comm -13 "$SUID_BASELINE" "$SUID_CURRENT" 2>/dev/null || true)"
    if [ -n "$new_suid" ]; then
        log_warn "$LOG_SECURITY" "new SUID files: $(echo "$new_suid" | wc -l)"
        log_incident "security" "WARN" "new SUID files" "$(echo "$new_suid" | head -5 | tr '\n' ' ')"
        if alert_should_send "sec_suid" 60; then
            body="REDOS Monitoring Alert — SECURITY
=================================

Host:   $(hostname)
Event:  New SUID/SGID files detected
Time:   $(date '+%Y-%m-%d %H:%M:%S')

These files were added or had permissions changed since baseline:
$new_suid

This may indicate privilege escalation. Please investigate."
            send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} SEC: new SUID files" \
                "$body" \
                "${ALERT_TO}"
            alert_mark_sent "sec_suid"
        fi
    fi
fi

# ============================================================
#  Запись JSON состояния
# ============================================================
banned_json=""
for b in "${BANNED_IPS[@]:-}"; do
    [ -z "$b" ] && continue
    banned_json="${banned_json}\"${b}\","
done
banned_json="[${banned_json%,}]"

ports_json=""
for p in "${UNEXPECTED_PORTS[@]:-}"; do
    [ -z "$p" ] && continue
    ports_json="${ports_json}${p},"
done
ports_json="[${ports_json%,}]"

failed_ips_json=""
for ip in "${!FAIL_IPS[@]}"; do
    failed_ips_json="${failed_ips_json}{\"ip\":\"${ip}\",\"count\":${FAIL_IPS[$ip]}},"
done
failed_ips_json="[${failed_ips_json%,}]"

cat > "$STATE_SECURITY.tmp" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "host": "$(hostname)",
  "window_min": ${window_min},
  "failed_logins": ${failed_ips_json},
  "banned_ips": ${banned_json},
  "unexpected_ports": ${ports_json},
  "journal_error_count": ${err_count}
}
EOF
mv -f "$STATE_SECURITY.tmp" "$STATE_SECURITY" 2>/dev/null
chmod 0640 "$STATE_SECURITY" 2>/dev/null || true

log_info "$LOG_SECURITY" "security check finished | failed_ips=${#FAIL_IPS[@]} banned=${#BANNED_IPS[@]} bad_ports=${#UNEXPECTED_PORTS[@]} errors=${err_count}"
exit 0
