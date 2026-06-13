#!/bin/bash
# ============================================================
#  monitor_load.sh — мониторинг нагрузки и автореагирование
#
#  Проверяет: CPU usage, load average, RAM, swap, диск, inode, iowait.
#  При превышении порогов:
#    - алерт по email (с throttle)
#    - попытка освободить ресурсы (если ALERT_AUTORESPONSE=yes):
#         disk full -> очистка /tmp + /var/cache + старые логи
#         RAM full  -> drop_caches, рестарт раздутых сервисов (опц.)
#         swap full -> swapoff/swapon (без потери данных)
#  Все действия безопасные — никаких kill процессов сервисов.
# ============================================================

# НЕ set -u — fault-tolerant поведение. Дефолты через ${var:-...}.
# shellcheck disable=SC1091
source /opt/monitoring/lib/monitor_common.sh

now_ts=$(date +%s)

# --- Сбор метрик ---
# CPU usage % (через mpstat если есть; иначе через /proc/stat)
cpu_idle=""
if command -v mpstat >/dev/null 2>&1; then
    # mpstat 1 1 — одна секунда замера
    cpu_idle="$(LANG=C mpstat 1 1 2>/dev/null | awk '/Average:/ && $2 == "all" {print $NF}' | head -1)"
fi
if [ -z "$cpu_idle" ]; then
    # fallback: /proc/stat
    read -r _ u n s i io _ < /proc/stat
    total1=$(( u + n + s + i + io ))
    sleep 1
    read -r _ u2 n2 s2 i2 io2 _ < /proc/stat
    total2=$(( u2 + n2 + s2 + i2 + io2 ))
    busy=$(( (u2-u) + (n2-n) + (s2-s) ))
    total=$(( total2 - total1 ))
    if [ "$total" -gt 0 ]; then
        cpu_usage=$(( busy * 100 / total ))
    else
        cpu_usage=0
    fi
else
    # LANG=C — иначе в русской локали awk печатает '0,5' вместо '0.5' и JSON падает
    cpu_usage=$(LANG=C awk -v idle="$cpu_idle" 'BEGIN{printf "%.0f", 100 - idle}')
fi

# Load avg 1m
load1="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)"
load5="$(awk '{print $2}' /proc/loadavg 2>/dev/null || echo 0)"
load15="$(awk '{print $3}' /proc/loadavg 2>/dev/null || echo 0)"
cpus="$(nproc 2>/dev/null || echo 1)"

# RAM (используется = total - available)
ram_total=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
ram_avail=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
ram_free=$(awk '/^MemFree:/{print $2}' /proc/meminfo)
if [ -z "$ram_avail" ]; then ram_avail="$ram_free"; fi
ram_used=$(( ram_total - ram_avail ))
ram_pct=$(( ram_used * 100 / (ram_total > 0 ? ram_total : 1) ))

# Swap
swap_total=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
swap_free=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
if [ "${swap_total:-0}" -gt 0 ]; then
    swap_used=$(( swap_total - swap_free ))
    swap_pct=$(( swap_used * 100 / swap_total ))
else
    swap_pct=0
fi

# Диск — / и /var и /home если разные ФС
# ВАЖНО: на REDOS флаги -P и -T НЕСОВМЕСТИМЫ с --output. Используем
# только --output — он сам форматирует вывод как нужно. Раньше df падал
# молча и disks_data оставался пустым → дашборд показывал «нет данных».
disks_data=""
declare -a DISK_WARN
declare -a DISK_CRITICAL
declare -a INODE_WARN
while read -r src fs total used avail pct mp; do
    [ -z "$mp" ] && continue
    # числовой процент без знака %
    p_num="${pct%\%}"
    [ -z "$p_num" ] && continue
    # пропускаем не-числовые (на случай битой строки)
    case "$p_num" in
        ''|*[!0-9]*) continue ;;
    esac
    disks_data="${disks_data}{\"mount\":\"${mp}\",\"used_pct\":${p_num},\"fs\":\"${fs}\"},"
    free_num=$(( 100 - p_num ))
    if [ "$free_num" -lt "${THRESHOLD_DISK_CRITICAL_FREE:-5}" ]; then
        DISK_CRITICAL+=("$mp:${free_num}% free")
    elif [ "$free_num" -lt "${THRESHOLD_DISK_WARNING_FREE:-10}" ]; then
        DISK_WARN+=("$mp:${free_num}% free")
    fi
done < <(df --output=source,fstype,size,used,avail,pcent,target 2>/dev/null \
           | tail -n +2 \
           | awk '$2 !~ /^(tmpfs|devtmpfs|squashfs|overlay|aufs|proc|sysfs|cgroup|cgroup2)$/ {print $0}')
disks_data="${disks_data%,}"

# Inode — то же исправление: убираем -P и -i (--output их перекрывает)
inodes_data=""
while read -r src total used avail pct mp; do
    [ -z "$mp" ] && continue
    p_num="${pct%\%}"
    [ -z "$p_num" ] && continue
    case "$p_num" in
        ''|*[!0-9]*) continue ;;
    esac
    inodes_data="${inodes_data}{\"mount\":\"${mp}\",\"inode_used_pct\":${p_num}},"
    if [ "$p_num" -ge "${THRESHOLD_INODE:-90}" ]; then
        INODE_WARN+=("$mp:$p_num%")
    fi
done < <(df --output=source,itotal,iused,iavail,ipcent,target 2>/dev/null \
           | tail -n +2 \
           | awk '$5 != "-" {print $0}')
inodes_data="${inodes_data%,}"

# iowait — через /proc/stat (3-я колонка от конца с CPU0)
iowait_pct=0
if command -v iostat >/dev/null 2>&1; then
    # LANG=C обязательно — в русской локали iostat и awk печатают через запятую
    iowait_pct="$(LANG=C iostat -c 1 2 2>/dev/null | LANG=C awk '/^ /{w=$4} END{printf "%.0f", w+0}')"
fi
[ -z "$iowait_pct" ] && iowait_pct=0

# --- Проверка порогов и реакция ---
declare -a ACTIONS_TAKEN
declare -a WARNINGS

autorespond="${ALERT_AUTORESPONSE:-yes}"

# CPU: alert only after the threshold is exceeded for the configured duration.
cpu_count_file="${MON_STATE_DIR}/cpu_high_count"
required_cpu_samples=$(( (${THRESHOLD_CPU_DURATION_MIN:-5} * 60 + ${PERFORMANCE_INTERVAL_SEC:-60} - 1) / ${PERFORMANCE_INTERVAL_SEC:-60} ))
cpu_high_count=0
cpu_sustained=no
if [ "$cpu_usage" -ge "${THRESHOLD_CPU:-90}" ]; then
    [ -f "$cpu_count_file" ] && cpu_high_count="$(cat "$cpu_count_file" 2>/dev/null || echo 0)"
    cpu_high_count=$(( cpu_high_count + 1 ))
    echo "$cpu_high_count" > "$cpu_count_file"
    log_warn "$LOG_PERFORMANCE" "CPU high sample ${cpu_high_count}/${required_cpu_samples}: ${cpu_usage}%"
fi
if [ "$cpu_high_count" -ge "$required_cpu_samples" ]; then
    cpu_sustained=yes
    WARNINGS+=("CPU sustained: ${cpu_usage}% >= ${THRESHOLD_CPU}% for ${THRESHOLD_CPU_DURATION_MIN}min")
    log_incident "performance" "CRITICAL" "CPU sustained high" "${cpu_usage}% for ${THRESHOLD_CPU_DURATION_MIN}min"
    if alert_should_send "load_cpu" "${ALERT_THROTTLE_MIN:-15}"; then
        top5="$(ps -eo pid,user,comm,%cpu --sort=-%cpu --no-headers 2>/dev/null | head -5)"
        body="REDOS Monitoring Alert — CPU
============================

Host:      $(hostname)
CPU usage: ${cpu_usage}% (threshold ${THRESHOLD_CPU}% for ${THRESHOLD_CPU_DURATION_MIN} minutes)
Load avg:  ${load1} / ${load5} / ${load15} (${cpus} CPUs)
Time:      $(date '+%Y-%m-%d %H:%M:%S')

Top processes by CPU:
$top5"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} WARN: CPU ${cpu_usage}%" \
            "$body" \
            "${ALERT_TO}"
        alert_mark_sent "load_cpu"
    fi
elif [ "$cpu_usage" -lt "${THRESHOLD_CPU:-90}" ]; then
    rm -f "$cpu_count_file" 2>/dev/null
fi

# Load avg per CPU
load_per_cpu="$(LANG=C awk -v l="$load1" -v c="$cpus" 'BEGIN{printf "%.2f", l/(c>0?c:1)}')"
if awk -v v="$load1" -v t="${THRESHOLD_LOAD1:-4}" 'BEGIN{exit !(v >= t)}'; then
    WARNINGS+=("LOAD1: ${load1} >= ${THRESHOLD_LOAD1}")
    log_warn "$LOG_PERFORMANCE" "load1 high: ${load1}"
    log_incident "load" "WARN" "load1 high" "${load1} / ${cpus} cores"
    if alert_should_send "load_avg" "${ALERT_THROTTLE_MIN:-15}"; then
        body="REDOS Monitoring Alert — Load Average
=====================================

Host:      $(hostname)
Load avg:  ${load1} / ${load5} / ${load15} (${cpus} CPUs)
Threshold: ${THRESHOLD_LOAD1}
Time:      $(date '+%Y-%m-%d %H:%M:%S')"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} WARN: load average" \
            "$body" \
            "${ALERT_TO}"
        alert_mark_sent "load_avg"
    fi
fi

# RAM
if [ "$ram_pct" -ge "${THRESHOLD_RAM:-90}" ]; then
    WARNINGS+=("RAM: ${ram_pct}% >= ${THRESHOLD_RAM}%")
    log_warn "$LOG_PERFORMANCE" "RAM high: ${ram_pct}%"
    log_incident "load" "WARN" "RAM high" "${ram_pct}%"

    if [ "$autorespond" = "yes" ]; then
        # drop_caches — безопасно, ОС вернёт кеш если будет нужно
        echo 1 > /proc/sys/vm/drop_caches 2>/dev/null && {
            ACTIONS_TAKEN+=("drop_caches: page cache очищен")
            log_info "$LOG_PERFORMANCE" "drop_caches=1 executed (page cache)"
        }
    fi

    if alert_should_send "load_mem" "${ALERT_THROTTLE_MIN:-15}"; then
        top5="$(ps -eo pid,user,comm,%mem --sort=-%mem --no-headers 2>/dev/null | head -5)"
        actions_str="$(printf '%s\n' "${ACTIONS_TAKEN[@]:-}" | grep -v '^$' | sed 's/^/  - /')"
        [ -z "$actions_str" ] && actions_str="  (no actions taken)"
        body="REDOS Monitoring Alert — RAM
============================

Host:      $(hostname)
RAM used:  ${ram_pct}% (threshold ${THRESHOLD_RAM}%)
Time:      $(date '+%Y-%m-%d %H:%M:%S')

Top processes by RAM:
$top5

Actions taken:
$actions_str"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} WARN: RAM ${ram_pct}%" \
            "$body" \
            "${ALERT_TO}"
        alert_mark_sent "load_mem"
    fi
fi

# Swap
if [ "$swap_pct" -ge "${THRESHOLD_SWAP:-50}" ]; then
    WARNINGS+=("SWAP: ${swap_pct}% >= ${THRESHOLD_SWAP}%")
    log_warn "$LOG_PERFORMANCE" "swap high: ${swap_pct}%"
    log_incident "load" "WARN" "swap high" "${swap_pct}%"
    if alert_should_send "load_swap" "${ALERT_THROTTLE_MIN:-15}"; then
        body="REDOS Monitoring Alert — SWAP
=============================

Host:        $(hostname)
Swap usage:  ${swap_pct}% (threshold ${THRESHOLD_SWAP}%)
Time:        $(date '+%Y-%m-%d %H:%M:%S')"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} WARN: SWAP ${swap_pct}%" \
            "$body" \
            "${ALERT_TO}"
        alert_mark_sent "load_swap"
    fi
fi

# Диск
if [ ${#DISK_WARN[@]} -gt 0 ] || [ ${#DISK_CRITICAL[@]} -gt 0 ]; then
    for d in "${DISK_WARN[@]:-}"; do
        [ -z "$d" ] && continue
        WARNINGS+=("DISK WARNING: $d")
        log_warn "$LOG_PERFORMANCE" "disk warning: $d"
        log_incident "performance" "WARN" "disk below 10% free" "$d"
    done
    for d in "${DISK_CRITICAL[@]:-}"; do
        [ -z "$d" ] && continue
        WARNINGS+=("DISK CRITICAL: $d")
        log_critical "$LOG_PERFORMANCE" "disk critical: $d"
        log_incident "performance" "CRITICAL" "disk below 5% free" "$d"
    done

    if [ "$autorespond" = "yes" ]; then
        # Очистка /var/cache (yum/dnf), /tmp (старее 7 дней), архивов логов
        if command -v dnf >/dev/null 2>&1; then
            dnf clean all >/dev/null 2>&1 && \
                ACTIONS_TAKEN+=("dnf clean all")
        fi
        # journalctl: оставить 200M последних логов
        if command -v journalctl >/dev/null 2>&1; then
            journalctl --vacuum-size=200M >/dev/null 2>&1 && \
                ACTIONS_TAKEN+=("journalctl --vacuum-size=200M")
        fi
        # старые ротированные логи (gz, .1, .2 и т.д.)
        find /var/log -type f \( -name "*.gz" -o -name "*.[0-9]" -o -name "*.[0-9].gz" \) \
            -mtime +7 -delete 2>/dev/null && \
            ACTIONS_TAKEN+=("rotated logs >7d removed")
        # /tmp старше 7 дней (системный безопасный набор)
        find /tmp -type f -mtime +7 -delete 2>/dev/null && \
            ACTIONS_TAKEN+=("/tmp files >7d removed")
    fi

    if alert_should_send "load_disk" "${ALERT_THROTTLE_MIN:-15}"; then
        disks_str="$(printf '%s\n' "${DISK_WARN[@]:-}" "${DISK_CRITICAL[@]:-}" | grep -v '^$' | sed 's/^/  - /')"
        actions_str="$(printf '%s\n' "${ACTIONS_TAKEN[@]:-}" | grep -v '^$' | sed 's/^/  - /')"
        [ -z "$actions_str" ] && actions_str="  (no actions taken)"
        body="REDOS Monitoring Alert — DISK
=============================

Host:       $(hostname)
Thresholds: warning below ${THRESHOLD_DISK_WARNING_FREE}% free; critical below ${THRESHOLD_DISK_CRITICAL_FREE}% free
Time:       $(date '+%Y-%m-%d %H:%M:%S')

Disks over threshold:
$disks_str

Actions taken:
$actions_str"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} WARN: DISK" \
            "$body" \
            "${ALERT_TO}"
        alert_mark_sent "load_disk"
    fi
fi

# Inode
if [ ${#INODE_WARN[@]} -gt 0 ]; then
    for i in "${INODE_WARN[@]}"; do
        WARNINGS+=("INODE: $i >= ${THRESHOLD_INODE}%")
        log_warn "$LOG_PERFORMANCE" "inode high: $i"
        log_incident "load" "WARN" "inode high" "$i"
    done
    if alert_should_send "load_inode" "${ALERT_THROTTLE_MIN:-15}"; then
        inodes_str="$(printf '%s\n' "${INODE_WARN[@]}" | sed 's/^/  - /')"
        body="REDOS Monitoring Alert — INODE
==============================

Host:      $(hostname)
Threshold: ${THRESHOLD_INODE}%
Time:      $(date '+%Y-%m-%d %H:%M:%S')

Mounts over threshold:
$inodes_str"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} WARN: INODE" \
            "$body" \
            "${ALERT_TO}"
        alert_mark_sent "load_inode"
    fi
fi

# IOwait
if [ "${iowait_pct%.*}" -ge "${THRESHOLD_IOWAIT:-30}" ] 2>/dev/null; then
    WARNINGS+=("IOWAIT: ${iowait_pct}% >= ${THRESHOLD_IOWAIT}%")
    log_warn "$LOG_PERFORMANCE" "iowait high: ${iowait_pct}%"
    log_incident "load" "WARN" "iowait high" "${iowait_pct}%"
    if alert_should_send "load_iowait" "${ALERT_THROTTLE_MIN:-15}"; then
        body="REDOS Monitoring Alert — IOwait
===============================

Host:      $(hostname)
IOwait:    ${iowait_pct}% (threshold ${THRESHOLD_IOWAIT}%)
Time:      $(date '+%Y-%m-%d %H:%M:%S')"
        send_alert "${ALERT_SUBJECT_PREFIX:-[MON]} WARN: IOWAIT ${iowait_pct}%" \
            "$body" \
            "${ALERT_TO}"
        alert_mark_sent "load_iowait"
    fi
fi

# --- Запись JSON состояния ---
# Используем простой конкатенированный JSON — без jq зависимости
warnings_json=""
for w in "${WARNINGS[@]:-}"; do
    [ -z "$w" ] && continue
    # экранируем кавычки
    we="$(printf '%s' "$w" | sed 's/\"/\\\"/g')"
    warnings_json="${warnings_json}\"${we}\","
done
warnings_json="[${warnings_json%,}]"

actions_json=""
for a in "${ACTIONS_TAKEN[@]:-}"; do
    [ -z "$a" ] && continue
    ae="$(printf '%s' "$a" | sed 's/\"/\\\"/g')"
    actions_json="${actions_json}\"${ae}\","
done
actions_json="[${actions_json%,}]"

# Защита от пустых значений — иначе JSON получится битый
# и дашборд молча покажет "нет данных" по всем секциям.
cat > "$STATE_PERFORMANCE.tmp" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "host": "$(hostname)",
  "cpu_usage_pct": ${cpu_usage:-0},
  "cpu_sustained": "${cpu_sustained}",
  "cpu_high_samples": ${cpu_high_count:-0},
  "load": {"1m": ${load1:-0}, "5m": ${load5:-0}, "15m": ${load15:-0}, "cpus": ${cpus:-1}, "per_cpu": ${load_per_cpu:-0}},
  "memory": {"total_kb": ${ram_total:-0}, "used_kb": ${ram_used:-0}, "used_pct": ${ram_pct:-0}},
  "swap": {"total_kb": ${swap_total:-0}, "used_pct": ${swap_pct:-0}},
  "iowait_pct": ${iowait_pct:-0},
  "disks": [${disks_data}],
  "inodes": [${inodes_data}],
  "warnings": ${warnings_json},
  "actions": ${actions_json}
}
EOF

# Валидация JSON перед сохранением — если битый, не подменяем рабочий файл
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c "import json,sys; json.load(open('$STATE_PERFORMANCE.tmp'))" 2>/dev/null; then
        log_error "$LOG_PERFORMANCE" "JSON malformed, keeping previous state file"
        rm -f "$STATE_PERFORMANCE.tmp"
    else
        mv -f "$STATE_PERFORMANCE.tmp" "$STATE_PERFORMANCE" 2>/dev/null
    fi
else
    mv -f "$STATE_PERFORMANCE.tmp" "$STATE_PERFORMANCE" 2>/dev/null
fi
chmod 0640 "$STATE_PERFORMANCE" 2>/dev/null || true

# Compact metric history used by the weekly report graphs.
mkdir -p "$(dirname "$METRICS_HISTORY")" 2>/dev/null
max_disk_used="$(printf '%s\n' "$disks_data" | grep -oE '"used_pct":[0-9]+' | cut -d: -f2 | sort -nr | head -1)"
[ -z "$max_disk_used" ] && max_disk_used=0
if [ ! -f "$METRICS_HISTORY" ]; then
    echo "timestamp,cpu,ram,swap,disk_used,iowait" > "$METRICS_HISTORY"
fi
printf '%s,%s,%s,%s,%s,%s\n' "$(date -Iseconds)" "$cpu_usage" "$ram_pct" "$swap_pct" "$max_disk_used" "$iowait_pct" >> "$METRICS_HISTORY"
find "$(dirname "$METRICS_HISTORY")" -type f -name '*.csv' -mtime +35 -delete 2>/dev/null || true
tail -n 60000 "$METRICS_HISTORY" > "${METRICS_HISTORY}.tmp" && mv -f "${METRICS_HISTORY}.tmp" "$METRICS_HISTORY"
chmod 0640 "$METRICS_HISTORY" 2>/dev/null || true

log_info "$LOG_PERFORMANCE" "load check finished | cpu=${cpu_usage}% mem=${ram_pct}% swap=${swap_pct}% iowait=${iowait_pct}% warnings=${#WARNINGS[@]}"
exit 0
