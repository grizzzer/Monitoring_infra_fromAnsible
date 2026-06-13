#!/bin/bash
# ============================================================
#  monitor_send_mail.sh — отправка email через iRedMail
#
#  Использование:
#    monitor_send_mail.sh "Subject" "Body" [recipient]
#
#  Цепочка отправки:
#    1. SMTP с авторизацией (submission 587 + STARTTLS + SASL AUTH)
#       — если в monitor.env есть SMTP_USER/SMTP_PASSWORD
#       — отправка от имени authenticated user (требование "безопасность")
#    2. Локальный sendmail (postfix) — fallback
#    3. mailx — последний fallback
#
#  Защита: Subject очищается от \r\n (RFC 5322).
# ============================================================

# shellcheck disable=SC1091
source /opt/monitoring/lib/monitor_common.sh

SUBJECT="${1:-REDOS Monitor Alert}"
BODY="${2:-(empty)}"
TO="${3:-${ALERT_TO:-root@localhost}}"
FROM="${ALERT_FROM:-monitoring@$(hostname -d 2>/dev/null || echo localhost)}"

# RFC 5322: заголовки не могут содержать CR/LF
SUBJECT="$(printf '%s' "$SUBJECT" | tr -d '\r\n' | tr -s ' ')"
# Truncate
[ "${#SUBJECT}" -gt 200 ] && SUBJECT="${SUBJECT:0:197}..."

# Лимит тела
MAX_BODY_LEN=8192
if [ "${#BODY}" -gt "$MAX_BODY_LEN" ]; then
    BODY="${BODY:0:$MAX_BODY_LEN}

[truncated]"
fi

log_msg "$LOG_ALERTS" "INFO" "sending: $SUBJECT -> $TO"

# === Способ 1 — SMTP с AUTH через Python smtplib ===
if [ -n "${SMTP_USER:-}" ] && [ -n "${SMTP_PASSWORD:-}" ] && command -v python3 >/dev/null 2>&1; then
    py_out="$(SMTP_HOST="${SMTP_HOST:-127.0.0.1}" \
              SMTP_PORT="${SMTP_PORT:-587}" \
              SMTP_USER="${SMTP_USER}" \
              SMTP_PASSWORD="${SMTP_PASSWORD}" \
              SMTP_USE_TLS="${SMTP_USE_TLS:-yes}" \
              MAIL_FROM="${FROM}" \
              MAIL_TO="${TO}" \
              MAIL_SUBJECT="${SUBJECT}" \
              MAIL_BODY="${BODY}" \
              python3 - 2>&1 <<'PYEOF'
import os, smtplib, ssl, sys
from email.message import EmailMessage

host = os.environ.get("SMTP_HOST", "127.0.0.1")
port = int(os.environ.get("SMTP_PORT", "587"))
user = os.environ.get("SMTP_USER", "")
pwd  = os.environ.get("SMTP_PASSWORD", "")
use_tls = os.environ.get("SMTP_USE_TLS", "yes").lower() in ("yes","true","1")

msg = EmailMessage()
msg["From"] = os.environ.get("MAIL_FROM", "root@localhost")
msg["To"]   = os.environ.get("MAIL_TO", "root@localhost")
msg["Subject"] = os.environ.get("MAIL_SUBJECT", "")
msg.set_content(os.environ.get("MAIL_BODY", ""))

def make_ctx():
    """SSL-контекст. Для 127.0.0.1 отключаем проверку (iRedMail self-signed)."""
    ctx = ssl.create_default_context()
    if host in ("127.0.0.1", "localhost", "::1"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

try:
    if use_tls and port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=20, context=make_ctx()) as s:
            s.login(user, pwd)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.ehlo()
            if use_tls:
                s.starttls(context=make_ctx())
                s.ehlo()
            if user:
                s.login(user, pwd)
            s.send_message(msg)
    print("OK")
    sys.exit(0)
except Exception as e:
    print("ERROR:", str(e))
    sys.exit(1)
PYEOF
)"
    rc=$?
    if [ "$rc" = "0" ]; then
        log_msg "$LOG_ALERTS" "INFO" "sent via SMTP-auth as $SMTP_USER: $TO"
        exit 0
    else
        log_msg "$LOG_ALERTS" "ERROR" "SMTP-auth failed: $py_out"
        log_msg "$LOG_ALERTS" "WARN" "fallback to local sendmail"
    fi
fi

# === Способ 2 — sendmail (постфикс) ===
if command -v sendmail >/dev/null 2>&1; then
    {
        printf 'From: %s\n' "$FROM"
        printf 'To: %s\n' "$TO"
        printf 'Subject: %s\n' "$SUBJECT"
        printf 'Content-Type: text/plain; charset=UTF-8\n'
        printf 'X-REDOS-Monitor: 1\n'
        printf '\n'
        printf '%s\n' "$BODY"
    } | sendmail -t -i 2>>"$LOG_ALERTS"
    rc=$?
    if [ "$rc" = "0" ]; then
        log_msg "$LOG_ALERTS" "INFO" "sent via sendmail: $TO"
        exit 0
    fi
fi

# === Способ 3 — mailx ===
if command -v mail >/dev/null 2>&1; then
    printf '%s' "$BODY" | mail -s "$SUBJECT" -r "$FROM" "$TO" 2>>"$LOG_ALERTS"
    [ "$?" = "0" ] && { log_msg "$LOG_ALERTS" "INFO" "sent via mailx"; exit 0; }
fi

log_msg "$LOG_ALERTS" "ERROR" "all delivery methods failed: $SUBJECT"
exit 1
