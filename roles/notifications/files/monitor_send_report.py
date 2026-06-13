#!/usr/bin/env python3
"""Send report attachments over authenticated SMTP with STARTTLS.

Behaviour:
    * If submission server advertises STARTTLS — use it (encrypted).
    * If not — fall back to plain SMTP only when SMTP_REQUIRE_TLS_REPORTS=no.
    * For self-signed iRedMail certs on 127.0.0.1 we relax verification by
      default (SMTP_VERIFY_TLS=no in monitor.env).

Usage:
    monitor_send_report.py SUBJECT BODY_FILE ATTACHMENT...
"""
import mimetypes
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path

if len(sys.argv) < 4:
    raise SystemExit("usage: monitor_send_report.py SUBJECT BODY_FILE ATTACHMENT...")

host = os.environ.get("SMTP_HOST", "127.0.0.1")
port = int(os.environ.get("SMTP_PORT", "587"))
user = os.environ.get("SMTP_USER", "")
password = os.environ.get("SMTP_PASSWORD", "")
sender = os.environ.get("ALERT_FROM", user or "monitoring@localhost")
recipient = os.environ.get("ALERT_TO", "root@localhost")
require_tls = os.environ.get("SMTP_REQUIRE_TLS_REPORTS", "yes").lower() in {"1", "yes", "true"}
verify_tls = os.environ.get("SMTP_VERIFY_TLS", "no").lower() in {"1", "yes", "true"}
ca_file = os.environ.get("SMTP_CA_FILE", "")

message = EmailMessage()
message["Subject"] = sys.argv[1].replace("\r", "").replace("\n", " ")[:200]
message["From"] = sender
message["To"] = recipient
message.set_content(Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")[:20000])
for filename in sys.argv[3:]:
    path = Path(filename)
    content_type, _ = mimetypes.guess_type(path.name)
    major, minor = (content_type or "application/octet-stream").split("/", 1)
    message.add_attachment(path.read_bytes(), maintype=major, subtype=minor, filename=path.name)


def make_context() -> ssl.SSLContext:
    """SSL-контекст. Для 127.0.0.1 (self-signed iRedMail) отключаем проверку."""
    context = ssl.create_default_context(cafile=ca_file or None)
    if not verify_tls or host in ("127.0.0.1", "localhost", "::1"):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def tls_proof(smtp_conn) -> str:
    """Возвращает доказательство шифрования соединения (cipher + version)."""
    try:
        sock = smtp_conn.sock
        if isinstance(sock, ssl.SSLSocket):
            cipher = sock.cipher()  # (name, ssl_version, bits)
            return f"TLS={cipher[1]} cipher={cipher[0]} bits={cipher[2]}"
        return "TLS=NONE (plain socket)"
    except Exception:
        return "TLS=unknown"


def send_via_smtp() -> str:
    """STARTTLS на 587. Возвращает proof-of-encryption строку."""
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo()
        has_tls = smtp.has_extn("starttls")
        if has_tls:
            smtp.starttls(context=make_context())
            smtp.ehlo()
        elif require_tls:
            raise RuntimeError("SMTP server does not advertise STARTTLS")
        if user:
            smtp.login(user, password)
        proof = tls_proof(smtp)
        smtp.send_message(message)
    return proof


def send_via_ssl() -> str:
    """SMTPS:465 — implicit TLS (для совместимости когда STARTTLS не работает)."""
    with smtplib.SMTP_SSL(host, 465, timeout=30, context=make_context()) as smtp:
        if user:
            smtp.login(user, password)
        proof = tls_proof(smtp)
        smtp.send_message(message)
    return proof


# Основной путь — STARTTLS на submission (587)
try:
    proof = send_via_smtp()
    print(f"OK: report sent via STARTTLS on {host}:{port} | {proof}", file=sys.stderr)
    sys.exit(0)
except Exception as exc:  # noqa: BLE001
    print(f"WARN: STARTTLS path failed: {exc!r}", file=sys.stderr)
    if require_tls:
        try:
            proof = send_via_ssl()
            print(f"OK: report sent via SMTPS on {host}:465 | {proof}", file=sys.stderr)
            sys.exit(0)
        except Exception as exc2:  # noqa: BLE001
            print(f"ERROR: SMTPS:465 fallback failed: {exc2!r}", file=sys.stderr)
            sys.exit(2)
    try:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            if user:
                smtp.login(user, password)
            smtp.send_message(message)
        print(f"OK: report sent in PLAIN on {host}:{port} (TLS not required by config)", file=sys.stderr)
        sys.exit(0)
    except Exception as exc3:  # noqa: BLE001
        print(f"ERROR: plain SMTP failed: {exc3!r}", file=sys.stderr)
        sys.exit(3)
