#!/usr/bin/env python3
import csv
import datetime as dt
import html
import json
import os
import socket
import subprocess
import sys
import unicodedata
from pathlib import Path

kind = sys.argv[1] if len(sys.argv) > 1 else "daily"
hours = {"hourly": 1, "daily": 24, "weekly": 24 * 7}.get(kind, 24)
state_dir = Path(os.environ.get("MON_STATE_DIR", "/var/lib/monitoring"))
report_dir = Path(os.environ.get("MON_REPORT_DIR", "/var/log/monitoring/reports"))
template_dir = Path(os.environ.get("MON_BASE_DIR", "/opt/monitoring")) / "templates"
incident_log = Path(os.environ.get("MON_INCIDENT_LOG", "/var/log/infrastructure_monitor.log"))
report_dir.mkdir(parents=True, exist_ok=True)


def read_json(name):
    try:
        return json.loads((state_dir / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


services = read_json("state_services.json")
performance = read_json("state_performance.json")
security = read_json("state_security.json")
internet = read_json("state_internet.json")
clients = read_json("state_clients.json")
incidents = []
cutoff = dt.datetime.now() - dt.timedelta(hours=hours)
try:
    for line in incident_log.read_text(encoding="utf-8", errors="replace").splitlines()[-2000:]:
        try:
            stamp = dt.datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if stamp >= cutoff:
            incidents.append(line)
except OSError:
    pass


def service_rows():
    rows = []
    for svc in services.get("services", []):
        status = html.escape(str(svc.get("status", "unknown")))
        css = "ok" if status == "active" else ("muted" if status == "not-installed" else "bad")
        rows.append(
            "<tr><td>{}</td><td class='{}'>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(str(svc.get("name", ""))),
                css,
                status,
                html.escape(str(svc.get("enabled", ""))),
                html.escape(str(svc.get("action", ""))),
            )
        )
    return "\n".join(rows) or "<tr><td colspan='4'>No service data</td></tr>"


def metric(name, value, suffix="%"):
    return f"<div class='metric'><span>{html.escape(name)}</span><strong>{html.escape(str(value))}{suffix}</strong></div>"


def load_history():
    path = state_dir / "history" / "metrics.csv"
    points = []
    try:
        with path.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                try:
                    stamp = dt.datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).replace(tzinfo=None)
                    if stamp >= cutoff:
                        points.append(
                            (stamp, float(row["cpu"]), float(row["ram"]), float(row["disk_used"]))
                        )
                except (KeyError, ValueError):
                    continue
    except OSError:
        pass
    return points[-12000:]


def graph_svg(points):
    if not points:
        return "<p>No history yet. The graph appears after metric samples are collected.</p>"
    width, height, pad = 900, 280, 35
    sample = points[:: max(1, len(points) // 180)]
    colors = {"CPU": "#d23f3f", "RAM": "#2563eb", "Disk": "#d97706"}
    svg = [f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='Weekly load graph'>"]
    for y in (0, 25, 50, 75, 100):
        py = height - pad - (y / 100) * (height - 2 * pad)
        svg.append(f"<line x1='{pad}' y1='{py:.1f}' x2='{width-pad}' y2='{py:.1f}' class='grid'/>")
        svg.append(f"<text x='2' y='{py+4:.1f}'>{y}%</text>")
    for idx, (label, color) in enumerate(colors.items()):
        value_idx = idx + 1
        coords = []
        for pos, point in enumerate(sample):
            x = pad + pos * (width - 2 * pad) / max(1, len(sample) - 1)
            y = height - pad - max(0, min(100, point[value_idx])) * (height - 2 * pad) / 100
            coords.append(f"{x:.1f},{y:.1f}")
        svg.append(f"<polyline points='{' '.join(coords)}' fill='none' stroke='{color}' stroke-width='2'/>")
        svg.append(f"<text x='{pad + idx*110}' y='18' fill='{color}'>{label}</text>")
    svg.append("</svg>")
    return "".join(svg)


memory = performance.get("memory", {})
swap = performance.get("swap", {})
disks = performance.get("disks", [])
max_disk = max([d.get("used_pct", 0) for d in disks] or [0])
metrics_html = "".join(
    [
        metric("CPU", performance.get("cpu_usage_pct", "?")),
        metric("RAM", memory.get("used_pct", "?")),
        metric("Swap", swap.get("used_pct", "?")),
        metric("Max disk used", max_disk),
        metric("Internet", internet.get("speed_mbps", "?"), " Mbit/s"),
    ]
)
generated = dt.datetime.now().astimezone().isoformat(timespec="seconds")
hostname = socket.gethostname()
title = f"REDOS Monitoring {kind.capitalize()} Report"
template_name = "report_weekly.html.tpl" if kind == "weekly" else "report_daily.html.tpl"
template = (template_dir / template_name).read_text(encoding="utf-8")
def clients_table():
    rows = clients.get("clients", [])
    if not rows:
        return "<p class='muted'>No client data. Run: <code>ansible-playbook monitoring_playbook.yml --tags client</code></p>"
    header = (
        "<table><thead><tr><th>Host</th><th>Ping</th><th>Ports</th>"
        "<th>Internet (Mbit/s)</th><th>CPU %</th><th>RAM %</th><th>Disk used %</th></tr></thead><tbody>"
    )
    body_rows = []
    for c in rows:
        ping_html = "<span class='ok'>OK</span>" if c.get("ping_ok") else "<span class='bad'>FAIL</span>"
        # Подсветка скорости: красным если < 0.8 Mbit/s, серым если 0 (не измерено)
        try:
            speed_val = float(str(c.get("internet_mbps", "0")).strip() or 0)
        except ValueError:
            speed_val = 0.0
        if speed_val == 0:
            speed_cls = "muted"
        elif speed_val < 0.8:
            speed_cls = "bad"
        else:
            speed_cls = "ok"
        internet_html = "<span class='{}'>{}</span>".format(
            speed_cls, html.escape(str(c.get("internet_mbps", "?")))
        )
        body_rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(str(c.get("host", ""))),
                ping_html,
                html.escape(str(c.get("ports_ok", ""))),
                internet_html,
                html.escape(str(c.get("cpu_pct", "?"))),
                html.escape(str(c.get("ram_pct", "?"))),
                html.escape(str(c.get("disk_used_pct", "?"))),
            )
        )
    return header + "\n".join(body_rows) + "</tbody></table>"


replacements = {
    "@@TITLE@@": html.escape(title),
    "@@HOST@@": html.escape(hostname),
    "@@GENERATED@@": html.escape(generated),
    "@@WINDOW@@": str(hours),
    "@@SERVICE_ROWS@@": service_rows(),
    "@@METRICS@@": metrics_html,
    "@@CLIENTS@@": clients_table(),
    "@@SECURITY@@": html.escape(json.dumps(security, ensure_ascii=False, indent=2)),
    "@@INCIDENTS@@": html.escape("\n".join(incidents[-200:]) or "No incidents in this period"),
    "@@GRAPH@@": graph_svg(load_history()) if kind == "weekly" else "",
}
for key, value in replacements.items():
    template = template.replace(key, value)

stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
base = report_dir / f"{stamp}_{kind}"
html_path = base.with_suffix(".html")
json_path = base.with_suffix(".json")
txt_path = base.with_suffix(".txt")
pdf_path = base.with_suffix(".pdf")
html_path.write_text(template, encoding="utf-8")
json_path.write_text(
    json.dumps(
        {
            "type": kind,
            "generated_at": generated,
            "host": hostname,
            "services": services,
            "performance": performance,
            "security": security,
            "internet": internet,
            "clients": clients,
            "incidents": incidents,
        },
        ensure_ascii=False,
        indent=2,
    ),
    encoding="utf-8",
)
lines = [
    title,
    f"Generated: {generated}",
    f"Host: {hostname}",
    f"CPU: {performance.get('cpu_usage_pct', '?')}%",
    f"RAM: {memory.get('used_pct', '?')}%",
    f"Disk used max: {max_disk}%",
    f"Internet: {internet.get('speed_mbps', '?')} Mbit/s",
    "",
    "Services:",
]
for svc in services.get("services", []):
    lines.append(f"  {svc.get('name')}: {svc.get('status')} [{svc.get('action')}]")
lines.extend(["", "Incidents:"] + (incidents[-30:] or ["  None"]))
txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def ascii_text(value):
    normalized = unicodedata.normalize("NFKD", value)
    return normalized.encode("ascii", "replace").decode("ascii")


def write_pdf(path, text_lines):
    chunks = [text_lines[i : i + 52] for i in range(0, len(text_lines), 52)] or [[]]
    objects = {}
    page_ids = []
    content_ids = []
    next_id = 4
    for _ in chunks:
        page_ids.append(next_id)
        content_ids.append(next_id + 1)
        next_id += 2
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{obj} 0 R" for obj in page_ids)
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()
    objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    for page_id, content_id, chunk in zip(page_ids, content_ids, chunks):
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode()
        commands = ["BT", "/F1 9 Tf", "40 800 Td", "13 TL"]
        for line in chunk:
            escaped = ascii_text(line).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            commands.extend([f"({escaped[:110]}) Tj", "T*"])
        commands.append("ET")
        stream = "\n".join(commands).encode()
        objects[content_id] = f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream"
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0] * (max(objects) + 1)
    for obj_id in sorted(objects):
        offsets[obj_id] = len(output)
        output.extend(f"{obj_id} 0 obj\n".encode() + objects[obj_id] + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for obj_id in range(1, len(offsets)):
        output.extend(f"{offsets[obj_id]:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    path.write_bytes(output)


def render_pdf_from_html(html_file, pdf_file, text_lines):
    """
    Каскад генерации PDF (от лучшего к худшему):
      1. wkhtmltopdf       — full-fidelity HTML→PDF с CSS и SVG-графиками
      2. chromium-headless — то же через Chrome rendering engine
      3. libreoffice       — конвертация через офис
      4. fallback text PDF — встроенный примитивный writer (текст без графики)
    """
    import shutil
    import subprocess

    # 1. wkhtmltopdf — самый компактный
    if shutil.which("wkhtmltopdf"):
        try:
            subprocess.run(
                ["wkhtmltopdf", "--enable-local-file-access", "--quiet",
                 str(html_file), str(pdf_file)],
                check=True, timeout=60,
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            )
            if pdf_file.exists() and pdf_file.stat().st_size > 1000:
                return "wkhtmltopdf"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            pass

    # 2. chromium / google-chrome headless
    for binary in ("chromium-browser", "chromium", "google-chrome", "chrome"):
        chrome = shutil.which(binary)
        if not chrome:
            continue
        try:
            subprocess.run(
                [chrome, "--headless", "--disable-gpu", "--no-sandbox",
                 "--run-all-compositor-stages-before-draw",
                 "--virtual-time-budget=5000",
                 f"--print-to-pdf={pdf_file}",
                 f"file://{html_file.absolute()}"],
                check=True, timeout=90,
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            )
            if pdf_file.exists() and pdf_file.stat().st_size > 1000:
                return f"chromium ({binary})"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            pass

    # 3. libreoffice headless
    if shutil.which("libreoffice"):
        try:
            tmpdir = pdf_file.parent / ".libreoffice"
            tmpdir.mkdir(exist_ok=True)
            subprocess.run(
                ["libreoffice", "--headless", "--convert-to", "pdf",
                 "--outdir", str(tmpdir), str(html_file)],
                check=True, timeout=90,
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            )
            converted = tmpdir / (html_file.stem + ".pdf")
            if converted.exists():
                converted.replace(pdf_file)
                shutil.rmtree(tmpdir, ignore_errors=True)
                if pdf_file.stat().st_size > 1000:
                    return "libreoffice"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            pass

    # 4. Fallback — текстовый PDF (без графики, но валидный)
    write_pdf(pdf_file, text_lines)
    return "text-fallback"


pdf_engine = render_pdf_from_html(html_path, pdf_path, lines)
import sys as _sys
print(f"PDF engine used: {pdf_engine}", file=_sys.stderr)

for path in (html_path, json_path, txt_path, pdf_path):
    path.chmod(0o640)
    latest = report_dir / f"latest_{kind}{path.suffix}"
    latest.unlink(missing_ok=True)
    latest.symlink_to(path.name)

retention = int(os.environ.get("REPORT_RETENTION_DAYS", "31"))
cutoff_mtime = dt.datetime.now().timestamp() - retention * 86400
for old in report_dir.iterdir():
    if old.is_file() and old.stat().st_mtime < cutoff_mtime:
        old.unlink(missing_ok=True)

print(f"{html_path}|{pdf_path}|{txt_path}")
