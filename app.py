"""
Advanced Web Application Security Testing Tool — Flask application.
Educational use only; scan only authorized targets.
"""

from __future__ import annotations

import configparser
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for

from integrations.ipinfo import fetch_ip_info
from integrations.virustotal import check_urls_throttled
from scanner.scanner import run_full_scan

# -----------------------------------------------------------------------------
# Paths & config
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"
CONFIG_PATH = BASE_DIR / "config.ini"
LOG_DIR = BASE_DIR / "logs"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-change-me-in-production")

# Simple in-memory rate limit: last scan epoch per client IP
_rate_lock = threading.Lock()
_last_scan_by_ip: dict[str, float] = {}
RATE_LIMIT_SECONDS = 90


def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if CONFIG_PATH.exists():
        cfg.read(CONFIG_PATH, encoding="utf-8-sig")
    else:
        cfg["virustotal"] = {"api_key": ""}
        cfg["scanner"] = {
            "max_depth": "2",
            "max_pages": "40",
            "timeout": "12",
            "max_workers": "6",
            "vt_max_urls": "3",
            "vt_delay_seconds": "16",
        }
    return cfg


def setup_logging() -> None:
    LOG_DIR.mkdir(exist_ok=True)
    log_file = LOG_DIR / "app.log"
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(fmt))
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(fmt))
    root.handlers.clear()
    root.addHandler(fh)
    root.addHandler(ch)


setup_logging()
log = logging.getLogger("wast")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add columns missing from older database.db files."""
    cur = conn.execute("PRAGMA table_info(scans)")
    cols = {str(row[1]) for row in cur.fetchall()}
    if "status" not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN status TEXT DEFAULT 'pending'")
    if "error_message" not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN error_message TEXT")


def init_db() -> None:
    conn = get_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                error_message TEXT
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                url TEXT NOT NULL,
                payload TEXT,
                severity TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                virustotal_status TEXT,
                ip TEXT,
                country TEXT,
                isp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )
        _migrate_schema(conn)
        conn.commit()
    finally:
        conn.close()


def is_valid_http_url(url: str) -> bool:
    try:
        p = urlparse(url.strip())
        if p.scheme not in ("http", "https"):
            return False
        return bool(p.netloc)
    except Exception:
        return False


def check_rate_limit(ip: str) -> tuple[bool, float]:
    """Returns (allowed, seconds_remaining)."""
    now = time.time()
    with _rate_lock:
        last = _last_scan_by_ip.get(ip, 0.0)
        elapsed = now - last
        if elapsed < RATE_LIMIT_SECONDS:
            return False, RATE_LIMIT_SECONDS - elapsed
        _last_scan_by_ip[ip] = now
        return True, 0.0


def release_rate_limit(ip: str) -> None:
    """Undo last rate-limit stamp if the scan was not created (e.g. DB error)."""
    with _rate_lock:
        _last_scan_by_ip.pop(ip, None)


def _cfg_int(cfg: configparser.ConfigParser, section: str, key: str, default: int) -> int:
    try:
        return int(cfg.get(section, key, fallback=str(default)).strip())
    except (ValueError, TypeError):
        log.warning("Invalid int for [%s] %s — using %s", section, key, default)
        return default


def _cfg_float(cfg: configparser.ConfigParser, section: str, key: str, default: float) -> float:
    try:
        return float(cfg.get(section, key, fallback=str(default)).strip())
    except (ValueError, TypeError):
        log.warning("Invalid float for [%s] %s — using %s", section, key, default)
        return default


def _payload_with_evidence(raw_payload: str, evidence: str) -> str:
    """Store evidence alongside payload (schema has no evidence column)."""
    return f"{raw_payload}\nEvidence: {evidence}"


def run_scan_job(scan_id: int, target_url: str) -> None:
    cfg = load_config()
    max_depth = max(0, _cfg_int(cfg, "scanner", "max_depth", 2))
    max_pages = max(1, _cfg_int(cfg, "scanner", "max_pages", 40))
    timeout = 15  # scanner default requirement
    max_workers = min(10, max(1, _cfg_int(cfg, "scanner", "max_workers", 6)))
    vt_max = max(0, _cfg_int(cfg, "scanner", "vt_max_urls", 3))
    vt_delay = max(0.0, _cfg_float(cfg, "scanner", "vt_delay_seconds", 16.0))
    vt_key = cfg.get("virustotal", "api_key", fallback="")

    conn = get_db()
    try:
        conn.execute(
            "UPDATE scans SET status = ?, error_message = NULL WHERE id = ?",
            ("running", scan_id),
        )
        conn.commit()

        result = run_full_scan(
            target_url,
            max_depth=max_depth,
            max_pages=max_pages,
            timeout=timeout,
            max_workers=max_workers,
        )

        for f in result.sqli:
            conn.execute(
                """
                INSERT INTO vulnerabilities (scan_id, type, url, payload, severity)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    "SQLi" if f.context != "demo" else "Demo (No real vulnerability detected)",
                    f.url,
                    _payload_with_evidence(f.payload, f.evidence),
                    f.severity,
                ),
            )
        for f in result.xss:
            conn.execute(
                """
                INSERT INTO vulnerabilities (scan_id, type, url, payload, severity)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    "XSS" if f.context != "demo" else "Demo (No real vulnerability detected)",
                    f.url,
                    _payload_with_evidence(f.payload, f.evidence),
                    f.severity,
                ),
            )

        ip_res = fetch_ip_info(target_url, timeout=timeout + 5)
        urls_for_vt = result.sampled_urls_for_intel[: max(0, vt_max)]
        vt_results = check_urls_throttled(
            vt_key, urls_for_vt, delay_seconds=vt_delay, timeout=25
        )

        for vr in vt_results:
            conn.execute(
                """
                INSERT INTO threat_intel
                (scan_id, url, virustotal_status, ip, country, isp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    vr.url,
                    vr.status_label,
                    ip_res.ip or "",
                    ip_res.country or "",
                    ip_res.isp or "",
                ),
            )

        if not vt_results and ip_res.ip:
            conn.execute(
                """
                INSERT INTO threat_intel
                (scan_id, url, virustotal_status, ip, country, isp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target_url,
                    "Skipped",
                    ip_res.ip or "",
                    ip_res.country or "",
                    ip_res.isp or "",
                ),
            )

        err_note = "; ".join(result.crawl_errors[:5]) if result.crawl_errors else None
        conn.execute(
            "UPDATE scans SET status = ?, error_message = ? WHERE id = ?",
            ("completed", err_note, scan_id),
        )
        conn.commit()
        log.info("Scan %s completed for %s", scan_id, target_url)
    except Exception as e:
        log.exception("Scan %s failed", scan_id)
        conn.execute(
            "UPDATE scans SET status = ?, error_message = ? WHERE id = ?",
            ("failed", str(e), scan_id),
        )
        conn.commit()
    finally:
        conn.close()


@app.route("/")
def home():
    return render_template("index.html", rate_limit_seconds=RATE_LIMIT_SECONDS)


@app.route("/scan", methods=["GET", "POST"])
def start_scan():
    if request.method == "GET":
        return redirect(url_for("home"))

    raw = (request.form.get("url") or "").strip()
    if not raw:
        flash("Please enter a target URL.", "warning")
        return redirect(url_for("home"))
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    if not is_valid_http_url(raw):
        flash("Invalid URL. Use http:// or https:// with a valid host.", "danger")
        return redirect(url_for("home"))

    ip = request.remote_addr or "unknown"
    ok, wait = check_rate_limit(ip)
    if not ok:
        flash(
            f"Rate limit: wait {int(wait) + 1} seconds before starting another scan.",
            "warning",
        )
        return redirect(url_for("home"))

    scan_id: int | None = None
    conn = get_db()
    try:
        ts = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO scans (target_url, timestamp, status) VALUES (?, ?, ?)",
            (raw, ts, "pending"),
        )
        scan_id = cur.lastrowid
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        log.exception("Failed to create scan row")
        release_rate_limit(ip)
        flash(f"Database error: {e}", "danger")
        return redirect(url_for("home"))
    finally:
        conn.close()

    if not scan_id:
        release_rate_limit(ip)
        flash("Could not start scan (no scan id).", "danger")
        return redirect(url_for("home"))

    t = threading.Thread(target=run_scan_job, args=(scan_id, raw), daemon=True)
    t.start()
    flash("Scan started. This page updates automatically when the scan finishes.", "info")
    return redirect(url_for("results", scan_id=scan_id))


@app.route("/api/scan/<int:scan_id>/status")
def scan_status(scan_id: int):
    """JSON status for dashboard auto-refresh while scan runs."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT status, error_message FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "not_found"}), 404
    return jsonify(
        {
            "status": row["status"],
            "error_message": row["error_message"],
            "scan_id": scan_id,
        }
    )


@app.route("/results/<int:scan_id>")
def results(scan_id: int):
    conn = get_db()
    try:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            flash("Scan not found.", "danger")
            return redirect(url_for("home"))
        vulns = conn.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        intel = conn.execute(
            "SELECT * FROM threat_intel WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    scan_d = dict(scan)
    vulns_d = [dict(v) for v in vulns]
    intel_d = [dict(r) for r in intel]

    sqli_count = sum(1 for v in vulns_d if "SQLi" in (v.get("type") or ""))
    xss_count = sum(1 for v in vulns_d if "XSS" in (v.get("type") or ""))
    sev_counts = {"Low": 0, "Medium": 0, "High": 0}
    for v in vulns_d:
        s = (v.get("severity") or "").split()[0] if v.get("severity") else ""
        if s in sev_counts:
            sev_counts[s] += 1
        elif v.get("severity"):
            sev_counts["Medium"] += 1
    sev_struct = {"low": sev_counts["Low"], "medium": sev_counts["Medium"], "high": sev_counts["High"]}

    return render_template(
        "results.html",
        scan=scan_d,
        vulns=vulns_d,
        intel=intel_d,
        sqli_count=sqli_count,
        xss_count=xss_count,
        sev_counts=sev_counts,
        sev_struct=sev_struct,
        total_vulns=len(vulns_d),
    )


@app.route("/report/<int:scan_id>")
def report(scan_id: int):
    conn = get_db()
    try:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            flash("Scan not found.", "danger")
            return redirect(url_for("home"))
        vulns = conn.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        intel = conn.execute(
            "SELECT * FROM threat_intel WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    scan_d = dict(scan)
    vulns_d = [dict(v) for v in vulns]
    intel_d = [dict(r) for r in intel]

    sqli_count = sum(1 for v in vulns_d if "SQLi" in (v.get("type") or ""))
    xss_count = sum(1 for v in vulns_d if "XSS" in (v.get("type") or ""))
    sev_counts = {"Low": 0, "Medium": 0, "High": 0}
    for v in vulns_d:
        s = (v.get("severity") or "").split()[0] if v.get("severity") else ""
        if s in sev_counts:
            sev_counts[s] += 1
        elif v.get("severity"):
            sev_counts["Medium"] += 1

    return render_template(
        "report.html",
        scan=scan_d,
        vulns=vulns_d,
        intel=intel_d,
        sqli_count=sqli_count,
        xss_count=xss_count,
        sev_counts=sev_counts,
        total_vulns=len(vulns_d),
    )


init_db()
log.info("Database ready at %s", DB_PATH)

if __name__ == "__main__":
    # use_reloader=False avoids duplicate scan threads during development reloads
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
