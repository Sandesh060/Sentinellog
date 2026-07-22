"""
SentinelLog — analyzer.py  (improved & premium dashboard)
==========================================================
Parse, analyze, and audit Apache/Nginx combined-format log files.

Usage:
    python analyzer.py analyze --file access.log
    python analyzer.py analyze --file access.log --report all --top 20
    python analyzer.py analyze --file access.log --filter-status 4xx
    python analyzer.py analyze --file access.log --since "2024-01-01" --until "2024-01-31"
    python analyzer.py analyze --file access.log --allowlist "10.0.0.5" --watch
    python analyzer.py history --db log_history.db
    python analyzer.py export --db log_history.db --out report.html
"""

from __future__ import annotations

import re
import argparse
import sqlite3
import csv
import json
import logging
import statistics
from html import escape
import webbrowser
import sys
from datetime import datetime, timezone
from collections import Counter, defaultdict
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional


# ─── LOGGING SETUP ────────────────────────────────────────────────────────────
def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
        level=getattr(logging, level.upper(), logging.INFO),
    )

log = logging.getLogger(__name__)


# ─── 1. REGEX / PATTERNS ──────────────────────────────────────────────────────
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)'
    r' \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) '
    r'(?P<path>.+?) '
    r'HTTP/[\d.]+" '
    r'(?P<status>\d{3}) '
    r'(?P<bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<ua>[^"]*)"'
)

SQLI_PATTERNS   = re.compile(r"(union\s+select|insert\s+into|drop\s+table|or\s+1=1|'--)", re.I)
TRAVERSAL_PATHS = re.compile(r"(\.\./|etc/passwd|/wp-admin|/phpmyadmin|/admin/config)", re.I)
SCANNER_AGENTS  = re.compile(r"(nikto|sqlmap|nessus|nmap|masscan|dirbuster|zgrab|go-http)", re.I)
XSS_PATTERNS    = re.compile(r"(<script|javascript:|onerror=|onload=|alert\()", re.I)


# ─── 2. PARSING ───────────────────────────────────────────────────────────────
def parse_line(line: str) -> Optional[dict]:
    """Parse one log line → dict or None if it doesn't match."""
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    d["status"] = int(d["status"])
    d["bytes"]  = int(d["bytes"]) if d["bytes"] != "-" else 0
    try:
        d["dt"] = datetime.strptime(d["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        d["dt"] = None
    return d


def parse_chunk(lines: list[str]) -> list[dict]:
    return [r for line in lines if (r := parse_line(line))]


def load_logs(
    filepath: str,
    workers: int = 4,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    status_filter: Optional[str] = None,
) -> list[dict]:
    """
    Load, parse, and optionally filter log records.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    lines    = path.read_text(errors="replace").splitlines()
    size_mb  = path.stat().st_size / (1024 * 1024)
    log.info("Loaded %s lines (%.1f MB) from %s", f"{len(lines):,}", size_mb, filepath)

    if size_mb < 10 or workers == 1:
        records = parse_chunk(lines)
    else:
        chunk_size = max(1000, len(lines) // workers)
        chunks     = [lines[i:i+chunk_size] for i in range(0, len(lines), chunk_size)]
        records    = []
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for f in as_completed(pool.submit(parse_chunk, c) for c in chunks):
                records.extend(f.result())

    log.info("Parsed %s valid entries using %s worker(s)", f"{len(records):,}", workers)

    # ── optional filters ──────────────────────────────────────────────────────
    if since:
        records = [r for r in records if r["dt"] and r["dt"] >= since]
        log.debug("After --since filter: %s records", len(records))
    if until:
        records = [r for r in records if r["dt"] and r["dt"] <= until]
        log.debug("After --until filter: %s records", len(records))
    if status_filter:
        grp = int(status_filter[0])
        records = [r for r in records if r["status"] // 100 == grp]
        log.debug("After --filter-status %s: %s records", status_filter, len(records))

    return records


# ─── 3. ANALYSIS ──────────────────────────────────────────────────────────────
def _check_threats(record: dict) -> set[str]:
    """Return the set of threat labels found in a single record."""
    threats: set[str] = set()
    if SQLI_PATTERNS.search(record["path"]):
        threats.add("SQL Injection")
    if TRAVERSAL_PATHS.search(record["path"]):
        threats.add("Path Traversal")
    if XSS_PATTERNS.search(record["path"]):
        threats.add("XSS Attempt")
    if SCANNER_AGENTS.search(record["ua"]):
        threats.add("Scanner UA")
    return threats


def _rate_limit_offenders(records: list[dict], threshold: int = 60, allowlist: Optional[set[str]] = None) -> set[str]:
    """
    Return IPs that burst above `threshold` requests within any 60-second window.
    """
    from collections import deque
    ip_times: dict[str, deque] = defaultdict(deque)
    offenders: set[str] = set()
    for r in sorted(records, key=lambda x: x["dt"] or datetime.min.replace(tzinfo=timezone.utc)):
        if not r["dt"]:
            continue
        ip  = r["ip"]
        if allowlist and ip in allowlist:
            continue
        ts  = r["dt"].timestamp()
        dq  = ip_times[ip]
        dq.append(ts)
        while dq and ts - dq[0] > 60:
            dq.popleft()
        if len(dq) > threshold:
            offenders.add(ip)
    return offenders


def parse_allowlist(arg: Optional[str]) -> set[str]:
    """Parse comma-separated IP list or load from file."""
    if not arg:
        return set()
    p = Path(arg)
    if p.exists() and p.is_file():
        try:
            ips = {line.strip() for line in p.read_text(errors="replace").splitlines() if line.strip()}
            log.info("Loaded %s IP(s) from allowlist file %s", len(ips), arg)
            return ips
        except Exception as e:
            log.warning("Could not read allowlist file %s: %s. Treating as direct IP list.", arg, e)
    ips = {ip.strip() for ip in arg.split(",") if ip.strip()}
    log.info("Parsed %s IP(s) from allowlist argument", len(ips))
    return ips


def analyze(records: list[dict], top_n: int = 10, allowlist: Optional[set[str]] = None) -> dict:
    """Run all analysis passes over the parsed records."""
    total = len(records)
    if total == 0:
        log.warning("No records to analyse.")
        return {}

    hour_counts    = Counter(r["dt"].hour for r in records if r["dt"])
    status_counts  = Counter(r["status"] for r in records)
    status_groups: dict[str, int] = defaultdict(int)
    for code, cnt in status_counts.items():
        status_groups[f"{code // 100}xx"] += cnt

    ip_counts       = Counter(r["ip"] for r in records)
    endpoint_counts = Counter(r["path"] for r in records)
    ua_counts       = Counter(r["ua"] for r in records)
    method_counts   = Counter(r["method"] for r in records)

    hourly_vals = list(hour_counts.values())
    mean_rph    = statistics.mean(hourly_vals) if hourly_vals else 0
    std_rph     = statistics.stdev(hourly_vals) if len(hourly_vals) > 1 else 0
    spike_hours = {h: c for h, c in hour_counts.items() if c > mean_rph + 2 * std_rph}

    # ── per-IP security forensics ─────────────────────────────────────────────
    ip_security: dict[str, dict] = defaultdict(lambda: {
        "requests": 0, "auth_failures": 0, "threats": set(), "bytes": 0,
    })
    for r in records:
        ip = r["ip"]
        ip_security[ip]["requests"]  += 1
        ip_security[ip]["bytes"]     += r["bytes"]
        if allowlist and ip in allowlist:
            continue
        if r["status"] in (401, 403):
            ip_security[ip]["auth_failures"] += 1
        ip_security[ip]["threats"] |= _check_threats(r)

    rate_offenders = _rate_limit_offenders(records, allowlist=allowlist)
    for ip in rate_offenders:
        ip_security[ip]["threats"].add("Rate Limit Burst")

    for ip, data in ip_security.items():
        if allowlist and ip in allowlist:
            continue
        if data["auth_failures"] >= 3:
            data["threats"].add("Brute Force")

    flagged_ips = {
        ip: data for ip, data in ip_security.items()
        if data["threats"] or data["auth_failures"] >= 3
    }

    return {
        "total":          total,
        "unique_ips":     len(ip_counts),
        "error_rate":     round(
            (status_groups.get("4xx", 0) + status_groups.get("5xx", 0)) / total * 100, 2
        ),
        "hour_counts":    dict(sorted(hour_counts.items())),
        "status_counts":  dict(status_counts.most_common()),
        "status_groups":  dict(status_groups),
        "top_ips":        ip_counts.most_common(top_n),
        "top_endpoints":  endpoint_counts.most_common(top_n),
        "top_ua":         ua_counts.most_common(5),
        "method_counts":  dict(method_counts),
        "spike_hours":    spike_hours,
        "flagged_ips":    {ip: {**d, "threats": sorted(d["threats"])} for ip, d in flagged_ips.items()},
        "mean_rph":       round(mean_rph, 1),
        "std_rph":        round(std_rph, 1),
    }


# ─── 4. REPORTING ─────────────────────────────────────────────────────────────
def print_report(analysis: dict) -> None:
    """Print a formatted CLI dashboard."""
    if not analysis:
        print("No data to report.")
        return

    W   = 60
    SEP = "─" * W

    def row(label: str, value) -> str:
        return f"  {label:<22} {value}"

    print(f"\n{'═' * W}")
    print(f"  SENTINELLOG REPORT  —  {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"{'═' * W}")
    print(row("Total requests:", f"{analysis['total']:,}"))
    print(row("Unique IPs:", f"{analysis['unique_ips']:,}"))
    print(row("Error rate:", f"{analysis['error_rate']}%"))
    print(row("Mean req/hour:", f"{analysis['mean_rph']}  (σ = {analysis['std_rph']})"))

    print(f"\n  {SEP}\n  HTTP METHODS")
    print(f"  {SEP}")
    for method, cnt in sorted(analysis.get("method_counts", {}).items(), key=lambda x: -x[1]):
        print(f"  {cnt:>6}  {method}")

    print(f"\n  {SEP}\n  STATUS CODE BREAKDOWN")
    print(f"  {SEP}")
    for grp, cnt in sorted(analysis["status_groups"].items()):
        bar = "█" * min(cnt, 40)
        print(f"  {grp}  {bar}  {cnt}")

    print(f"\n  {SEP}\n  TOP ENDPOINTS")
    print(f"  {SEP}")
    for path, cnt in analysis["top_endpoints"]:
        short = (path[:50] + "…") if len(path) > 51 else path
        print(f"  {cnt:>6}  {short}")

    print(f"\n  {SEP}\n  TOP IP ADDRESSES")
    print(f"  {SEP}")
    for ip, cnt in analysis["top_ips"]:
        flag = " ← FLAGGED" if ip in analysis["flagged_ips"] else ""
        print(f"  {cnt:>6}  {ip:<18}{flag}")

    if analysis["spike_hours"]:
        print(f"\n  {SEP}\n  ⚠  TRAFFIC ANOMALIES  (> mean + 2σ)")
        print(f"  {SEP}")
        for h, c in analysis["spike_hours"].items():
            print(f"  Hour {h:02d}:00  →  {c:,} requests")

    if analysis["flagged_ips"]:
        print(f"\n  {SEP}\n  🚨 SECURITY ALERTS")
        print(f"  {SEP}")
        for ip, d in analysis["flagged_ips"].items():
            threats = ", ".join(d["threats"]) or "Auth failures"
            print(f"  {ip:<20}  {d['requests']:>4} req  |  "
                  f"{d['auth_failures']} auth fails  |  {threats}")
    else:
        print("\n  ✓ No suspicious IPs detected.")

    print(f"\n{'═' * W}\n")


# ─── 5. EXPORTS ───────────────────────────────────────────────────────────────
def export_csv(analysis: dict, out_path: str = "log_report.csv") -> None:
    """Export top IPs and endpoints to CSV."""
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "item", "count", "auth_failures", "threats"])
        for ip, cnt in analysis["top_ips"]:
            d = analysis["flagged_ips"].get(ip, {})
            w.writerow(["Top IP", ip, cnt,
                        d.get("auth_failures", 0),
                        "; ".join(d.get("threats", []))])
        for path, cnt in analysis["top_endpoints"]:
            w.writerow(["Top Endpoint", path, cnt, "", ""])
    log.info("CSV saved → %s", out_path)


def export_json(analysis: dict, out_path: str = "log_report.json") -> None:
    """Export the full analysis as JSON."""
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2, default=str)
    log.info("JSON saved → %s", out_path)


def export_html(analysis: dict, out_path: str = "log_report.html") -> None:
    """Export a self-contained HTML report matching the tabbed dashboard UI."""
    now          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    flagged_ips  = analysis.get("flagged_ips", {})
    top_ips      = analysis.get("top_ips", [])
    top_endpoints= analysis.get("top_endpoints", [])
    status_groups= analysis.get("status_groups", {})
    spike_hours  = analysis.get("spike_hours", {})
    
    max_count    = max((c for _, c in top_ips), default=1)

    # ── Overview: IP bar rows ─────────────────────────────────────────────────
    ip_rows_html = ""
    for ip, cnt in top_ips:
        pct      = round(cnt / max_count * 100)
        flagged  = ip in flagged_ips
        bar_class = "danger" if flagged else "primary"
        tag      = '<span class="badge badge-danger">FLAGGED</span>' if flagged else '<span class="badge badge-success">CLEAN</span>'
        ip_rows_html += f"""
        <div class="ip-row hover-target">
          <span class="ip-addr mono">{escape(ip)}</span>
          <div class="bar-wrap">
            <div class="bar bar-{bar_class}" style="width:{pct}%"></div>
          </div>
          <span class="ip-count font-semibold">{cnt}</span>
          {tag}
        </div>"""

    # ── Overview: Endpoint rows ───────────────────────────────────────────────
    ep_rows_html = ""
    for path, cnt in top_endpoints:
        danger  = any(p in path for p in ["passwd","etc/","../","wp-admin","phpmyadmin"])
        tag     = '<span class="badge badge-danger">SUSPICIOUS</span>' if danger else ""
        ep_class = "text-rose-400 font-semibold" if danger else "text-gray-300"
        ep_rows_html += f"""
        <div class="ep-row hover-target">
          <span class="ep-path mono {ep_class}" title="{escape(path)}">{escape(path)}</span>
          <span class="ep-count font-semibold">{cnt}</span>
          {tag}
        </div>"""

    # ── Overview: Status cards ────────────────────────────────────────────────
    s2 = status_groups.get("2xx", 0)
    s4 = status_groups.get("4xx", 0)
    s5 = status_groups.get("5xx", 0)

    # ── Security: alert boxes ─────────────────────────────────────────────────
    alert_boxes = ""
    if flagged_ips:
        for ip, d in flagged_ips.items():
            threats_str = ", ".join(d["threats"]) or "Auth failures"
            alert_boxes += f"""
            <div class="alert-box-card">
              <div class="alert-box-header">
                <div class="alert-box-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:1.25rem; height:1.25rem;">
                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                  </svg>
                </div>
                <div class="alert-box-info">
                  <h4>{escape(threats_str)}</h4>
                  <span class="mono text-rose-400">{escape(ip)}</span>
                </div>
                <div class="alert-box-badge">CRITICAL</div>
              </div>
              <div class="alert-box-body">
                <p>Accumulated <span class="mono" style="color:white; font-weight:600;">{d['requests']}</span> requests and <span class="mono" style="color:white; font-weight:600;">{d['auth_failures']}</span> auth failures.</p>
                <div class="alert-box-action">Recommendation: IP is exhibiting abusive behavior. Block IP in firewall.</div>
              </div>
            </div>"""
    else:
        alert_boxes = """
        <div class="empty-alerts">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:3rem; height:3rem; color:#10b981; margin:0 auto 1rem;">
            <path d="M9 12l2 2 4-4m5 .5a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          <h3>All Systems Secure</h3>
          <p>No suspicious activities or policy violations detected in this log run.</p>
        </div>"""

    # ── Security: forensics table ─────────────────────────────────────────────
    forensics_rows = ""
    for ip, cnt in top_ips:
        d       = flagged_ips.get(ip, {})
        threats = ", ".join(d.get("threats", [])) or "—"
        is_flagged = ip in flagged_ips
        tag     = f'<span class="badge badge-danger">{escape(threats)}</span>' if is_flagged else '<span class="badge badge-success">CLEAN</span>'
        action_str = "BLOCK AT FIREWALL" if is_flagged else "NONE"
        action_class = "text-rose-400 font-semibold" if is_flagged else "text-emerald-400"
        forensics_rows += f"""
        <tr class="hover-target">
          <td class="mono font-semibold" style="color:#e5e7eb;">{escape(ip)}</td>
          <td>{cnt}</td>
          <td class="mono">{d.get('auth_failures', 0)}</td>
          <td>{tag}</td>
          <td class="mono {action_class}">{action_str}</td>
        </tr>"""

    # ── Traffic: spike rows ───────────────────────────────────────────────────
    spike_rows = ""
    for h, c in spike_hours.items():
        spike_rows += f"<tr><td>Hour {h:02d}:00</td><td>{c:,} requests</td><td><span class='badge badge-danger'>Spike</span></td></tr>"
    if not spike_rows:
        spike_rows = "<tr><td colspan='3' style='text-align:center; padding: 2rem 0; color: #9ca3af;'>No traffic spikes detected.</td></tr>"

    # ── Chart.js data ─────────────────────────────────────────────────────────
    chart_labels   = [ip  for ip,  _ in top_ips]
    chart_counts   = [cnt for _,  cnt in top_ips]
    chart_colors   = ["#ef4444" if ip in flagged_ips else "#3b82f6" for ip, _ in top_ips]
    donut_labels   = [p   for p,   _ in top_endpoints]
    donut_counts   = [cnt for _,  cnt in top_endpoints]
    donut_colors   = ["#3b82f6","#10b981","#ef4444","#f59e0b","#8b5cf6","#ec4899",
                      "#14b8a6","#6366f1","#84cc16","#06b6d4"]

    flagged_count  = len(flagged_ips)
    err_cls        = "danger" if analysis.get("error_rate",0) > 5 else ("warning" if analysis.get("error_rate",0) > 1 else "success")
    flag_cls       = "danger" if flagged_count else "success"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelLog Report — {now}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {{
  --bg: #080b11;
  --surface: rgba(18, 24, 38, 0.65);
  --border: rgba(255, 255, 255, 0.06);
  --border-hover: rgba(255, 255, 255, 0.12);
  --text: #f3f4f6;
  --text-muted: #9ca3af;
  --primary: #3b82f6;
  --primary-glow: rgba(59, 130, 246, 0.15);
  --primary-gradient: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
  --success: #10b981;
  --success-glow: rgba(16, 185, 129, 0.15);
  --danger: #ef4444;
  --danger-glow: rgba(239, 68, 68, 0.15);
  --warning: #f59e0b;
  --warning-glow: rgba(245, 158, 11, 0.15);
  --glass-blur: 16px;
}}

* {{
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}}

body {{
  font-family: 'Outfit', sans-serif;
  background-color: var(--bg);
  background-image: 
    radial-gradient(circle at 10% 20%, rgba(139, 92, 246, 0.08) 0%, transparent 40%),
    radial-gradient(circle at 90% 80%, rgba(59, 130, 246, 0.08) 0%, transparent 40%);
  color: var(--text);
  padding: 2rem 3rem;
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}}

.dashboard-container {{
  max-width: 1400px;
  margin: 0 auto;
}}

/* Topbar Header */
.topbar {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 2rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
}}

.topbar-brand {{
  display: flex;
  align-items: center;
  gap: 12px;
}}

.topbar-brand svg {{
  width: 2.2rem;
  height: 2.2rem;
  color: var(--primary);
  filter: drop-shadow(0 0 8px var(--primary-glow));
}}

.topbar-brand h1 {{
  font-size: 1.5rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  background: var(--primary-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}}

.topbar-meta {{
  display: flex;
  align-items: center;
  gap: 16px;
}}

.status-badge {{
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.85rem;
  font-weight: 600;
  padding: 6px 14px;
  border-radius: 9999px;
  border: 1px solid transparent;
  transition: all 0.3s ease;
}}

.status-badge.ok {{
  background: var(--success-glow);
  color: var(--success);
  border-color: rgba(16, 185, 129, 0.25);
  box-shadow: 0 0 15px rgba(16, 185, 129, 0.1);
}}

.status-badge.danger {{
  background: var(--danger-glow);
  color: var(--danger);
  border-color: rgba(239, 68, 68, 0.25);
  box-shadow: 0 0 15px rgba(239, 68, 68, 0.1);
}}

.topbar-time {{
  font-size: 0.85rem;
  color: var(--text-muted);
  background: rgba(255, 255, 255, 0.03);
  padding: 6px 14px;
  border-radius: 9999px;
  border: 1px solid var(--border);
}}

/* Metrics Grid */
.metrics-grid {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1.25rem;
  margin-bottom: 2rem;
}}

.metric-card {{
  background: var(--surface);
  backdrop-filter: blur(var(--glass-blur));
  -webkit-backdrop-filter: blur(var(--glass-blur));
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 1.5rem;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
}}

.metric-card::before {{
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 4px;
  height: 100%;
  background: var(--primary);
  opacity: 0;
  transition: opacity 0.3s ease;
}}

.metric-card:hover {{
  transform: translateY(-4px);
  border-color: var(--border-hover);
  box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
}}

.metric-card:hover::before {{
  opacity: 1;
}}

.metric-card.danger::before {{
  background: var(--danger);
}}

.metric-card.warning::before {{
  background: var(--warning);
}}

.metric-card.success::before {{
  background: var(--success);
}}

.metric-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}}

.metric-label {{
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}}

.metric-icon {{
  width: 1.25rem;
  height: 1.25rem;
  color: var(--text-muted);
}}

.metric-card:hover .metric-icon {{
  color: var(--primary);
}}

.metric-card.danger:hover .metric-icon {{
  color: var(--danger);
}}

.metric-value {{
  font-size: 2rem;
  font-weight: 700;
  letter-spacing: -0.03em;
  margin-bottom: 0.25rem;
}}

.metric-sub {{
  font-size: 0.8rem;
  color: var(--text-muted);
}}

/* Navigation Tabs */
.tabs-container {{
  display: flex;
  background: rgba(0, 0, 0, 0.2);
  border: 1px solid var(--border);
  padding: 4px;
  border-radius: 12px;
  margin-bottom: 2rem;
  width: fit-content;
}}

.tab-btn {{
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: inherit;
  font-size: 0.9rem;
  font-weight: 500;
  padding: 8px 18px;
  color: var(--text-muted);
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
}}

.tab-btn svg {{
  width: 1.1rem;
  height: 1.1rem;
}}

.tab-btn:hover {{
  color: var(--text);
  background: rgba(255, 255, 255, 0.03);
}}

.tab-btn.active {{
  color: var(--text);
  background: var(--surface);
  box-shadow: 0 4px 12px rgba(0,0,0,0.25);
  border: 1px solid var(--border);
}}

/* Panes & Grid layouts */
.pane {{
  display: none;
  animation: fadeIn 0.4s ease forwards;
}}

.pane.active {{
  display: block;
}}

@keyframes fadeIn {{
  from {{ opacity: 0; transform: translateY(8px); }}
  to {{ opacity: 1; transform: translateY(0); }}
}}

.grid-2col {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.5rem;
  margin-bottom: 1.5rem;
}}

/* Card Panels */
.panel {{
  background: var(--surface);
  backdrop-filter: blur(var(--glass-blur));
  -webkit-backdrop-filter: blur(var(--glass-blur));
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 1.5rem;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
}}

.panel-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.25rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--border);
}}

.panel-title {{
  font-size: 1rem;
  font-weight: 600;
  color: var(--text);
  letter-spacing: -0.01em;
}}

/* Search bar styling */
.search-wrapper {{
  position: relative;
  width: 320px;
}}

.search-wrapper svg {{
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  width: 1.1rem;
  height: 1.1rem;
  color: var(--text-muted);
  pointer-events: none;
}}

.search-input {{
  width: 100%;
  padding: 8px 12px 8px 38px;
  background: rgba(0, 0, 0, 0.25);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text);
  font-family: inherit;
  font-size: 0.85rem;
  outline: none;
  transition: all 0.2s ease;
}}

.search-input:focus {{
  border-color: var(--primary);
  box-shadow: 0 0 10px var(--primary-glow);
  background: rgba(0, 0, 0, 0.4);
}}

/* IP and Endpoint rows */
.ip-row, .ep-row {{
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0.75rem 0.5rem;
  border-bottom: 1px solid var(--border);
  font-size: 0.9rem;
  transition: background 0.2s ease;
  border-radius: 6px;
}}

.ip-row:last-child, .ep-row:last-child {{
  border-bottom: none;
}}

.ip-row:hover, .ep-row:hover {{
  background: rgba(255, 255, 255, 0.02);
}}

.ip-addr {{
  min-width: 140px;
  font-size: 0.85rem;
}}

.bar-wrap {{
  flex: 1;
  background: rgba(255, 255, 255, 0.03);
  border-radius: 9999px;
  height: 8px;
  overflow: hidden;
}}

.bar {{
  height: 100%;
  border-radius: 9999px;
  transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
}}

.bar.bar-primary {{
  background: linear-gradient(90deg, var(--primary) 0%, #8b5cf6 100%);
}}

.bar.bar-danger {{
  background: linear-gradient(90deg, var(--danger) 0%, #ec4899 100%);
}}

.ip-count, .ep-count {{
  font-size: 0.85rem;
  color: var(--text-muted);
  min-width: 40px;
  text-align: right;
}}

.ep-path {{
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.85rem;
}}

/* Badges */
.badge {{
  font-size: 0.75rem;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 6px;
  letter-spacing: 0.02em;
}}

.badge-danger {{
  background: rgba(239, 68, 68, 0.1);
  color: #f87171;
  border: 1px solid rgba(239, 68, 68, 0.2);
}}

.badge-success {{
  background: rgba(16, 185, 129, 0.1);
  color: #34d399;
  border: 1px solid rgba(16, 185, 129, 0.2);
}}

.badge-warn {{
  background: rgba(245, 158, 11, 0.1);
  color: #fbbf24;
  border: 1px solid rgba(245, 158, 11, 0.2);
}}

/* Status Code Grid */
.status-grid {{
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-top: 1.5rem;
  padding-top: 1.25rem;
  border-top: 1px solid var(--border);
}}

.status-card {{
  padding: 1rem;
  border-radius: 12px;
  text-align: center;
  border: 1px solid var(--border);
  transition: transform 0.2s ease;
}}

.status-card:hover {{
  transform: translateY(-2px);
}}

.status-card.s-success {{
  background: rgba(16, 185, 129, 0.05);
  border-color: rgba(16, 185, 129, 0.15);
  color: #34d399;
}}

.status-card.s-client {{
  background: rgba(245, 158, 11, 0.05);
  border-color: rgba(245, 158, 11, 0.15);
  color: #fbbf24;
}}

.status-card.s-server {{
  background: rgba(239, 68, 68, 0.05);
  border-color: rgba(239, 68, 68, 0.15);
  color: #f87171;
}}

.status-num {{
  font-size: 1.5rem;
  font-weight: 700;
  margin-bottom: 2px;
}}

.status-lbl {{
  font-size: 0.75rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  opacity: 0.8;
}}

/* Forensics Table */
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}}

th {{
  text-align: left;
  padding: 12px 16px;
  color: var(--text-muted);
  font-weight: 600;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid var(--border);
}}

td {{
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
}}

tr.hover-target:hover td {{
  color: var(--text);
  background: rgba(255, 255, 255, 0.015);
}}

tr:last-child td {{
  border-bottom: none;
}}

.mono {{
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
}}

.font-semibold {{
  font-weight: 600;
}}

/* Security Alerts Pane */
.alert-list {{
  display: flex;
  flex-direction: column;
  gap: 16px;
}}

.alert-box-card {{
  background: rgba(239, 68, 68, 0.04);
  border: 1px solid rgba(239, 68, 68, 0.15);
  border-radius: 14px;
  padding: 1.25rem;
  transition: all 0.2s ease;
}}

.alert-box-card:hover {{
  border-color: rgba(239, 68, 68, 0.35);
  background: rgba(239, 68, 68, 0.07);
  box-shadow: 0 8px 24px rgba(239, 68, 68, 0.08);
}}

.alert-box-header {{
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
}}

.alert-box-icon {{
  display: flex;
  align-items: center;
  justify-content: center;
  width: 2.25rem;
  height: 2.25rem;
  border-radius: 10px;
  background: rgba(239, 68, 68, 0.15);
  color: #f87171;
}}

.alert-box-info {{
  flex: 1;
}}

.alert-box-info h4 {{
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text);
}}

.alert-box-badge {{
  font-size: 0.7rem;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 6px;
  background: var(--danger);
  color: white;
}}

.alert-box-body {{
  padding-left: 3.25rem;
  font-size: 0.85rem;
  color: var(--text-muted);
}}

.alert-box-body p {{
  margin-bottom: 8px;
}}

.alert-box-action {{
  font-size: 0.8rem;
  font-weight: 500;
  color: #f87171;
  background: rgba(239, 68, 68, 0.12);
  padding: 6px 12px;
  border-radius: 8px;
  border-left: 3px solid var(--danger);
  display: inline-block;
  margin-top: 6px;
}}

.empty-alerts {{
  text-align: center;
  padding: 4rem 2rem;
  border: 1px dashed var(--border);
  border-radius: 18px;
}}

.empty-alerts svg {{
  margin-bottom: 1.25rem;
  filter: drop-shadow(0 0 10px var(--success-glow));
}}

.empty-alerts h3 {{
  font-size: 1.2rem;
  font-weight: 600;
  margin-bottom: 6px;
}}

.empty-alerts p {{
  font-size: 0.9rem;
  color: var(--text-muted);
  max-width: 320px;
  margin: 0 auto;
}}

/* Charts Pane styling */
.chartbox-container {{
  position: relative;
  width: 100%;
  height: 260px;
  margin-top: 0.5rem;
}}

.chartbox-donut-container {{
  position: relative;
  width: 100%;
  height: 240px;
  margin-top: 0.5rem;
}}

footer {{
  margin-top: 4rem;
  font-size: 0.8rem;
  color: var(--text-muted);
  text-align: center;
  border-top: 1px solid var(--border);
  padding-top: 1.5rem;
}}

@media(max-width: 1024px) {{
  .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
  .grid-2col {{ grid-template-columns: 1fr; }}
  body {{ padding: 1.5rem; }}
}}
@media(max-width: 640px) {{
  .metrics-grid {{ grid-template-columns: 1fr; }}
  .topbar {{ flex-direction: column; align-items: flex-start; gap: 12px; }}
  .topbar-meta {{ width: 100%; justify-content: space-between; }}
}}
</style>
</head>
<body>

<div class="dashboard-container">
  <!-- Topbar -->
  <div class="topbar">
    <div class="topbar-brand">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <h1>SentinelLog</h1>
    </div>
    <div class="topbar-meta">
      {'<span class="status-badge danger"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' + str(flagged_count) + ' threat(s) detected</span>' if flagged_count else '<span class="status-badge ok"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>All clear</span>'}
      <span class="topbar-time">{now}</span>
    </div>
  </div>

  <!-- Quick Metrics -->
  <div class="metrics-grid">
    <div class="metric-card success">
      <div class="metric-header">
        <span class="metric-label">Total requests</span>
        <svg class="metric-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
      </div>
      <div class="metric-value">{analysis.get('total', 0):,}</div>
      <div class="metric-sub">Aggregated log hits</div>
    </div>
    
    <div class="metric-card success">
      <div class="metric-header">
        <span class="metric-label">Unique IPs</span>
        <svg class="metric-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
          <circle cx="9" cy="7" r="4"/>
          <path d="M23 21v-2a4 4 0 00-3-3.87"/>
          <path d="M16 3.13a4 4 0 010 7.75"/>
        </svg>
      </div>
      <div class="metric-value">{analysis.get('unique_ips', 0):,}</div>
      <div class="metric-sub">Unique traffic sources</div>
    </div>
    
    <div class="metric-card {flag_cls}">
      <div class="metric-header">
        <span class="metric-label">Threat Level</span>
        <svg class="metric-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0110 0v4"/>
        </svg>
      </div>
      <div class="metric-value">
        { 'CRITICAL' if flagged_count >= 3 else ('SUSPICIOUS' if flagged_count > 0 else 'SECURE') }
      </div>
      <div class="metric-sub">{flagged_count} source(s) flagged</div>
    </div>
    
    <div class="metric-card {err_cls}">
      <div class="metric-header">
        <span class="metric-label">Error rate</span>
        <svg class="metric-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      </div>
      <div class="metric-value">{analysis.get('error_rate', 0)}%</div>
      <div class="metric-sub">HTTP 4xx & 5xx traffic</div>
    </div>
  </div>

  <!-- Tabs Nav -->
  <div class="tabs-container">
    <button class="tab-btn active" onclick="switchTab('overview')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="3" width="7" height="9"/>
        <rect x="14" y="3" width="7" height="5"/>
        <rect x="14" y="12" width="7" height="9"/>
        <rect x="3" y="16" width="7" height="5"/>
      </svg>
      Overview
    </button>
    <button class="tab-btn" onclick="switchTab('forensics')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="8" y1="6" x2="21" y2="6"/>
        <line x1="8" y1="12" x2="21" y2="12"/>
        <line x1="8" y1="18" x2="21" y2="18"/>
        <line x1="3" y1="6" x2="3.01" y2="6"/>
        <line x1="3" y1="12" x2="3.01" y2="12"/>
        <line x1="3" y1="18" x2="3.01" y2="18"/>
      </svg>
      IP Forensics
    </button>
    <button class="tab-btn" onclick="switchTab('security')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Security Alerts ({flagged_count})
    </button>
    <button class="tab-btn" onclick="switchTab('traffic')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 3v18h18"/>
        <path d="M18.7 8l-5.1 5.2-2.8-2.7L7 14.3"/>
      </svg>
      Traffic & Charts
    </button>
  </div>

  <!-- ── OVERVIEW PANE ── -->
  <div id="pane-overview" class="pane active">
    <div class="grid-2col">
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Top IP addresses</span>
          <span class="badge badge-success">{len(top_ips)} unique IPs shown</span>
        </div>
        <div style="display:flex; flex-direction:column; gap:8px;">
          {ip_rows_html}
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Top Endpoints</span>
        </div>
        <div style="display:flex; flex-direction:column; gap:8px; margin-bottom:1.5rem;">
          {ep_rows_html}
        </div>
        <div class="status-grid">
          <div class="status-card s-success">
            <div class="status-num">{s2}</div>
            <div class="status-lbl">2xx success</div>
          </div>
          <div class="status-card s-client">
            <div class="status-num">{s4}</div>
            <div class="status-lbl">4xx client err</div>
          </div>
          <div class="status-card s-server">
            <div class="status-num">{s5}</div>
            <div class="status-lbl">5xx server err</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── IP FORENSICS PANE ── -->
  <div id="pane-forensics" class="pane">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Detailed IP forensics logs</span>
        <div class="search-wrapper">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input type="text" id="forensicsSearch" class="search-input" placeholder="Search IP address or threats..." onkeyup="filterForensicsTable()">
        </div>
      </div>
      <table id="forensicsTable">
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Requests</th>
            <th>Auth Failures</th>
            <th>Threat Signature</th>
            <th>Action Status</th>
          </tr>
        </thead>
        <tbody>
          {forensics_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── SECURITY ALERTS PANE ── -->
  <div id="pane-security" class="pane">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title" style="color:var(--rose)">Abuse Alerts Timeline</span>
      </div>
      <div class="alert-list">
        {alert_boxes}
      </div>
    </div>
  </div>

  <!-- ── TRAFFIC PANE ── -->
  <div id="pane-traffic" class="pane">
    <div class="panel" style="margin-bottom:1.5rem;">
      <div class="panel-header">
        <span class="panel-title">Requests Volume per IP address</span>
      </div>
      <div class="chartbox-lg" style="height: 300px; position: relative;">
        <canvas id="barChart" role="img" aria-label="Requests by IP Chart"></canvas>
      </div>
    </div>

    <div class="grid-2col">
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Endpoint distribution</span>
        </div>
        <div class="chartbox" style="height: 240px; position: relative;">
          <canvas id="donutChart" role="img" aria-label="Endpoint distribution donut chart"></canvas>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Traffic spikes</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Hour</th>
              <th>Requests</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {spike_rows}
          </tbody>
        </table>
        <div style="margin-top: 1.25rem; font-size: 0.8rem; color: var(--text-muted);">
          Computed Mean: <span class="mono" style="color:white;">{analysis.get('mean_rph', 0)} req/hr</span> &nbsp;·&nbsp; Standard Deviation (&sigma;): <span class="mono" style="color:white;">{analysis.get('std_rph', 0)}</span>
        </div>
      </div>
    </div>
  </div>

  <footer>
    SentinelLog &copy; 2026. Made with Premium SIEM Dashboard Engine.
  </footer>
</div>

<script>
function switchTab(name) {{
  document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
  
  document.getElementById('pane-' + name).classList.add('active');
  
  const tabIndex = {{'overview':0, 'forensics':1, 'security':2, 'traffic':3}}[name];
  document.querySelectorAll('.tab-btn')[tabIndex].classList.add('active');
  
  if (name === 'traffic') {{
    initCharts();
  }}
}}

function filterForensicsTable() {{
  const input = document.getElementById('forensicsSearch');
  const filter = input.value.toLowerCase();
  const table = document.getElementById('forensicsTable');
  const tr = table.getElementsByTagName('tr');

  for (let i = 1; i < tr.length; i++) {{
    let rowText = tr[i].textContent || tr[i].innerText;
    if (rowText.toLowerCase().indexOf(filter) > -1) {{
      tr[i].style.display = "";
    }} else {{
      tr[i].style.display = "none";
    }}
  }}
}}

let chartsInited = false;
function initCharts() {{
  if (chartsInited) return;
  chartsInited = true;

  const barCtx = document.getElementById('barChart').getContext('2d');
  
  const blueGrad = barCtx.createLinearGradient(0, 0, 0, 300);
  blueGrad.addColorStop(0, 'rgba(59, 130, 246, 0.85)');
  blueGrad.addColorStop(1, 'rgba(139, 92, 246, 0.1)');
  
  const roseGrad = barCtx.createLinearGradient(0, 0, 0, 300);
  roseGrad.addColorStop(0, 'rgba(239, 68, 68, 0.85)');
  roseGrad.addColorStop(1, 'rgba(239, 68, 68, 0.15)');

  const colors = {json.dumps(chart_colors)}.map(c => c === '#ef4444' ? roseGrad : blueGrad);

  new Chart(document.getElementById('barChart'), {{
    type: 'bar',
    data: {{
      labels: {json.dumps(chart_labels)},
      datasets: [{{
        label: 'Requests Count',
        data: {json.dumps(chart_counts)},
        backgroundColor: colors,
        borderColor: {json.dumps(chart_colors)},
        borderWidth: 1.5,
        borderRadius: 6,
        hoverBackgroundColor: {json.dumps(chart_colors)},
      }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          backgroundColor: '#1f2937',
          titleFont: {{ family: 'Outfit', size: 13 }},
          bodyFont: {{ family: 'JetBrains Mono', size: 12 }},
          borderColor: 'rgba(255, 255, 255, 0.1)',
          borderWidth: 1
        }}
      }},
      scales: {{
        x: {{ 
          ticks: {{ 
            color: '#9ca3af', 
            font: {{ family: 'Outfit', size: 11 }},
            autoSkip: false, 
            maxRotation: 30 
          }},
          grid: {{ display: false }},
          border: {{ color: 'rgba(255, 255, 255, 0.08)' }} 
        }},
        y: {{ 
          ticks: {{ 
            color: '#9ca3af', 
            stepSize: 1,
            font: {{ family: 'JetBrains Mono', size: 11 }}
          }},
          grid: {{ color: 'rgba(255, 255, 255, 0.04)' }},
          border: {{ color: 'rgba(255, 255, 255, 0.08)' }}
        }}
      }}
    }}
  }});

  new Chart(document.getElementById('donutChart'), {{
    type: 'doughnut',
    data: {{
      labels: {json.dumps(donut_labels)},
      datasets: [{{
        data: {json.dumps(donut_counts)},
        backgroundColor: [
          '#3b82f6', '#10b981', '#ef4444', '#f59e0b', '#8b5cf6', 
          '#ec4899', '#14b8a6', '#6366f1', '#84cc16', '#06b6d4'
        ],
        borderWidth: 2,
        borderColor: '#0b0f19',
        hoverOffset: 4
      }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      plugins: {{
        legend: {{
          display: true, 
          position: 'right',
          labels: {{ 
            color: '#9ca3af', 
            font: {{ size: 12, family: 'Outfit' }},
            padding: 14, 
            boxWidth: 12,
            boxHeight: 12
          }}
        }},
        tooltip: {{
          backgroundColor: '#1f2937',
          titleFont: {{ family: 'Outfit', size: 12 }},
          bodyFont: {{ family: 'JetBrains Mono', size: 11 }},
          borderColor: 'rgba(255,255,255,0.08)',
          borderWidth: 1
        }}
      }},
      cutout: '70%'
    }}
  }});
}}
</script>
</body>
</html>"""

    Path(out_path).write_text(html, encoding="utf-8")
    log.info("HTML report saved → %s", out_path)


# ─── UPLOAD GUI ───────────────────────────────────────────────────────────────
def launch_gui() -> None:
    """Tkinter desktop file-picker — no pip install needed, built into Python."""
    import tkinter as tk
    from tkinter import filedialog, messagebox
    import webbrowser, tempfile

    root = tk.Tk()
    root.title("SentinelLog — Log Analyzer")
    root.geometry("340x130")
    root.resizable(False, False)

    def pick_file():
        path = filedialog.askopenfilename(
            title="Select your access.log",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            status_var.set("Parsing log file...")
            root.update()
            records = load_logs(path)
            status_var.set(f"Analysing {len(records):,} records...")
            root.update()
            result  = analyze(records)
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as tf:
             out = tf.name
            export_html(result, out)
            status_var.set(f"Done — {len(records):,} entries parsed.")
            webbrowser.open(out)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            status_var.set("Error — see dialog.")

    tk.Label(root, text="SentinelLog Analyzer", font=("Courier", 13, "bold")).pack(pady=(14, 6))
    tk.Button(root, text="Open log file and generate report…",
              command=pick_file, width=36).pack()
    status_var = tk.StringVar(value="Ready — click above to pick a log file.")
    tk.Label(root, textvariable=status_var, font=("Courier", 9),
             fg="gray").pack(pady=(8, 0))
    root.mainloop()


def generate_chart(analysis: dict, out_path: str = "ip_activity_chart.png") -> None:
    """Generate a bar chart of top IPs (requires matplotlib)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        log.warning("matplotlib not installed — skipping chart. pip install matplotlib")
        return

    ips    = [item[0] for item in analysis["top_ips"]]
    counts = [item[1] for item in analysis["top_ips"]]
    colors = ["#ef4444" if ip in analysis["flagged_ips"] else "#3b82f6" for ip in ips]

    fig, ax = plt.subplots(figsize=(11, 5), facecolor="#080b11")
    ax.set_facecolor("#080b11")
    bars = ax.bar(ips, counts, color=colors, width=0.6, zorder=3)

    ax.set_title("Top IP Addresses by Request Count", color="#f3f4f6", fontsize=13, pad=14)
    ax.set_xlabel("IP Address", color="#9ca3af", fontsize=10)
    ax.set_ylabel("Requests", color="#9ca3af", fontsize=10)
    ax.tick_params(colors="#9ca3af", labelsize=9)
    plt.xticks(rotation=40, ha="right")
    ax.grid(axis="y", linestyle="--", alpha=0.3, color="#253048", zorder=0)
    for spine in ax.spines.values():
        spine.set_color("#253048")

    # annotate bars
    for bar, val in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                str(val), ha="center", va="bottom", color="#f3f4f6", fontsize=9)

    from matplotlib.patches import Patch
    legend = [Patch(facecolor="#ef4444", label="Flagged"), Patch(facecolor="#3b82f6", label="Normal")]
    ax.legend(handles=legend, facecolor="#121826", edgecolor="#253048",
              labelcolor="#f3f4f6", fontsize=9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=140, facecolor="#080b11")
    plt.close()
    log.info("Chart saved → %s", out_path)


# ─── 6. SQLITE PERSISTENCE ────────────────────────────────────────────────────
def save_to_db(analysis: dict, db_path: str = "log_history.db") -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            run_at    TEXT,
            total     INTEGER,
            error_pct REAL,
            flagged   INTEGER,
            summary   TEXT
        )
    """)
    conn.execute(
        "INSERT INTO runs (run_at, total, error_pct, flagged, summary) VALUES (?,?,?,?,?)",
        (datetime.now().isoformat(), analysis["total"], analysis["error_rate"],
         len(analysis["flagged_ips"]), json.dumps(analysis, default=str)),
    )
    conn.commit()
    conn.close()
    log.info("Run saved → %s", db_path)


def compare_with_history(db_path: str = "log_history.db") -> None:
    """Print a delta table comparing the latest two runs."""
    conn  = sqlite3.connect(db_path)
    rows  = conn.execute(
        "SELECT run_at, total, error_pct, flagged FROM runs ORDER BY id DESC LIMIT 2"
    ).fetchall()
    conn.close()

    if len(rows) < 2:
        log.info("Not enough history for comparison (need ≥ 2 runs).")
        return

    curr, prev = rows
    W = 56
    print(f"\n  {'─' * W}")
    print("  HISTORICAL COMPARISON")
    print(f"  {'─' * W}")
    print(f"  {'Metric':<22} {'Previous':>12} {'Current':>12} {'Delta':>10}")
    print(f"  {'─' * W}")
    print(f"  {'Total requests':<22} {prev[1]:>12,} {curr[1]:>12,} {curr[1]-prev[1]:>+10,}")
    print(f"  {'Error rate %':<22} {prev[2]:>12.2f} {curr[2]:>12.2f} {curr[2]-prev[2]:>+10.2f}")
    print(f"  {'Flagged IPs':<22} {prev[3]:>12} {curr[3]:>12} {curr[3]-prev[3]:>+10}")
    print(f"  {'─' * W}\n")


def show_history(db_path: str = "log_history.db", limit: int = 10) -> None:
    """Print the last N analysis runs stored in the DB."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT id, run_at, total, error_pct, flagged FROM runs ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()

    if not rows:
        print("No history found.")
        return

    print(f"\n  {'ID':>4}  {'Run at':<22}  {'Requests':>10}  {'Err%':>6}  {'Flagged':>7}")
    print("  " + "─" * 56)
    for row in rows:
        print(f"  {row[0]:>4}  {row[1][:19]:<22}  {row[2]:>10,}  {row[3]:>6.2f}  {row[4]:>7}")
    print()


# ─── 7. CLI ───────────────────────────────────────────────────────────────────
def parse_dt_arg(s: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(f"Cannot parse date: {s!r}  (use YYYY-MM-DD)")


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="sentinellog",
        description="SentinelLog — parse, analyze, and audit Apache/Nginx log files.",
    )
    root.add_argument("--log-level", default="INFO",
                      choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity")
    root.add_argument("--gui", action="store_true",
                      help="Open file-picker GUI (no subcommand needed)")

    sub = root.add_subparsers(dest="command", required=False)

    # ── analyze ────────────────────────────────────────────────────────────────
    p_analyze = sub.add_parser("analyze", help="Parse and analyze a log file")
    p_analyze.add_argument("--file",           required=True,  help="Path to log file")
    p_analyze.add_argument("--top",            type=int, default=10, help="Top N IPs/endpoints")
    p_analyze.add_argument("--workers",        type=int, default=4,  help="Parallel workers")
    p_analyze.add_argument("--db",             default="log_history.db", help="SQLite DB path")
    p_analyze.add_argument("--report",         choices=["cli","csv","json","html","chart","all"],
                           default="cli", help="Output format(s)")
    p_analyze.add_argument("--filter-status",  choices=["2xx","3xx","4xx","5xx"],
                           dest="filter_status", help="Only include these status codes")
    p_analyze.add_argument("--since",          type=parse_dt_arg, help="Start date (YYYY-MM-DD)")
    p_analyze.add_argument("--until",          type=parse_dt_arg, help="End date (YYYY-MM-DD)")
    p_analyze.add_argument("--no-db",          action="store_true", help="Skip DB persistence")
    p_analyze.add_argument("--history",        action="store_true", help="Show run comparison after analysis")
    p_analyze.add_argument("--allowlist",      help="Comma-separated IP list or path to a file with one IP per line to exclude from flagging")
    p_analyze.add_argument("--watch",          action="store_true", help="Monitor the log file in real-time, tailing new entries and refreshing reports")

    # ── history ────────────────────────────────────────────────────────────────
    p_history = sub.add_parser("history", help="View previous analysis runs")
    p_history.add_argument("--db",    default="log_history.db")
    p_history.add_argument("--limit", type=int, default=10, help="Rows to show")

    # ── export ─────────────────────────────────────────────────────────────────
    p_export = sub.add_parser("export", help="Export the latest run from DB to file")
    p_export.add_argument("--db",  default="log_history.db")
    p_export.add_argument("--out", default="log_report.html", help="Output file (.html/.json/.csv)")

    return root


def cmd_analyze(args) -> None:
    allowlist = parse_allowlist(args.allowlist)
    records = load_logs(
        args.file,
        workers=args.workers,
        since=args.since,
        until=args.until,
        status_filter=args.filter_status,
    )
    if not records and not args.watch:
        log.warning("No matching records after filters — nothing to report.")
        sys.exit(0)

    results = analyze(records, top_n=args.top, allowlist=allowlist) if records else {}
    mode    = args.report

    if results:
        if mode in ("cli", "all"):
            print_report(results)
        if mode in ("csv", "all"):
            export_csv(results)
        if mode in ("json", "all"):
            export_json(results)
        if mode in ("html", "all"):
            export_html(results)
        if mode in ("chart", "all"):
            generate_chart(results)

        if not args.no_db:
            save_to_db(results, args.db)

        if args.history:
            compare_with_history(args.db)

        flagged = len(results.get("flagged_ips", {}))
        print(f"\n  ✅  Done. {results['total']:,} requests analysed."
              + (f"  🚨 {flagged} IP(s) flagged." if flagged else "  ✓ No threats detected."))

    if args.watch:
        import time
        log.info("Starting live watch mode on %s (Press Ctrl+C to stop)...", args.file)
        
        # Follow the file
        filepath = Path(args.file)
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            # Go to the end of file
            f.seek(0, 2)
            
            try:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1.0)
                        continue
                    
                    # Accumulate new records
                    new_records = []
                    while line:
                        if parsed := parse_line(line):
                            # Apply filters
                            keep = True
                            if args.since and parsed["dt"] and parsed["dt"] < args.since:
                                keep = False
                            if args.until and parsed["dt"] and parsed["dt"] > args.until:
                                keep = False
                            if args.filter_status:
                                grp = int(args.filter_status[0])
                                if parsed["status"] // 100 != grp:
                                    keep = False
                            if keep:
                                new_records.append(parsed)
                        line = f.readline()
                    
                    if new_records:
                        log.info("Watch Mode: Detected %s new log line(s)", len(new_records))
                        records.extend(new_records)
                        results = analyze(records, top_n=args.top, allowlist=allowlist)
                        
                        # Refresh reports
                        if mode in ("cli", "all"):
                            print_report(results)
                        if mode in ("csv", "all"):
                            export_csv(results)
                        if mode in ("json", "all"):
                            export_json(results)
                        if mode in ("html", "all"):
                            export_html(results)
                        if mode in ("chart", "all"):
                            generate_chart(results)
                            
                        # Update DB
                        if not args.no_db:
                            save_to_db(results, args.db)
                            
                        flagged = len(results.get("flagged_ips", {}))
                        print(f"  Live Update: {results['total']:,} requests analysed."
                              + (f"  🚨 {flagged} IP(s) flagged." if flagged else "  ✓ No threats detected."))
            except KeyboardInterrupt:
                log.info("Live watch stopped.")


def cmd_history(args) -> None:
    show_history(args.db, limit=args.limit)
    compare_with_history(args.db)


def cmd_export(args) -> None:
    conn = sqlite3.connect(args.db)
    row  = conn.execute("SELECT summary FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    if not row:
        log.error("No runs found in %s", args.db)
        sys.exit(1)
    analysis = json.loads(row[0])
    out      = args.out
    if out.endswith(".html"):
        export_html(analysis, out)
    elif out.endswith(".json"):
        export_json(analysis, out)
    elif out.endswith(".csv"):
        export_csv(analysis, out)
    else:
        log.error("Unknown extension for --out. Use .html, .json, or .csv")
        sys.exit(1)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    parser = build_parser()
    args   = parser.parse_args()
    configure_logging(args.log_level)

    if args.gui:
        launch_gui()
        return

    if not args.command:
        parser.print_help()
        sys.exit(0)

    try:
        {"analyze": cmd_analyze, "history": cmd_history, "export": cmd_export}[args.command](args)
    except FileNotFoundError as e:
        log.error("%s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
