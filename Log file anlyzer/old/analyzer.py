"""
Log File Analyzer — analyzer.py
================================
A CLI tool for parsing, analyzing, and reporting on Apache-format log files.

Usage:
    python analyzer.py --file access.log
    python analyzer.py --file access.log --report pdf
    python analyzer.py --file access.log --filter-status 4xx --top 20
"""

import re
import argparse
import sqlite3
import csv
import json
import statistics
from datetime import datetime
from collections import Counter, defaultdict
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed


# ─── 1. REGEX PATTERN ─────────────────────────────────────────────────────────
# Apache / Nginx Combined Log Format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://ref" "Mozilla/5.0"
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)'            # Client IP
    r' \S+ \S+ '              # ident, authuser (usually -)
    r'\[(?P<timestamp>[^\]]+)\] '  # Timestamp
    r'"(?P<method>\w+) '      # HTTP Method
    r'(?P<path>\S+) '         # Requested path
    r'\S+" '                  # Protocol
    r'(?P<status>\d{3}) '     # Status code
    r'(?P<bytes>\d+|-) '      # Response size
    r'"(?P<referer>[^"]*)" '  # Referer
    r'"(?P<ua>[^"]*)"'        # User-Agent
)

# Security signatures to flag
SQLI_PATTERNS   = re.compile(r"(union|select|insert|drop|or 1=1|'--)", re.I)
TRAVERSAL_PATHS = re.compile(r"(\.\./|etc/passwd|/wp-admin|/phpmyadmin|/admin/config)", re.I)
SCANNER_AGENTS  = re.compile(r"(nikto|sqlmap|nessus|nmap|masscan|dirbuster)", re.I)


# ─── 2. PARSING ───────────────────────────────────────────────────────────────
def parse_line(line: str) -> dict | None:
    """Parse a single log line into a structured dict. Returns None on failure."""
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
    """Parse a chunk of lines — suitable for multiprocessing."""
    return [r for line in lines if (r := parse_line(line))]


def load_logs(filepath: str, workers: int = 4) -> list[dict]:
    """
    Load and parse a log file using parallel processing for large files.
    Files under 10 MB are parsed in a single pass; larger ones use a pool.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    lines = path.read_text(errors="replace").splitlines()
    size_mb = path.stat().st_size / (1024 * 1024)

    if size_mb < 10 or workers == 1:
        records = parse_chunk(lines)
    else:
        chunk_size = max(1000, len(lines) // workers)
        chunks = [lines[i:i+chunk_size] for i in range(0, len(lines), chunk_size)]
        records = []
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(parse_chunk, c): c for c in chunks}
            for f in as_completed(futures):
                records.extend(f.result())

    print(f"[parser] Parsed {len(records):,} valid entries from {len(lines):,} lines "
          f"({size_mb:.1f} MB) using {workers} worker(s).")
    return records


# ─── 3. ANALYSIS ──────────────────────────────────────────────────────────────
def analyze(records: list[dict], top_n: int = 10) -> dict:
    """Run all analysis passes over the parsed log records."""
    total = len(records)
    if total == 0:
        return {}

    # --- Traffic by hour
    hour_counts = Counter(r["dt"].hour for r in records if r["dt"])

    # --- Status codes
    status_counts = Counter(r["status"] for r in records)
    status_groups = defaultdict(int)
    for code, cnt in status_counts.items():
        status_groups[f"{code // 100}xx"] += cnt

    # --- Top IPs
    ip_counts = Counter(r["ip"] for r in records)

    # --- Top endpoints
    endpoint_counts = Counter(r["path"] for r in records)

    # --- User agents
    ua_counts = Counter(r["ua"] for r in records)

    # --- Anomaly detection (DDoS heuristic)
    hourly_vals = list(hour_counts.values())
    mean_rps = statistics.mean(hourly_vals) if hourly_vals else 0
    std_rps  = statistics.stdev(hourly_vals) if len(hourly_vals) > 1 else 0
    spike_hours = {h: c for h, c in hour_counts.items() if c > mean_rps + 2 * std_rps}

    # --- Security forensics per IP
    ip_security = defaultdict(lambda: {"requests": 0, "auth_failures": 0,
                                        "threats": set(), "paths": []})
    for r in records:
        ip = r["ip"]
        ip_security[ip]["requests"] += 1
        if r["status"] in (401, 403):
            ip_security[ip]["auth_failures"] += 1
        if SQLI_PATTERNS.search(r["path"]):
            ip_security[ip]["threats"].add("SQL Injection")
        if TRAVERSAL_PATHS.search(r["path"]):
            ip_security[ip]["threats"].add("Path Traversal")
        if SCANNER_AGENTS.search(r["ua"]):
            ip_security[ip]["threats"].add("Scanner UA")
        ip_security[ip]["paths"].append(r["path"])

    flagged_ips = {
        ip: data for ip, data in ip_security.items()
        if data["threats"] or data["auth_failures"] >= 3
    }
    for ip in flagged_ips:
        if ip_security[ip]["auth_failures"] >= 3:
            flagged_ips[ip]["threats"].add("Brute Force")

    return {
        "total":          total,
        "unique_ips":     len(ip_counts),
        "error_rate":     round((status_groups.get("4xx", 0) + status_groups.get("5xx", 0)) / total * 100, 2),
        "hour_counts":    dict(sorted(hour_counts.items())),
        "status_counts":  dict(status_counts.most_common()),
        "status_groups":  dict(status_groups),
        "top_ips":        ip_counts.most_common(top_n),
        "top_endpoints":  endpoint_counts.most_common(top_n),
        "top_ua":         ua_counts.most_common(5),
        "spike_hours":    spike_hours,
        "flagged_ips":    {ip: {**d, "threats": list(d["threats"])} for ip, d in flagged_ips.items()},
        "mean_rph":       round(mean_rps, 1),
        "std_rph":        round(std_rps, 1),
    }


# ─── 4. SQLITE PERSISTENCE ────────────────────────────────────────────────────
def save_to_db(analysis: dict, db_path: str = "log_history.db"):
    """Persist analysis summary to SQLite for historical comparison."""
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
        (
            datetime.now().isoformat(),
            analysis["total"],
            analysis["error_rate"],
            len(analysis["flagged_ips"]),
            json.dumps(analysis, default=str),
        ),
    )
    conn.commit()
    conn.close()
    print(f"[db] Saved run to {db_path}")


def compare_with_history(db_path: str = "log_history.db"):
    """Print a simple comparison with the previous run."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT run_at, total, error_pct, flagged FROM runs ORDER BY id DESC LIMIT 2"
    ).fetchall()
    conn.close()

    if len(rows) < 2:
        print("[history] Not enough runs to compare yet.")
        return

    curr, prev = rows
    print("\n── Historical comparison ──────────────────────────────")
    print(f"  {'Metric':<20} {'Previous':>12} {'Current':>12} {'Delta':>10}")
    print(f"  {'Total requests':<20} {prev[1]:>12,} {curr[1]:>12,} {curr[1]-prev[1]:>+10,}")
    print(f"  {'Error rate %':<20} {prev[2]:>12.2f} {curr[2]:>12.2f} {curr[2]-prev[2]:>+10.2f}")
    print(f"  {'Flagged IPs':<20} {prev[3]:>12} {curr[3]:>12} {curr[3]-prev[3]:>+10}")


# ─── 5. REPORTING ─────────────────────────────────────────────────────────────
def print_report(analysis: dict):
    """Print a formatted CLI dashboard."""
    W = 56
    sep = "─" * W

    print(f"\n{'═' * W}")
    print(f"  LOG FILE ANALYSIS REPORT  —  {datetime.now():%Y-%m-%d %H:%M}")
    print(f"{'═' * W}")

    print(f"\n  Total requests : {analysis['total']:,}")
    print(f"  Unique IPs     : {analysis['unique_ips']:,}")
    print(f"  Error rate     : {analysis['error_rate']}%")
    print(f"  Mean req/hour  : {analysis['mean_rph']}  (σ = {analysis['std_rph']})")

    print(f"\n  {sep}")
    print("  STATUS CODE BREAKDOWN")
    print(f"  {sep}")
    for grp, cnt in sorted(analysis["status_groups"].items()):
        bar = "█" * min(cnt, 40)
        print(f"  {grp}  {bar}  {cnt}")

    print(f"\n  {sep}")
    print("  TOP ENDPOINTS")
    print(f"  {sep}")
    for path, cnt in analysis["top_endpoints"]:
        short = (path[:45] + "…") if len(path) > 46 else path
        print(f"  {cnt:>6}  {short}")

    print(f"\n  {sep}")
    print("  TOP IP ADDRESSES")
    print(f"  {sep}")
    for ip, cnt in analysis["top_ips"]:
        flag = " ← FLAGGED" if ip in analysis["flagged_ips"] else ""
        print(f"  {cnt:>6}  {ip:<18}{flag}")

    if analysis["spike_hours"]:
        print(f"\n  {sep}")
        print("  ⚠ TRAFFIC ANOMALIES (> mean + 2σ)")
        print(f"  {sep}")
        for h, c in analysis["spike_hours"].items():
            print(f"  Hour {h:02d}:00  →  {c} requests")

    if analysis["flagged_ips"]:
        print(f"\n  {sep}")
        print("  🚨 SECURITY ALERTS")
        print(f"  {sep}")
        for ip, d in analysis["flagged_ips"].items():
            threats = ", ".join(d["threats"]) or "Auth failures"
            print(f"  {ip:<18}  {d['requests']:>4} req  |  {d['auth_failures']} auth fails  |  {threats}")
    else:
        print("\n  ✓ No suspicious IPs detected.")

    print(f"\n{'═' * W}\n")


def export_csv(analysis: dict, out_path: str = "report.csv"):
    """Export the top IPs and flagged IPs to a CSV file."""
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "requests", "auth_failures", "threats"])
        for ip, cnt in analysis["top_ips"]:
            d = analysis["flagged_ips"].get(ip, {})
            w.writerow([ip, cnt, d.get("auth_failures", 0), "; ".join(d.get("threats", []))])
    print(f"[csv] Saved to {out_path}")


def export_json(analysis: dict, out_path: str = "report.json"):
    """Export the full analysis as JSON."""
    with open(out_path, "w") as f:
        json.dump(analysis, f, indent=2, default=str)
    print(f"[json] Saved to {out_path}")


# ─── 6. CLI ENTRYPOINT ────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Log File Analyzer — parse, analyze, and audit Apache-format log files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python analyzer.py --file access.log\n"
               "  python analyzer.py --file access.log --report csv --top 20\n"
               "  python analyzer.py --file access.log --workers 8 --history",
    )
    p.add_argument("--file",     required=True, help="Path to the log file")
    p.add_argument("--top",      type=int, default=10, help="Show top N IPs/endpoints (default: 10)")
    p.add_argument("--workers",  type=int, default=4, help="Parallel workers for large files (default: 4)")
    p.add_argument("--report",   choices=["cli", "csv", "json", "all"], default="cli",
                   help="Output format (default: cli)")
    p.add_argument("--db",       default="log_history.db", help="SQLite database path")
    p.add_argument("--history",  action="store_true", help="Compare with previous run from DB")
    return p

def export_to_csv(analysis: dict, filename="log_report.csv"):
    """Saves the top IPs and Endpoints to a CSV file."""
    with open(filename, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Item", "Count"])
        for ip, count in analysis['top_ips']:
            writer.writerow(["Top IP", ip, count])
        for path, count in analysis['top_endpoints']:
            writer.writerow(["Top Endpoint", path, count])
    print(f"\n[export] Report saved to {filename}")


def print_report(analysis: dict):
    """Print a clean summary of findings to the terminal."""
    if not analysis:
        print("No data to report.")
        return

    print("\n" + "="*60)
    print(f" LOG ANALYSIS REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("="*60)
    
    print(f"Total Requests:   {analysis['total']:,}")
    print(f"Unique Visitors:  {analysis['unique_ips']:,}")
    print(f"Error Rate:       {analysis['error_rate']}%")
    
    print("\n[!] SECURITY ALERTS")
    if not analysis['flagged_ips']:
        print("  No suspicious activity detected.")
    for ip, data in list(analysis['flagged_ips'].items())[:5]: # Show top 5
        print(f"  - {ip}: {', '.join(data['threats'])} ({data['requests']} reqs)")

    print("\n[+] TOP ENDPOINTS")
    for path, count in analysis['top_endpoints']:
        print(f"  {count:>7,}  {path}")

    if analysis['spike_hours']:
        print("\n[?] TRAFFIC SPIKES DETECTED")
        for hour, count in analysis['spike_hours'].items():
            print(f"  Hour {hour:02d}:00 -> {count:,} requests (Anomaly)")


import matplotlib.pyplot as plt

def generate_visual_report(analysis: dict):
    """Generates a bar chart of the top IP addresses."""
    if not analysis.get('top_ips'):
        print("[visual] No IP data found for charting.")
        return

    # Extract labels (IPs) and values (counts) from the analysis dict
    ips = [item[0] for item in analysis['top_ips']]
    counts = [item[1] for item in analysis['top_ips']]

    plt.figure(figsize=(10, 6))
    
    # Highlight flagged IPs (like 1.1.1.1) in red, others in skyblue
    colors = ['red' if ip == '1.1.1.1' else 'skyblue' for ip in ips]

    # --- ADD THESE LINES TO FINISH IT ---
    plt.bar(ips, counts, color=colors)
    plt.title('Top 10 Most Active IP Addresses', fontsize=14, fontweight='bold')
    plt.xlabel('IP Address', fontsize=12)
    plt.ylabel('Number of Requests', fontsize=12)
    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    
    # Save the chart as an image in your current folder
    plt.savefig('ip_activity_chart.png')
    print("[visual] Graphical report saved as 'ip_activity_chart.png'")


def main():
    parser = argparse.ArgumentParser(description="SentinelLog Analyzer")
    parser.add_argument("--file", required=True, help="Path to log file")
    parser.add_argument("--top", type=int, default=10, help="Number of items")
    args = parser.parse_args()

    try:
        # 1. Processing (This MUST come first to create the 'results' variable)
        records = load_logs(args.file)
        results = analyze(records, top_n=args.top)
        
        # 2. Terminal Reporting
        print_report(results)
        
        # 3. Database & History
        save_to_db(results)
        compare_with_history()
        
        # 4. File Exports (CSV and the Chart)
        export_to_csv(results)
        generate_visual_report(results)
        
        print("\n" + "═"*60)
        print(" ✅ SUCCESS: Terminal, Database, CSV, and Chart updated.")
        print("═"*60 + "\n")
        
    except Exception as e:
        print(f"❌ ERROR: {e}")

if __name__ == "__main__":
    main()
