"""
Simple IDS (Intrusion Detection System) 
=============================================================
A practical, interview-ready IDS that scans web/server logs for:
  1. Rule-based signatures (brute force, scanning, payload attacks, bot UAs)
  2. Anomaly-based outliers (statistical z-score or IsolationForest)

Architecture mirrors real SOC tooling:
  parse_events() → rule_engine() → anomaly_engine() → alert_generator() → report

Interview talking points:
  - Signature-based IDS: low false positives for known patterns, blind to novel attacks.
  - Anomaly-based IDS: catches zero-days but higher false positives.
  - SOC triage: analysts need severity, evidence, affected IP, and remediation context.
  - False positives: tuning thresholds per environment is critical.

Usage:
  python simple_ids.py --logfile access.log
  python simple_ids.py --logfile access.log --ruleset rules.json --output-json report.json
  python simple_ids.py --generate-sample sample.log   # generate test log

Sample ruleset (rules.json):
  {
    "failures_threshold": 5,
    "failures_window_seconds": 300,
    "scan_paths_threshold": 15,
    "unusual_endpoints": ["/admin", "/.git", "/.env", "/wp-admin"],
    "anomaly_engine": true
  }

Limitations:
  - Log format parsing is heuristic; custom formats may need regex tuning.
  - Time-window detection requires parseable timestamps.
  - Anomaly detection needs ≥50 events to be meaningful.
  - This is passive alerting; it does not block or respond.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Event:
    """Single parsed log event."""
    ip: str
    method: str
    path: str
    status: int
    timestamp: Optional[datetime]
    user_agent: str
    size: int
    raw: str


@dataclass
class Alert:
    """IDS alert for SOC triage."""
    severity: str           # HIGH / MED / LOW
    category: str           # human-readable attack category
    ip: str
    evidence: str
    count: int
    mitre_tactic: str       # MITRE ATT&CK mapping for interview context


# ---------------------------------------------------------------------------
# Parsing — supports CLF, JSON, and key=value logs
# ---------------------------------------------------------------------------
# Why three parsers: real environments mix formats (nginx CLF, app JSON logs, WAF kv).

CLF_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)

CLF_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def _parse_clf(line: str) -> Optional[Event]:
    m = CLF_RE.match(line)
    if not m:
        return None
    ts = None
    try:
        ts = datetime.strptime(m.group("time"), CLF_TIME_FMT)
    except Exception:
        pass
    size_str = m.group("size")
    return Event(
        ip=m.group("ip"),
        method=m.group("method"),
        path=m.group("path"),
        status=int(m.group("status")),
        timestamp=ts,
        user_agent=m.group("ua") or "",
        size=int(size_str) if size_str and size_str != "-" else 0,
        raw=line,
    )


def _parse_json(line: str) -> Optional[Event]:
    if not (line.startswith("{") and line.endswith("}")):
        return None
    try:
        obj = json.loads(line)
    except Exception:
        return None
    ts = None
    for key in ("timestamp", "time", "@timestamp", "ts"):
        if key in obj:
            try:
                ts = datetime.fromisoformat(str(obj[key]).replace("Z", "+00:00"))
            except Exception:
                pass
            break
    return Event(
        ip=str(obj.get("ip", obj.get("remote_addr", "unknown"))),
        method=str(obj.get("method", obj.get("request_method", "GET"))),
        path=str(obj.get("path", obj.get("uri", "/"))),
        status=int(obj.get("status", obj.get("response_code", 0))),
        timestamp=ts,
        user_agent=str(obj.get("user_agent", obj.get("http_user_agent", ""))),
        size=int(obj.get("size", obj.get("body_bytes_sent", 0))),
        raw=line,
    )


def _parse_kv(line: str) -> Optional[Event]:
    pairs = {k: (v1 or v2) for k, v1, v2 in KV_RE.findall(line)}
    if "ip" not in pairs and "src" not in pairs:
        return None
    return Event(
        ip=pairs.get("ip", pairs.get("src", "unknown")),
        method=pairs.get("method", "GET"),
        path=pairs.get("path", pairs.get("uri", "/")),
        status=int(pairs.get("status", pairs.get("code", "0"))),
        timestamp=None,
        user_agent=pairs.get("ua", pairs.get("user_agent", "")),
        size=int(pairs.get("size", pairs.get("bytes", "0"))),
        raw=line,
    )


def parse_line(line: str) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    return _parse_clf(line) or _parse_json(line) or _parse_kv(line)


def load_events(logfile: str) -> List[Event]:
    events: List[Event] = []
    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                events.append(ev)
    return events


# ---------------------------------------------------------------------------
# Rule engine (signature-based)
# ---------------------------------------------------------------------------
# Why signature rules: deterministic, low false-positive, explainable in SOC.

# Attack payload patterns in request paths/query strings
SQLI_PATTERNS = re.compile(
    r"('|\b(union|select|insert|drop|delete|update|exec)\b.*"
    r"(from|where|set|into|table)|--|;.*=)", re.I
)
XSS_PATTERNS = re.compile(r"(<script|javascript:|on\w+=|alert\(|eval\()", re.I)
PATH_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|%2e%2e", re.I)
COMMAND_INJECTION_RE = re.compile(r"[;&|`]|\$\(|%0a|%0d", re.I)

# Known scanner/bot user agents
BOT_UA_PATTERNS = re.compile(
    r"(nikto|sqlmap|nmap|dirbuster|gobuster|wpscan|nuclei|masscan|zgrab|curl/|python-requests)",
    re.I,
)


def rule_engine(events: List[Event], rules: Dict) -> List[Alert]:
    """
    Signature-based detection.
    Why rules are structured per-IP: SOC analysts triage by source, not by event.
    """
    alerts: List[Alert] = []

    failures_threshold = int(rules.get("failures_threshold", 5))
    failure_statuses = set(rules.get("failure_statuses", [401, 403, 429]))
    scan_paths_threshold = int(rules.get("scan_paths_threshold", 15))
    unusual_endpoints = set(rules.get("unusual_endpoints", [
        "/admin", "/.git", "/.env", "/wp-admin", "/wp-login.php",
        "/phpmyadmin", "/actuator", "/server-status",
    ]))

    # Aggregation structures
    failures_by_ip: Dict[str, int] = defaultdict(int)
    paths_by_ip: Dict[str, Set[str]] = defaultdict(set)
    total_by_ip: Dict[str, int] = defaultdict(int)
    unusual_by_ip: Dict[str, Set[str]] = defaultdict(set)
    payload_by_ip: Dict[str, List[str]] = defaultdict(list)
    bot_ips: Dict[str, str] = {}

    for ev in events:
        total_by_ip[ev.ip] += 1
        paths_by_ip[ev.ip].add(ev.path)

        # Brute-force
        if ev.status in failure_statuses:
            failures_by_ip[ev.ip] += 1

        # Unusual endpoints (deduplicated per IP)
        if ev.path in unusual_endpoints:
            unusual_by_ip[ev.ip].add(ev.path)

        # Attack payloads in path
        if SQLI_PATTERNS.search(ev.path):
            payload_by_ip[ev.ip].append(f"SQLi: {ev.path[:80]}")
        elif XSS_PATTERNS.search(ev.path):
            payload_by_ip[ev.ip].append(f"XSS: {ev.path[:80]}")
        elif PATH_TRAVERSAL_RE.search(ev.path):
            payload_by_ip[ev.ip].append(f"PathTraversal: {ev.path[:80]}")
        elif COMMAND_INJECTION_RE.search(ev.path):
            payload_by_ip[ev.ip].append(f"CmdInj: {ev.path[:80]}")

        # Bot user agent
        if ev.user_agent and BOT_UA_PATTERNS.search(ev.user_agent):
            bot_ips[ev.ip] = ev.user_agent[:60]

    # --- Generate alerts ---

    # 1. Brute-force
    for ip, count in failures_by_ip.items():
        if count >= failures_threshold:
            alerts.append(Alert(
                severity="HIGH" if count >= failures_threshold * 3 else "MED",
                category="Brute-force / credential stuffing",
                ip=ip,
                evidence=f"{count} auth failures (statuses {sorted(failure_statuses)})",
                count=count,
                mitre_tactic="TA0006 Credential Access",
            ))

    # 2. Scanning behavior
    for ip, paths in paths_by_ip.items():
        if len(paths) >= scan_paths_threshold:
            alerts.append(Alert(
                severity="MED",
                category="Scanning / enumeration",
                ip=ip,
                evidence=f"{len(paths)} unique paths probed, {total_by_ip[ip]} total requests",
                count=len(paths),
                mitre_tactic="TA0007 Discovery",
            ))

    # 3. Unusual endpoint access (deduplicated per IP)
    for ip, endpoints in unusual_by_ip.items():
        alerts.append(Alert(
            severity="MED",
            category="Sensitive endpoint probing",
            ip=ip,
            evidence=f"Accessed: {', '.join(sorted(endpoints))}",
            count=len(endpoints),
            mitre_tactic="TA0007 Discovery",
        ))

    # 4. Attack payloads
    for ip, payloads in payload_by_ip.items():
        # Deduplicate and cap display
        unique = list(dict.fromkeys(payloads))[:5]
        alerts.append(Alert(
            severity="HIGH",
            category="Attack payload detected",
            ip=ip,
            evidence=f"{len(payloads)} malicious requests; samples: {'; '.join(unique)}",
            count=len(payloads),
            mitre_tactic="TA0001 Initial Access",
        ))

    # 5. Known scanner/bot UA
    for ip, ua in bot_ips.items():
        alerts.append(Alert(
            severity="LOW",
            category="Known scanner user-agent",
            ip=ip,
            evidence=f"UA: {ua}",
            count=total_by_ip.get(ip, 1),
            mitre_tactic="TA0043 Reconnaissance",
        ))

    return alerts


# ---------------------------------------------------------------------------
# Anomaly engine (statistical / optional ML)
# ---------------------------------------------------------------------------

def anomaly_engine(events: List[Event], enabled: bool = True) -> List[Alert]:
    """
    Anomaly-based IDS using z-score or IsolationForest.
    Why: catches attacks that don't match known signatures (zero-days, custom tools).
    Tradeoff: higher false-positive rate; requires analyst judgement.
    """
    if not enabled or len(events) < 50:
        return []

    # Aggregate per-IP features
    stats: Dict[str, Dict] = {}
    for ev in events:
        s = stats.setdefault(ev.ip, {"total": 0, "errors": 0, "paths": set(), "methods": set()})
        s["total"] += 1
        if 400 <= ev.status < 600:
            s["errors"] += 1
        s["paths"].add(ev.path)
        s["methods"].add(ev.method)

    ips = list(stats.keys())
    if len(ips) < 5:
        return []

    # Feature matrix: [total_requests, unique_paths, error_rate, method_count]
    X = []
    for ip in ips:
        total = stats[ip]["total"]
        X.append([
            total,
            len(stats[ip]["paths"]),
            stats[ip]["errors"] / max(1, total),
            len(stats[ip]["methods"]),
        ])

    # Try IsolationForest first
    try:
        from sklearn.ensemble import IsolationForest  # type: ignore
        model = IsolationForest(contamination=0.05, random_state=42)
        preds = model.fit_predict(X)
        alerts: List[Alert] = []
        for ip, pred, feats in zip(ips, preds, X):
            if pred == -1:
                alerts.append(Alert(
                    severity="MED",
                    category="Anomalous traffic (ML)",
                    ip=ip,
                    evidence=(
                        f"IsolationForest outlier: requests={int(feats[0])}, "
                        f"paths={int(feats[1])}, err_rate={feats[2]:.2f}"
                    ),
                    count=int(feats[0]),
                    mitre_tactic="TA0007 Discovery",
                ))
        return alerts
    except ImportError:
        pass

    # Fallback: z-score
    def z_scores(values: List[float]) -> List[float]:
        n = len(values)
        mean = sum(values) / n
        var = sum((v - mean) ** 2 for v in values) / max(1, n - 1)
        std = math.sqrt(var) if var > 0 else 1.0
        return [(v - mean) / std for v in values]

    z_totals = z_scores([x[0] for x in X])
    z_paths = z_scores([x[1] for x in X])

    alerts = []
    for i, ip in enumerate(ips):
        if z_totals[i] > 2.5 or z_paths[i] > 2.5:
            alerts.append(Alert(
                severity="MED",
                category="Anomalous traffic (z-score)",
                ip=ip,
                evidence=f"z_requests={z_totals[i]:.1f}, z_paths={z_paths[i]:.1f}",
                count=int(X[i][0]),
                mitre_tactic="TA0007 Discovery",
            ))
    return alerts


# ---------------------------------------------------------------------------
# Alert generator — merge, deduplicate, prioritize
# ---------------------------------------------------------------------------

def alert_generator(rule_alerts: List[Alert], anomaly_alerts: List[Alert]) -> List[Alert]:
    """
    Consolidate alerts, removing duplicates and sorting by severity.
    Why: SOC analysts need a concise, prioritized list — not raw noise.
    """
    all_alerts = rule_alerts + anomaly_alerts

    # Deduplicate by (category, ip)
    seen: set = set()
    unique: List[Alert] = []
    for a in all_alerts:
        key = (a.category, a.ip)
        if key not in seen:
            seen.add(key)
            unique.append(a)

    severity_rank = {"HIGH": 3, "MED": 2, "LOW": 1}
    return sorted(unique, key=lambda a: severity_rank.get(a.severity, 0), reverse=True)


# ---------------------------------------------------------------------------
# Sample log generator (for testing without a real log file)
# ---------------------------------------------------------------------------

def generate_sample_log(path: str, num_events: int = 500) -> None:
    """
    Produce a realistic mixed-traffic log for IDS testing.
    Why: enables immediate testing without hunting for sample data.
    """
    normal_ips = [f"10.0.1.{i}" for i in range(1, 20)]
    attacker_ip = "203.0.113.42"
    scanner_ip = "198.51.100.99"

    normal_paths = ["/", "/index.html", "/about", "/api/v1/users", "/static/style.css",
                    "/api/v1/products", "/contact", "/blog/post-1"]
    sensitive_paths = ["/admin", "/.git/config", "/.env", "/wp-login.php", "/actuator/health"]
    sqli_paths = ["/search?q=' OR 1=1--", "/login?user=admin'--", "/api?id=1 UNION SELECT * FROM users"]
    xss_paths = ["/comment?body=<script>alert(1)</script>", "/search?q=<img onerror=alert(1)>"]

    base_time = datetime(2026, 4, 30, 8, 0, 0)
    lines: List[str] = []

    for i in range(num_events):
        ts = base_time + timedelta(seconds=i * 2)
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

        # 80% normal, 10% brute-force, 5% scanner, 5% payload attacks
        r = random.random()
        if r < 0.80:
            ip = random.choice(normal_ips)
            path = random.choice(normal_paths)
            status = random.choice([200, 200, 200, 304, 301])
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        elif r < 0.90:
            ip = attacker_ip
            path = "/login"
            status = random.choice([401, 401, 401, 403])
            ua = "python-requests/2.28.0"
        elif r < 0.95:
            ip = scanner_ip
            path = random.choice(sensitive_paths + [f"/probe-{random.randint(1,100)}"])
            status = random.choice([404, 403, 200])
            ua = "Nikto/2.1.6"
        else:
            ip = attacker_ip
            path = random.choice(sqli_paths + xss_paths)
            status = random.choice([200, 500, 403])
            ua = "sqlmap/1.7"

        size = random.randint(200, 15000)
        line = f'{ip} - - [{ts_str}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'
        lines.append(line)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {num_events} sample log events → {path}")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(events: List[Event], alerts: List[Alert]) -> None:
    print("=== Simple IDS ===")
    print(f"Events parsed  : {len(events)}")
    print(f"Unique IPs     : {len(set(e.ip for e in events))}")
    print(f"Alerts generated: {len(alerts)}")
    print()

    # Summary by severity
    sev_counts = defaultdict(int)
    for a in alerts:
        sev_counts[a.severity] += 1
    print(f"  HIGH: {sev_counts.get('HIGH', 0)}  MED: {sev_counts.get('MED', 0)}  LOW: {sev_counts.get('LOW', 0)}")
    print()

    for a in alerts:
        print(f"[{a.severity}] {a.category}")
        print(f"  IP       : {a.ip}")
        print(f"  Evidence : {a.evidence}")
        print(f"  MITRE    : {a.mitre_tactic}")
        print()

    # --- Educational footer ---
    print("=" * 50)
    print("IDS Concepts (interview-ready):")
    print()
    print("  Signature-based IDS:")
    print("    - Matches traffic against known-bad patterns (like antivirus signatures)")
    print("    - Low false positives; blind to novel/zero-day attacks")
    print("    - Examples: Snort rules, Suricata, this tool's rule_engine()")
    print()
    print("  Anomaly-based IDS:")
    print("    - Builds a baseline of 'normal' and alerts on deviations")
    print("    - Catches unknown attacks; higher false-positive rate")
    print("    - Examples: ML models, statistical thresholds, this tool's anomaly_engine()")
    print()
    print("  False positives & SOC triage:")
    print("    - Every alert must include evidence for analyst to verify")
    print("    - Tuning thresholds per environment reduces alert fatigue")
    print("    - MITRE ATT&CK mapping helps analysts understand attacker intent")
    print()
    print("  Limitations of this tool:")
    print("    - Passive only (no blocking/response)")
    print("    - Time-window analysis requires parseable timestamps")
    print("    - Real IDS (Snort/Suricata) inspects packets, not just logs")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simple IDS — signature + anomaly detection on log files",
    )
    parser.add_argument("--logfile", help="Path to log file to analyze")
    parser.add_argument("--ruleset", help="JSON ruleset file (optional)")
    parser.add_argument("--output-json", help="Write JSON report to file")
    parser.add_argument("--generate-sample", metavar="PATH",
                        help="Generate a sample log file for testing")

    args = parser.parse_args()

    if args.generate_sample:
        generate_sample_log(args.generate_sample)
        return

    if not args.logfile:
        parser.error("--logfile is required (or use --generate-sample)")

    # Load ruleset
    rules: Dict = {}
    if args.ruleset:
        with open(args.ruleset, "r", encoding="utf-8") as f:
            rules = json.load(f)

    events = load_events(args.logfile)
    if not events:
        print("No events parsed from log file.")
        return

    rule_alerts = rule_engine(events, rules)
    anomaly_alerts = anomaly_engine(events, enabled=rules.get("anomaly_engine", True))
    alerts = alert_generator(rule_alerts, anomaly_alerts)

    print_report(events, alerts)

    if args.output_json:
        report = {
            "events_parsed": len(events),
            "unique_ips": len(set(e.ip for e in events)),
            "alerts": [asdict(a) for a in alerts],
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.output_json}")


if __name__ == "__main__":
    main()
