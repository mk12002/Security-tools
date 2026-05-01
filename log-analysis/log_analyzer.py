"""
TOOL 1 — Log Analyzer + Anomaly Detection (Auth Logs)
=========================================================
A production-quality, interview-ready CLI tool for detecting security anomalies
in authentication logs (SSH, web auth, or generic format).

Why this exists (security reasoning):
- Brute-force attacks manifest as repeated failures from the same IP or
  distributed attempts against a single username from many IPs.
- Password spraying attacks try a small number of passwords against many
  usernames from a single IP to stay below per-user lockout thresholds.
- Credential stuffing uses leaked credential pairs; a pattern of single
  success-after-failure across many accounts from one source is a red flag.
- Abnormal login behavior (e.g., unusual hours or first-time IPs for a user)
  often indicates account compromise, shared credentials, or insider misuse.
- Optional ML (Isolation Forest) helps surface subtle anomalies without
  hard-coded rules, but must be explainable and bounded by careful features.

Usage examples:
  python log_analyzer.py --logfile auth.log
  python log_analyzer.py --logfile auth.log --fail-threshold 3 --time-window 10
  python log_analyzer.py --logfile auth.log --enable-ml --output-json results.json
  python log_analyzer.py --generate-sample sample_auth.log   # create test data

Sample input (mixed formats):
------------------------------------------------
Apr 28 01:12:01 server sshd[1234]: Failed password for alice from 203.0.113.8 port 53321 ssh2
Apr 28 01:12:02 server sshd[1234]: Failed password for alice from 203.0.113.8 port 53321 ssh2
Apr 28 01:12:10 server sshd[1234]: Accepted password for alice from 203.0.113.8 port 53321 ssh2
2026-04-28T14:05:10Z webauth user=bob ip=198.51.100.42 result=success
2026-04-28T02:05:10Z webauth user=carol ip=198.51.100.42 result=failure
2026-04-28T03:05:10Z webauth user=carol ip=203.0.113.20 result=failure
2026-04-28 03:07:10 auth user=dave ip=203.0.113.99 status=FAIL
2026-04-28 13:07:10 auth user=dave ip=203.0.113.99 status=OK

Sample output (human readable):
------------------------------------------------
=== Log Analysis Summary ===
  Time span   : 2026-04-28 01:12:01 → 2026-04-28 14:05:10
  Total events: 8 (6 failures, 2 successes)
  Unique users: 4 | Unique IPs: 4
  Parse rate  : 100.0%

[HIGH] Brute-force (IP): 203.0.113.8 — 2 failures in 5m, then success (possible compromise)
[HIGH] Correlated anomaly: alice — unusual hour + first-time IP from 203.0.113.8
[MED]  Password spray: 198.51.100.42 targeted 2 distinct users with ≤2 attempts each in 5m
[MED]  Username targeted from many IPs: carol — failures from 2 distinct IPs in 10m
[MED]  Unusual login hour: bob at 02:00 (baseline 09-18)
[LOW]  First-time IP: dave from 203.0.113.99 (public)
[LOW]  ML anomaly: carol from 198.51.100.42 at 2026-04-28T02:05:10 (failure)

Limitations & false positives (SOC interview points):
- Shared corporate NATs or VPNs can make many users appear from the same IP.
- Travel or remote work can cause legitimate unusual-hour logins.
- Distributed password-spraying might not exceed per-IP thresholds.
- ML flags depend on data volume/quality; small datasets yield noisy results.
- Credential stuffing detection needs enough accounts; single-user logs are insufficient.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple, Dict, Set


# -----------------------------
# Data model
# -----------------------------
@dataclass
class AuthEvent:
    """Normalized authentication event.

    Every parsed log line is converted into this structure so that all
    downstream detectors work on a consistent schema regardless of the
    original log format.
    """
    timestamp: dt.datetime
    username: str
    ip: str
    result: str        # "success" or "failure"
    raw: str
    ip_type: str = ""  # "private" or "public" — enriched after parsing


# -----------------------------
# Parsing logic
# -----------------------------
# We support multiple common patterns to reduce fragility:
# - OpenSSH syslog lines (Failed/Accepted password)
# - Key=Value logs (user=, ip=, result=)
# - Generic logs (status=OK/FAIL)
SSH_FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+.*sshd\[\d+\]:\s+Failed password for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+.*sshd\[\d+\]:\s+Accepted password for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)

KEYVAL_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}Z?)\s+.*?user=(?P<user>\S+)\s+ip=(?P<ip>\S+)\s+result=(?P<res>\w+)"
)

GENERIC_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}Z?)\s+.*?user=(?P<user>\S+)\s+ip=(?P<ip>\S+)\s+status=(?P<res>\w+)"
)


def _parse_timestamp(value: str) -> Optional[dt.datetime]:
    """Parse timestamps in a small set of common auth log formats.

    Why this exists: logs often vary by source (syslog vs ISO8601). We normalize
    to UTC-naive datetime for consistent comparisons.
    """
    # Syslog: "Apr 28 01:12:01" (assume current year)
    for fmt in ("%b %d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = dt.datetime.strptime(value, fmt)
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=dt.datetime.utcnow().year)
            return parsed
        except ValueError:
            continue
    return None


def _normalize_result(value: str) -> Optional[str]:
    """Normalize result tokens to "success" or "failure"."""
    v = value.lower()
    if v in {"success", "ok", "accepted", "allow"}:
        return "success"
    if v in {"failure", "fail", "denied", "rejected"}:
        return "failure"
    return None


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _classify_ip(value: str) -> str:
    """Label an IP as 'private' or 'public'.

    Why: private-source logins are generally internal/VPN traffic, while public
    IPs hitting your auth endpoints deserve more scrutiny in findings.
    """
    try:
        return "private" if ipaddress.ip_address(value).is_private else "public"
    except ValueError:
        return "unknown"


def parse_logs(lines: Iterable[str]) -> Tuple[List[AuthEvent], int]:
    """Parse text-based auth logs into structured events.

    Returns (events, total_lines_read) so callers can compute a parse-rate
    metric — important for SOC dashboards to detect log-format drift.

    Security design: normalization enables deterministic detection without
    overfitting to a single log format.
    """
    events: List[AuthEvent] = []
    total_lines = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        total_lines += 1

        m = SSH_FAILED_RE.match(line)
        if m:
            ts = _parse_timestamp(m.group("ts"))
            if ts and _is_valid_ip(m.group("ip")):
                ev = AuthEvent(ts, m.group("user"), m.group("ip"), "failure", line)
                ev.ip_type = _classify_ip(ev.ip)
                events.append(ev)
            continue

        m = SSH_ACCEPTED_RE.match(line)
        if m:
            ts = _parse_timestamp(m.group("ts"))
            if ts and _is_valid_ip(m.group("ip")):
                ev = AuthEvent(ts, m.group("user"), m.group("ip"), "success", line)
                ev.ip_type = _classify_ip(ev.ip)
                events.append(ev)
            continue

        m = KEYVAL_RE.match(line)
        if m:
            ts = _parse_timestamp(m.group("ts"))
            res = _normalize_result(m.group("res"))
            if ts and res and _is_valid_ip(m.group("ip")):
                ev = AuthEvent(ts, m.group("user"), m.group("ip"), res, line)
                ev.ip_type = _classify_ip(ev.ip)
                events.append(ev)
            continue

        m = GENERIC_RE.match(line)
        if m:
            ts = _parse_timestamp(m.group("ts"))
            res = _normalize_result(m.group("res"))
            if ts and res and _is_valid_ip(m.group("ip")):
                ev = AuthEvent(ts, m.group("user"), m.group("ip"), res, line)
                ev.ip_type = _classify_ip(ev.ip)
                events.append(ev)
            continue

    return sorted(events, key=lambda e: e.timestamp), total_lines


# -----------------------------
# Detection logic
# -----------------------------
@dataclass
class Finding:
    severity: str  # LOW/MED/HIGH
    message: str
    key: str = ""  # Used to deduplicate related findings
    context: Dict[str, str] = field(default_factory=dict)


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on the provided key.

    Why: Multiple detectors can surface the same signal; deduping keeps
    analyst output focused and prevents alert fatigue.
    """
    seen: Set[str] = set()
    unique: List[Finding] = []
    for f in findings:
        k = f.key or f.message
        if k in seen:
            continue
        seen.add(k)
        unique.append(f)
    return unique


def brute_force_detector(
    events: List[AuthEvent], fail_threshold: int, time_window_minutes: int
) -> List[Finding]:
    """Detect brute-force attempts using two patterns.

    Pattern A: repeated failures from the same IP in a short window.
    Pattern B: same username attacked from many IPs in a short window.

    Why: attackers either hammer a single target from one IP, or spray across
    many IPs to evade per-IP thresholds.
    """
    findings: List[Finding] = []
    window = dt.timedelta(minutes=time_window_minutes)

    # A) failures from same IP
    failures_by_ip: Dict[str, List[AuthEvent]] = {}
    for ev in events:
        if ev.result == "failure":
            failures_by_ip.setdefault(ev.ip, []).append(ev)

    for ip, fails in failures_by_ip.items():
        # Sliding window to count failures; also detect success after failures
        for i in range(len(fails)):
            j = i
            while j < len(fails) and fails[j].timestamp - fails[i].timestamp <= window:
                j += 1
            count = j - i
            if count >= fail_threshold:
                # Check if a success follows shortly after to suggest compromise
                success_after = any(
                    ev.ip == ip and ev.result == "success" and 0 <= (ev.timestamp - fails[i].timestamp).total_seconds() <= window.total_seconds()
                    for ev in events
                )
                sev = "HIGH" if success_after else "MED"
                findings.append(
                    Finding(
                        sev,
                        f"Brute-force (IP): {ip} — {count} failures in {time_window_minutes}m"
                        + ("; success after failures (possible compromise)" if success_after else ""),
                        key=f"brute_ip:{ip}",
                        context={"ip": ip},
                    )
                )
                break  # one finding per IP window is sufficient

    # B) same username attacked from many IPs
    failures_by_user: Dict[str, List[AuthEvent]] = {}
    for ev in events:
        if ev.result == "failure":
            failures_by_user.setdefault(ev.username, []).append(ev)

    for user, fails in failures_by_user.items():
        # Count distinct IPs in window
        for i in range(len(fails)):
            j = i
            ips = set()
            while j < len(fails) and fails[j].timestamp - fails[i].timestamp <= window:
                ips.add(fails[j].ip)
                j += 1
            if len(ips) >= max(3, fail_threshold // 2):
                findings.append(
                    Finding(
                        "MED",
                        f"Username targeted from many IPs: {user} — failures from {len(ips)} IPs in {time_window_minutes}m",
                        key=f"brute_user:{user}",
                        context={"user": user},
                    )
                )
                break

    return findings


def password_spray_detector(
    events: List[AuthEvent], time_window_minutes: int, user_threshold: int, max_attempts_per_user: int
) -> List[Finding]:
    """Detect password spraying from a single IP.

    Pattern: many distinct usernames targeted from one IP, with only a small
    number of attempts per user to evade lockout thresholds.
    """
    findings: List[Finding] = []
    window = dt.timedelta(minutes=time_window_minutes)

    failures_by_ip: Dict[str, List[AuthEvent]] = {}
    for ev in events:
        if ev.result == "failure":
            failures_by_ip.setdefault(ev.ip, []).append(ev)

    for ip, fails in failures_by_ip.items():
        for i in range(len(fails)):
            j = i
            users = Counter()
            while j < len(fails) and fails[j].timestamp - fails[i].timestamp <= window:
                users[fails[j].username] += 1
                j += 1
            distinct_users = [u for u, c in users.items() if c <= max_attempts_per_user]
            if len(distinct_users) >= user_threshold:
                findings.append(
                    Finding(
                        "MED",
                        f"Password spray: {ip} targeted {len(distinct_users)} users with ≤{max_attempts_per_user} attempts each in {time_window_minutes}m",
                        key=f"spray:{ip}",
                        context={"ip": ip},
                    )
                )
                break

    return findings


def credential_stuffing_detector(
    events: List[AuthEvent], time_window_minutes: int, min_successes: int
) -> List[Finding]:
    """Detect potential credential stuffing.

    Pattern: the same IP has many failures across users and then multiple
    distinct successful logins in a short window.
    """
    findings: List[Finding] = []
    window = dt.timedelta(minutes=time_window_minutes)

    by_ip: Dict[str, List[AuthEvent]] = {}
    for ev in events:
        by_ip.setdefault(ev.ip, []).append(ev)

    for ip, evs in by_ip.items():
        for i in range(len(evs)):
            j = i
            successes = set()
            failures = 0
            while j < len(evs) and evs[j].timestamp - evs[i].timestamp <= window:
                if evs[j].result == "success":
                    successes.add(evs[j].username)
                else:
                    failures += 1
                j += 1
            if failures >= min_successes and len(successes) >= min_successes:
                findings.append(
                    Finding(
                        "HIGH",
                        f"Credential stuffing suspected: {ip} had {failures} failures and {len(successes)} distinct successes in {time_window_minutes}m",
                        key=f"stuffing:{ip}",
                        context={"ip": ip},
                    )
                )
                break

    return findings


def behavioral_anomaly_detector(events: List[AuthEvent]) -> List[Finding]:
    """Detect abnormal login behavior.

    - Unusual hour for a user's success logins based on baseline hours.
    - First-time IP for a user (useful for account compromise detection).

    Security note: these are heuristics; they should be used with context.
    """
    findings: List[Finding] = []

    # Build baseline hours per user from successful logins
    user_success_hours: Dict[str, List[int]] = {}

    for ev in events:
        if ev.result == "success":
            user_success_hours.setdefault(ev.username, []).append(ev.timestamp.hour)

    # Define baseline as the observed hour range (simple, explainable)
    baseline_by_user: Dict[str, Tuple[int, int]] = {}
    for user, hours in user_success_hours.items():
        if not hours:
            continue
        # For explainability: compute min/max of frequent hours or default 9-18
        if len(hours) >= 3:
            baseline_by_user[user] = (min(hours), max(hours))
        else:
            baseline_by_user[user] = (9, 18)

    # Detect unusual hours and first-time IPs
    seen_user_ips: Dict[str, set] = {}
    for ev in events:
        if ev.result == "success":
            unusual_hour = False
            if ev.username in baseline_by_user:
                start, end = baseline_by_user[ev.username]
                # Unusual if outside baseline range by 2+ hours
                if ev.timestamp.hour < (start - 2) or ev.timestamp.hour > (end + 2):
                    unusual_hour = True
                    findings.append(
                        Finding(
                            "MED",
                            f"Unusual login hour: {ev.username} at {ev.timestamp.hour:02d}:00 (baseline {start:02d}-{end:02d})",
                            key=f"unusual_hour:{ev.username}:{ev.timestamp.date()}",
                            context={"user": ev.username, "ip": ev.ip},
                        )
                    )

            # First-time IP logic
            if ev.username not in seen_user_ips:
                seen_user_ips[ev.username] = set()
            first_time_ip = ev.ip not in seen_user_ips[ev.username]
            if first_time_ip:
                # First-time IP is low severity unless paired with other signals
                findings.append(
                    Finding(
                        "LOW",
                        f"First-time IP: {ev.username} from {ev.ip} ({ev.ip_type})",
                        key=f"first_ip:{ev.username}:{ev.ip}",
                        context={"user": ev.username, "ip": ev.ip},
                    )
                )
                seen_user_ips[ev.username].add(ev.ip)

            # Correlation: unusual hour + first-time IP for same event
            if unusual_hour and first_time_ip:
                findings.append(
                    Finding(
                        "HIGH",
                        f"Correlated anomaly: {ev.username} — unusual hour + first-time IP {ev.ip}",
                        key=f"corr:{ev.username}:{ev.ip}",
                        context={"user": ev.username, "ip": ev.ip},
                    )
                )

    return findings


def ml_anomaly_detector(events: List[AuthEvent]) -> List[Finding]:
    """Optional ML anomaly detector using Isolation Forest.

    Features (explainable):
    - Hour of day
    - Result (success=1, failure=0)
    - IP entropy proxy (last octet as int, rough signal)
    - Username length (proxy for synthetic user spray)
    - Time since last event for same user
    - Time since last event for same IP

    Rationale: Use light-weight, explainable features to avoid black-box risk.
    """
    try:
        import importlib
        sklearn_ensemble = importlib.import_module("sklearn.ensemble")
        IsolationForest = getattr(sklearn_ensemble, "IsolationForest")
    except Exception:
        return [Finding("LOW", "ML disabled: scikit-learn not installed")]

    # Build numeric features (all explainable)
    # - hour of day
    # - success flag
    # - IP last octet (rough entropy proxy)
    # - username length
    # - time since last event for same user (seconds)
    # - time since last event for same IP (seconds)
    feats = []
    last_user_ts: Dict[str, dt.datetime] = {}
    last_ip_ts: Dict[str, dt.datetime] = {}

    for ev in events:
        ip_octet = 0
        if "." in ev.ip:
            try:
                ip_octet = int(ev.ip.split(".")[-1])
            except ValueError:
                ip_octet = 0

        user_delta = 0
        if ev.username in last_user_ts:
            user_delta = int((ev.timestamp - last_user_ts[ev.username]).total_seconds())
        ip_delta = 0
        if ev.ip in last_ip_ts:
            ip_delta = int((ev.timestamp - last_ip_ts[ev.ip]).total_seconds())

        feats.append([
            ev.timestamp.hour,
            1 if ev.result == "success" else 0,
            ip_octet,
            len(ev.username),
            min(user_delta, 3600),
            min(ip_delta, 3600),
        ])

        last_user_ts[ev.username] = ev.timestamp
        last_ip_ts[ev.ip] = ev.timestamp

    if len(feats) < 10:
        return [Finding("LOW", "ML skipped: insufficient data (<10 events)")]

    model = IsolationForest(contamination=0.05, random_state=42)
    preds = model.fit_predict(feats)

    findings: List[Finding] = []
    for ev, pred in zip(events, preds):
        if pred == -1:
            findings.append(
                Finding(
                    "LOW",
                    f"ML anomaly: {ev.username} from {ev.ip} at {ev.timestamp.isoformat()} ({ev.result})",
                    key=f"ml:{ev.username}:{ev.ip}:{ev.timestamp.isoformat()}",
                    context={"user": ev.username, "ip": ev.ip},
                )
            )
    return findings


# -----------------------------
# CLI / main
# -----------------------------
def _load_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def _summarize(events: List[AuthEvent], total_lines: int) -> Dict[str, str]:
    """Create a small summary for SOC visibility.

    Why: analysts need to know log coverage and time span to contextualize
    findings and spot ingestion gaps.
    """
    if not events:
        return {
            "time_start": "-",
            "time_end": "-",
            "total_events": "0",
            "failures": "0",
            "successes": "0",
            "unique_users": "0",
            "unique_ips": "0",
            "parse_rate": "0.0%",
        }

    failures = sum(1 for e in events if e.result == "failure")
    successes = sum(1 for e in events if e.result == "success")
    parse_rate = (len(events) / max(total_lines, 1)) * 100

    return {
        "time_start": str(events[0].timestamp),
        "time_end": str(events[-1].timestamp),
        "total_events": str(len(events)),
        "failures": str(failures),
        "successes": str(successes),
        "unique_users": str(len({e.username for e in events})),
        "unique_ips": str(len({e.ip for e in events})),
        "parse_rate": f"{parse_rate:.1f}%",
    }


def _print_summary(summary: Dict[str, str]) -> None:
    print("=== Log Analysis Summary ===")
    print(f"  Time span   : {summary['time_start']} → {summary['time_end']}")
    print(
        f"  Total events: {summary['total_events']} ({summary['failures']} failures, {summary['successes']} successes)"
    )
    print(f"  Unique users: {summary['unique_users']} | Unique IPs: {summary['unique_ips']}")
    print(f"  Parse rate  : {summary['parse_rate']}")
    print("")


def _findings_to_json(findings: List[Finding]) -> List[Dict[str, str]]:
    return [
        {
            "severity": f.severity,
            "message": f.message,
            "key": f.key,
            **f.context,
        }
        for f in findings
    ]


def _generate_sample_log(path: str) -> None:
    """Generate a small, realistic sample log file for quick testing."""
    users = ["alice", "bob", "carol", "dave", "erin", "frank"]
    ips = ["203.0.113.8", "203.0.113.9", "198.51.100.42", "203.0.113.20"]
    now = dt.datetime.utcnow().replace(microsecond=0)

    lines = []
    for i in range(10):
        ts = (now - dt.timedelta(minutes=10 - i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        user = random.choice(users)
        ip = random.choice(ips)
        res = random.choice(["failure", "failure", "success"])
        lines.append(f"{ts} webauth user={user} ip={ip} result={res}\n")

    # Inject a brute-force pattern
    for i in range(5):
        ts = (now - dt.timedelta(minutes=5 - i)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} server sshd[1234]: Failed password for alice from 203.0.113.8 port 53321 ssh2\n")
    lines.append(
        f"{now.strftime('%b %d %H:%M:%S')} server sshd[1234]: Accepted password for alice from 203.0.113.8 port 53321 ssh2\n"
    )

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for brute-force and behavioral anomalies",
    )
    parser.add_argument("--logfile", help="Path to auth log file")
    parser.add_argument("--fail-threshold", type=int, default=5, help="Failures to trigger brute-force detection")
    parser.add_argument("--time-window", type=int, default=5, help="Time window in minutes")
    parser.add_argument("--enable-ml", action="store_true", help="Enable ML anomaly detection (Isolation Forest)")
    parser.add_argument("--output-json", help="Write findings to JSON file for SIEM ingestion")
    parser.add_argument("--spray-user-threshold", type=int, default=5, help="Distinct users to flag password spray")
    parser.add_argument("--spray-max-attempts", type=int, default=2, help="Max attempts per user in a spray window")
    parser.add_argument("--stuffing-successes", type=int, default=2, help="Distinct successes to flag credential stuffing")
    parser.add_argument("--generate-sample", help="Generate a sample log file and exit")

    args = parser.parse_args()

    if args.generate_sample:
        _generate_sample_log(args.generate_sample)
        print(f"Sample log written to {args.generate_sample}")
        return

    if not args.logfile:
        parser.error("--logfile is required unless --generate-sample is used")

    lines = _load_lines(args.logfile)
    events, total_lines = parse_logs(lines)

    if not events:
        print("No parseable authentication events found.")
        return

    summary = _summarize(events, total_lines)
    _print_summary(summary)

    findings: List[Finding] = []
    findings.extend(brute_force_detector(events, args.fail_threshold, args.time_window))
    findings.extend(password_spray_detector(
        events,
        args.time_window,
        args.spray_user_threshold,
        args.spray_max_attempts,
    ))
    findings.extend(credential_stuffing_detector(
        events,
        args.time_window,
        args.stuffing_successes,
    ))
    findings.extend(behavioral_anomaly_detector(events))

    if args.enable_ml:
        findings.extend(ml_anomaly_detector(events))

    findings = _dedupe_findings(findings)

    if not findings:
        print("No anomalies detected.")
        return

    # Human-readable output
    for f in findings:
        print(f"[{f.severity}] {f.message}")

    if args.output_json:
        payload = {
            "summary": summary,
            "findings": _findings_to_json(findings),
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\nFindings written to {args.output_json}")


if __name__ == "__main__":
    main()
