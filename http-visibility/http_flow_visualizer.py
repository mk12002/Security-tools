"""
TOOL 7 — HTTP Request Flow Visualizer (Upgraded)
=================================================
A comprehensive HTTP flow analysis tool that visualizes redirect chains,
tracks cookie lifecycle, detects security issues in the flow, and provides
a JSON report.

Why this matters (interview-ready):
  Auth flows, OAuth callbacks, and SSO handshakes are multi-hop HTTP chains.
  Understanding which cookies are set/dropped at each hop, whether HTTPS is
  enforced, and if open redirects exist requires step-by-step visibility.

Usage:
  python http_flow_visualizer.py --url http://example.com --follow
  python http_flow_visualizer.py --url https://target/login --follow --cookie "sess=abc"
  python http_flow_visualizer.py --url https://target/oauth/callback --follow --output-json flow.json
  python http_flow_visualizer.py --generate-sample

Sample output (abridged):
  === HTTP Flow Visualizer ===
  Hops: 3

  [1] REQUEST  GET http://example.com
  [1] RESPONSE 301 → https://example.com/
      Set-Cookie: tracking=xyz

  [2] REQUEST  GET https://example.com/
      Cookie: tracking=xyz
  [2] RESPONSE 302 → https://example.com/home
      Set-Cookie: session=abc123; Secure; HttpOnly

  [3] REQUEST  GET https://example.com/home
      Cookie: tracking=xyz; session=abc123
  [3] RESPONSE 200 OK

  Security Findings:
    [MED] HTTP → HTTPS redirect: initial request was plain HTTP (MITM window)
    [LOW] Long redirect chain (3 hops): may indicate misconfiguration

Limitations:
  - Does not capture TCP/TLS handshake details.
  - JavaScript-based redirects are invisible (no JS engine).
  - Cookie parsing via SimpleCookie may miss edge cases.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict, field
from http.cookies import SimpleCookie
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Hop:
    index: int
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_cookies: Dict[str, str]
    response_status: int
    response_reason: str
    response_headers: Dict[str, str]
    response_cookies: Dict[str, str]
    cookie_changes: List[str]


@dataclass
class FlowFinding:
    severity: str       # HIGH / MED / LOW
    issue: str
    hop: int
    evidence: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_AUTH_HEADERS = {"authorization", "proxy-authorization", "www-authenticate"}

COLORS = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "cyan": "\033[36m", "bold": "\033[1m",
    "reset": "\033[0m",
}


def _c(text: str, color: str, enable: bool) -> str:
    if not enable:
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def _parse_set_cookies(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Parse Set-Cookie from response headers.
    Why SimpleCookie: handles quoted values and attributes safely.
    """
    jar: Dict[str, str] = {}
    raw = headers.get("Set-Cookie", headers.get("set-cookie", ""))
    if not raw:
        return jar
    # SimpleCookie can parse multiple cookies from combined header
    sc = SimpleCookie()
    try:
        sc.load(raw)
    except Exception:
        # Fallback: split on comma but avoid splitting Expires dates
        for part in raw.split(", "):
            if "=" in part:
                k, _, v = part.partition("=")
                jar[k.strip()] = v.split(";")[0].strip()
        return jar
    for name, morsel in sc.items():
        jar[name] = morsel.value
    return jar


def _cookie_header(jar: Dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in jar.items())


# ---------------------------------------------------------------------------
# Custom redirect handler that does NOT auto-follow
# ---------------------------------------------------------------------------

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent auto-redirect so we can capture each hop manually.
    Why: default urllib follows redirects silently, losing intermediate headers."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Don't follow


# ---------------------------------------------------------------------------
# Core flow engine
# ---------------------------------------------------------------------------

def trace_flow(
    url: str,
    follow: bool,
    cookie: str,
    extra_headers: Dict[str, str],
    insecure: bool,
    max_hops: int = 10,
) -> List[Hop]:
    """
    Trace HTTP flow hop-by-hop, manually following redirects.
    Why manual: captures each intermediate response for analysis.
    """
    hops: List[Hop] = []
    current_url = url
    cookie_jar: Dict[str, str] = {}

    # Seed cookie jar from --cookie argument
    if cookie:
        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookie_jar[k.strip()] = v.strip()

    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=ctx),
    )

    previous_cookies: Dict[str, str] = dict(cookie_jar)

    for i in range(1, max_hops + 1):
        req = urllib.request.Request(current_url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 (HttpFlowVisualizer/2.0)")
        for k, v in extra_headers.items():
            req.add_header(k, v)

        # Attach cookies
        if cookie_jar:
            req.add_header("Cookie", _cookie_header(cookie_jar))

        try:
            resp = opener.open(req, timeout=10)
        except urllib.error.HTTPError as e:
            resp = e

        status = resp.code if hasattr(resp, "code") else resp.status
        reason = resp.reason if hasattr(resp, "reason") else ""
        resp_headers = {k: v for k, v in resp.headers.items()}

        # Parse cookies from response
        response_cookies = _parse_set_cookies(resp_headers)
        cookie_jar.update(response_cookies)

        # Detect cookie changes
        changes: List[str] = []
        for k, v in response_cookies.items():
            if k not in previous_cookies:
                changes.append(f"+{k}={v[:20]}")
            elif previous_cookies[k] != v:
                changes.append(f"~{k} (changed)")
        # Detect removed cookies (Set-Cookie with Max-Age=0 or empty value)
        for k, v in response_cookies.items():
            if v == "" or v == "deleted":
                changes.append(f"-{k} (removed)")

        hop = Hop(
            index=i,
            request_method="GET",
            request_url=current_url,
            request_headers=dict(req.header_items()),
            request_cookies=dict(previous_cookies) if previous_cookies else {},
            response_status=status,
            response_reason=reason,
            response_headers=resp_headers,
            response_cookies=response_cookies,
            cookie_changes=changes,
        )
        hops.append(hop)
        previous_cookies = dict(cookie_jar)

        # Follow redirect?
        location = resp_headers.get("Location", resp_headers.get("location", ""))
        if follow and status in (301, 302, 303, 307, 308) and location:
            current_url = urllib.parse.urljoin(current_url, location)
            continue
        break

    return hops


# ---------------------------------------------------------------------------
# Security analysis of the flow
# ---------------------------------------------------------------------------

def analyze_flow(hops: List[Hop]) -> List[FlowFinding]:
    """
    Detect security issues in the HTTP flow.
    Why: redirect chains can expose open redirects, protocol downgrades, and
    cookie stripping across domain boundaries.
    """
    findings: List[FlowFinding] = []

    for hop in hops:
        url = hop.request_url
        status = hop.response_status
        resp_headers = hop.response_headers

        # HTTP → HTTPS redirect (first hop insecure = MITM window)
        if hop.index == 1 and url.startswith("http://") and status in (301, 302, 307, 308):
            location = resp_headers.get("Location", "")
            if location.startswith("https://"):
                findings.append(FlowFinding(
                    severity="MED",
                    issue="HTTP → HTTPS redirect",
                    hop=hop.index,
                    evidence="Initial request was plain HTTP; attacker can intercept before redirect",
                ))

        # HTTPS → HTTP downgrade (dangerous)
        if url.startswith("https://") and status in (301, 302, 303, 307, 308):
            location = resp_headers.get("Location", "")
            if location.startswith("http://") and not location.startswith("https://"):
                findings.append(FlowFinding(
                    severity="HIGH",
                    issue="HTTPS → HTTP downgrade",
                    hop=hop.index,
                    evidence=f"Redirect from HTTPS to HTTP ({location[:60]}); cookies exposed to MITM",
                ))

        # Open redirect indicator: redirect to different domain
        if status in (301, 302, 303, 307, 308):
            location = resp_headers.get("Location", "")
            if location:
                src_host = urllib.parse.urlsplit(url).netloc
                dst_host = urllib.parse.urlsplit(urllib.parse.urljoin(url, location)).netloc
                if src_host and dst_host and src_host != dst_host:
                    findings.append(FlowFinding(
                        severity="LOW",
                        issue="Cross-domain redirect",
                        hop=hop.index,
                        evidence=f"{src_host} → {dst_host} (verify this is intentional)",
                    ))

        # Missing HSTS on HTTPS response
        if url.startswith("https://") and status == 200:
            if "strict-transport-security" not in {k.lower() for k in resp_headers}:
                findings.append(FlowFinding(
                    severity="LOW",
                    issue="Missing HSTS on final HTTPS response",
                    hop=hop.index,
                    evidence="No Strict-Transport-Security header; browser may allow HTTP fallback",
                ))

    # Long redirect chain
    if len(hops) >= 4:
        findings.append(FlowFinding(
            severity="LOW",
            issue="Long redirect chain",
            hop=len(hops),
            evidence=f"{len(hops)} hops — may indicate misconfiguration or redirect loop",
        ))

    return findings


# ---------------------------------------------------------------------------
# Sample generator
# ---------------------------------------------------------------------------

def generate_sample() -> str:
    """
    Print sample URLs to test with.
    Why: gives users immediate targets for testing the tool.
    """
    print("=== Sample URLs for testing HTTP Flow Visualizer ===\n")
    samples = [
        ("HTTP→HTTPS redirect", "http://github.com"),
        ("OAuth-style multi-hop", "http://google.com"),
        ("Simple 200", "https://example.com"),
    ]
    for desc, url in samples:
        print(f"  {desc}:")
        print(f"    python http_flow_visualizer.py --url {url} --follow\n")
    return ""


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_flow(hops: List[Hop], findings: List[FlowFinding], color: bool) -> None:
    print("=== HTTP Flow Visualizer ===")
    print(f"Hops: {len(hops)}\n")

    for hop in hops:
        # Request
        print(_c(f"[{hop.index}] REQUEST  {hop.request_method} {hop.request_url}", "blue", color))
        if hop.request_cookies:
            print(f"    Cookie: {_cookie_header(hop.request_cookies)[:80]}")

        # Response
        status_color = "green" if hop.response_status < 400 else "red"
        location = hop.response_headers.get("Location", "")
        redirect_info = f" → {location}" if location else ""
        print(_c(f"[{hop.index}] RESPONSE {hop.response_status} {hop.response_reason}{redirect_info}",
                 status_color, color))

        # Set-Cookie
        if hop.response_cookies:
            for k, v in hop.response_cookies.items():
                print(f"    Set-Cookie: {k}={v[:30]}{'...' if len(v) > 30 else ''}")

        # Cookie changes
        if hop.cookie_changes:
            for change in hop.cookie_changes:
                print(_c(f"    Cookie Δ: {change}", "yellow", color))

        # Auth headers
        for k, v in hop.request_headers.items():
            if k.lower() in _AUTH_HEADERS:
                print(_c(f"    Auth: {k}: {v[:40]}...", "cyan", color))

        print()

    # Security findings
    if findings:
        print("Security Findings:")
        for f in findings:
            print(f"  [{f.severity}] {f.issue} (hop {f.hop})")
            print(f"    {f.evidence}")
        print()

    # Educational section
    print("=" * 50)
    print("HTTP flow security concepts:")
    print("  - HTTPS upgrades: first request on HTTP is vulnerable to MITM (use HSTS preload)")
    print("  - Cookie scope: cookies set on one hop may not travel to different domains")
    print("  - Open redirects: cross-domain redirects can be abused for phishing/token theft")
    print("  - Session fixation: watch for session cookies set BEFORE login completes")
    print()
    print("Limitations:")
    print("  - No JavaScript-based redirect detection")
    print("  - Cookie parsing may miss complex Set-Cookie values")
    print("  - Cannot inspect encrypted TLS handshake details")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Visualize HTTP flows with redirect tracking, cookie lifecycle, and security analysis",
    )
    parser.add_argument("--url", help="Target URL to trace")
    parser.add_argument("--follow", action="store_true", help="Follow redirects (capture each hop)")
    parser.add_argument("--cookie", default="", help="Initial cookie header value")
    parser.add_argument("--header", action="append", default=[],
                        help="Extra header (repeatable): 'Name: Value'")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--color", action="store_true", help="Colorized terminal output")
    parser.add_argument("--output-json", help="Write JSON report to file")
    parser.add_argument("--generate-sample", action="store_true", help="Show sample test URLs")

    args = parser.parse_args()

    if args.generate_sample:
        generate_sample()
        return

    if not args.url:
        parser.error("--url is required (or use --generate-sample)")

    extra_headers: Dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    hops = trace_flow(args.url, args.follow, args.cookie, extra_headers, args.insecure)
    findings = analyze_flow(hops)

    print_flow(hops, findings, args.color)

    if args.output_json:
        report = {
            "url": args.url,
            "hops": [asdict(h) for h in hops],
            "findings": [asdict(f) for f in findings],
            "summary": {
                "total_hops": len(hops),
                "high": sum(1 for f in findings if f.severity == "HIGH"),
                "med": sum(1 for f in findings if f.severity == "MED"),
                "low": sum(1 for f in findings if f.severity == "LOW"),
            },
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.output_json}")


if __name__ == "__main__":
    main()
