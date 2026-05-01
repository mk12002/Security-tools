"""
Security Headers Hardening Checker
======================================================
A comprehensive checker that inspects 10+ HTTP security headers, validates
their values for weaknesses, assigns severity ratings, computes an overall
grade, and provides OWASP-mapped remediation with secure defaults.

Why this matters (AppSec interview-ready):
  Security headers are the cheapest defense layer. A single missing header
  can enable XSS (no CSP), clickjacking (no X-Frame-Options), MIME sniffing
  attacks (no X-Content-Type-Options), or cross-origin data leaks (no COOP/CORP).

Usage:
  python headers_hardening_checker.py --url https://example.com
  python headers_hardening_checker.py --url https://example.com --output-json report.json
  python headers_hardening_checker.py --url https://example.com --cookie "sess=abc"

Sample output (abridged):
  === Security Headers Hardening Checker ===
  Target: https://example.com
  Grade : C (55/100)

  [HIGH] Content-Security-Policy — MISSING
    Why: Mitigates XSS by restricting script/style sources
    Default: default-src 'self'; script-src 'self'; object-src 'none'

  [MED] Strict-Transport-Security — WEAK
    Value: max-age=3600
    Issue: max-age too short (<1 year); preload missing
    Default: max-age=31536000; includeSubDomains; preload

  [PASS] X-Content-Type-Options: nosniff ✓

Limitations:
  - Checks a single URL; headers may vary per path or content type.
  - CSP quality analysis is surface-level; real CSP auditing needs csp-evaluator.
  - Some headers are deprecated (X-XSS-Protection) but noted for legacy awareness.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class HeaderCheck:
    name: str
    display_name: str
    present: bool
    value: str
    severity: str           # HIGH / MED / LOW / PASS / INFO
    status: str             # MISSING / WEAK / PASS / DEPRECATED
    issue: str
    why: str
    owasp_ref: str
    secure_default: str
    points: int             # 0-10 contribution to grade


# ---------------------------------------------------------------------------
# Header definitions — 10 security headers
# ---------------------------------------------------------------------------
# Why 10: covers OWASP Secure Headers Project recommendations plus modern
# cross-origin isolation headers that are increasingly required.

HEADER_SPECS = [
    {
        "name": "content-security-policy",
        "display": "Content-Security-Policy",
        "why": "Mitigates XSS by restricting which sources can load scripts, styles, images, etc.",
        "owasp": "OWASP ASVS V14.4.1 — CSP",
        "default": "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        "weight": 15,
        "weak_check": "_check_csp",
    },
    {
        "name": "strict-transport-security",
        "display": "Strict-Transport-Security",
        "why": "Forces HTTPS; prevents SSL stripping and downgrade attacks.",
        "owasp": "OWASP ASVS V9.1.1 — HSTS",
        "default": "max-age=31536000; includeSubDomains; preload",
        "weight": 15,
        "weak_check": "_check_hsts",
    },
    {
        "name": "x-content-type-options",
        "display": "X-Content-Type-Options",
        "why": "Prevents MIME sniffing; stops browsers from interpreting files as different types.",
        "owasp": "OWASP ASVS V14.4.2 — MIME Sniffing",
        "default": "nosniff",
        "weight": 10,
        "weak_check": "_check_xcto",
    },
    {
        "name": "x-frame-options",
        "display": "X-Frame-Options",
        "why": "Prevents clickjacking by controlling iframe embedding.",
        "owasp": "OWASP ASVS V14.4.3 — Clickjacking",
        "default": "DENY",
        "weight": 10,
        "weak_check": "_check_xfo",
    },
    {
        "name": "referrer-policy",
        "display": "Referrer-Policy",
        "why": "Controls referrer leakage; prevents URLs with tokens from leaking to third parties.",
        "owasp": "OWASP ASVS V13.2 — Referrer Policy",
        "default": "strict-origin-when-cross-origin",
        "weight": 8,
        "weak_check": "_check_referrer",
    },
    {
        "name": "permissions-policy",
        "display": "Permissions-Policy",
        "why": "Restricts powerful browser APIs (camera, mic, geolocation) to reduce attack surface.",
        "owasp": "OWASP ASVS V14.4 — Feature Policy",
        "default": "geolocation=(), microphone=(), camera=(), payment=()",
        "weight": 8,
        "weak_check": None,
    },
    {
        "name": "cross-origin-opener-policy",
        "display": "Cross-Origin-Opener-Policy",
        "why": "Isolates browsing context; prevents Spectre-like cross-origin attacks.",
        "owasp": "OWASP — Cross-Origin Isolation",
        "default": "same-origin",
        "weight": 8,
        "weak_check": None,
    },
    {
        "name": "cross-origin-resource-policy",
        "display": "Cross-Origin-Resource-Policy",
        "why": "Prevents other origins from loading your resources (images, scripts).",
        "owasp": "OWASP — Cross-Origin Isolation",
        "default": "same-origin",
        "weight": 8,
        "weak_check": None,
    },
    {
        "name": "cross-origin-embedder-policy",
        "display": "Cross-Origin-Embedder-Policy",
        "why": "Requires resources to explicitly grant permission to be loaded cross-origin.",
        "owasp": "OWASP — Cross-Origin Isolation",
        "default": "require-corp",
        "weight": 8,
        "weak_check": None,
    },
    {
        "name": "x-xss-protection",
        "display": "X-XSS-Protection",
        "why": "Legacy XSS filter (deprecated in modern browsers but shows security awareness).",
        "owasp": "OWASP — Legacy Header",
        "default": "0  (disable; rely on CSP instead)",
        "weight": 5,
        "weak_check": "_check_xxss",
    },
]

# Dangerous headers that should NOT be present
DANGEROUS_HEADERS = {
    "server": "Leaks server software/version — aids attacker reconnaissance",
    "x-powered-by": "Leaks framework/language — aids targeted exploit selection",
    "x-aspnet-version": "Leaks ASP.NET version — aids targeted attacks",
}


# ---------------------------------------------------------------------------
# Weak-value validators
# ---------------------------------------------------------------------------

def _check_csp(value: str) -> Optional[str]:
    """
    Surface-level CSP weakness detection.
    Why: CSP with 'unsafe-inline' or 'unsafe-eval' defeats its purpose.
    """
    issues = []
    val_lower = value.lower()
    if "'unsafe-inline'" in val_lower:
        issues.append("'unsafe-inline' allows inline scripts (XSS risk)")
    if "'unsafe-eval'" in val_lower:
        issues.append("'unsafe-eval' allows eval() (code injection risk)")
    if "data:" in val_lower and "script-src" in val_lower:
        issues.append("data: in script-src allows data: URI script injection")
    if "*" in value and "default-src" in val_lower:
        issues.append("Wildcard (*) in default-src is overly permissive")
    return "; ".join(issues) if issues else None


def _check_hsts(value: str) -> Optional[str]:
    """Check HSTS for short max-age or missing directives."""
    issues = []
    m = re.search(r"max-age=(\d+)", value, re.I)
    if m:
        age = int(m.group(1))
        if age < 31536000:  # less than 1 year
            issues.append(f"max-age={age} is too short (recommend ≥31536000)")
    else:
        issues.append("max-age directive missing")
    if "includesubdomains" not in value.lower():
        issues.append("includeSubDomains missing — subdomains not protected")
    return "; ".join(issues) if issues else None


def _check_xcto(value: str) -> Optional[str]:
    if value.strip().lower() != "nosniff":
        return f"Value should be 'nosniff', got '{value.strip()}'"
    return None


def _check_xfo(value: str) -> Optional[str]:
    v = value.strip().upper()
    if v not in ("DENY", "SAMEORIGIN") and not v.startswith("ALLOW-FROM"):
        return f"Invalid value '{value.strip()}'; use DENY or SAMEORIGIN"
    return None


def _check_referrer(value: str) -> Optional[str]:
    weak_values = {"unsafe-url", "no-referrer-when-downgrade", "origin"}
    if value.strip().lower() in weak_values:
        return f"'{value.strip()}' leaks path or origin info; prefer strict-origin-when-cross-origin"
    return None


def _check_xxss(value: str) -> Optional[str]:
    """X-XSS-Protection is deprecated; '0' is the only safe value now."""
    v = value.strip()
    if v.startswith("1"):
        return "Value '1' enables buggy XSS auditor (can be exploited); set to '0' and rely on CSP"
    return None


VALIDATORS = {
    "_check_csp": _check_csp,
    "_check_hsts": _check_hsts,
    "_check_xcto": _check_xcto,
    "_check_xfo": _check_xfo,
    "_check_referrer": _check_referrer,
    "_check_xxss": _check_xxss,
}


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def fetch_headers(url: str, insecure: bool = False, cookie: str = "") -> Dict[str, str]:
    """Fetch response headers from the target URL."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "Mozilla/5.0 (HeadersChecker/2.0)")
    if cookie:
        req.add_header("Cookie", cookie)

    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return {k.lower(): v for k, v in e.headers.items()}


def analyze(headers: Dict[str, str]) -> List[HeaderCheck]:
    """
    Analyze each security header for presence and value quality.
    Why two-phase: missing is obvious, but *weak* values are equally dangerous.
    """
    results: List[HeaderCheck] = []

    for spec in HEADER_SPECS:
        name = spec["name"]
        value = headers.get(name, "")
        present = bool(value)

        if not present:
            results.append(HeaderCheck(
                name=name,
                display_name=spec["display"],
                present=False,
                value="",
                severity="HIGH" if spec["weight"] >= 10 else "MED",
                status="MISSING",
                issue="Header not set",
                why=spec["why"],
                owasp_ref=spec["owasp"],
                secure_default=spec["default"],
                points=0,
            ))
            continue

        # Present — check for weak values
        issue = ""
        weak_check = spec.get("weak_check")
        if weak_check and weak_check in VALIDATORS:
            issue = VALIDATORS[weak_check](value) or ""

        if issue:
            results.append(HeaderCheck(
                name=name, display_name=spec["display"], present=True,
                value=value, severity="MED", status="WEAK",
                issue=issue, why=spec["why"], owasp_ref=spec["owasp"],
                secure_default=spec["default"],
                points=spec["weight"] // 2,  # half credit for weak
            ))
        else:
            results.append(HeaderCheck(
                name=name, display_name=spec["display"], present=True,
                value=value, severity="PASS", status="PASS",
                issue="", why=spec["why"], owasp_ref=spec["owasp"],
                secure_default=spec["default"],
                points=spec["weight"],
            ))

    return results


def check_dangerous(headers: Dict[str, str]) -> List[HeaderCheck]:
    """Check for headers that leak information and should be removed."""
    results: List[HeaderCheck] = []
    for name, why in DANGEROUS_HEADERS.items():
        if name in headers:
            results.append(HeaderCheck(
                name=name, display_name=name.title(), present=True,
                value=headers[name], severity="LOW", status="REMOVE",
                issue=why, why="Information disclosure aids attacker reconnaissance.",
                owasp_ref="OWASP ASVS V14.3 — Information Leakage",
                secure_default="(remove this header)",
                points=0,
            ))
    return results


def compute_grade(results: List[HeaderCheck]) -> tuple:
    """
    Compute a letter grade A-F based on points earned vs max possible.
    Why: gives a quick summary for reports and executive communication.
    """
    max_points = sum(s["weight"] for s in HEADER_SPECS)
    earned = sum(r.points for r in results if r.status in ("PASS", "WEAK"))
    pct = (earned / max_points) * 100 if max_points else 0

    if pct >= 90:
        grade = "A"
    elif pct >= 75:
        grade = "B"
    elif pct >= 55:
        grade = "C"
    elif pct >= 35:
        grade = "D"
    else:
        grade = "F"

    return grade, int(pct)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(url: str, results: List[HeaderCheck], dangerous: List[HeaderCheck],
                 grade: str, score: int) -> None:
    print("=== Security Headers Hardening Checker ===")
    print(f"Target: {url}")
    print(f"Grade : {grade} ({score}/100)\n")

    # Group by status
    for r in results:
        if r.status == "MISSING":
            print(f"[{r.severity}] {r.display_name} — MISSING")
            print(f"  Why    : {r.why}")
            print(f"  Default: {r.secure_default}")
            print(f"  OWASP  : {r.owasp_ref}")
        elif r.status == "WEAK":
            print(f"[{r.severity}] {r.display_name} — WEAK")
            print(f"  Value  : {r.value}")
            print(f"  Issue  : {r.issue}")
            print(f"  Default: {r.secure_default}")
        else:
            print(f"[PASS] {r.display_name}: {r.value[:60]} ✓")
        print()

    if dangerous:
        print("Information leakage (should remove):")
        for d in dangerous:
            print(f"  [LOW] {d.name}: {d.value}")
            print(f"    Issue: {d.issue}")
        print()

    # Educational footer
    print("=" * 55)
    print("Security headers explained (interview-ready):")
    print()
    print("  CSP: The most impactful header — prevents XSS even if input validation fails.")
    print("  HSTS: Once set, browser refuses HTTP for that domain (protects from MITM).")
    print("  X-Content-Type-Options: nosniff prevents browser from guessing MIME types.")
    print("  COOP/CORP/COEP: Modern cross-origin isolation; required for SharedArrayBuffer.")
    print("  X-XSS-Protection: DEPRECATED — disable it (set to 0) and rely on CSP instead.")
    print()
    print("  Implementation tips:")
    print("    - Add headers at reverse-proxy level (nginx/Cloudflare) for consistency")
    print("    - CSP: start with report-only mode to avoid breaking functionality")
    print("    - HSTS: start with short max-age, increase after confirming HTTPS works")
    print()
    print("  Limitations:")
    print("    - Headers may differ per path, content-type, or authenticated state")
    print("    - CSP effectiveness depends on application-specific sources")
    print("    - This tool doesn't test header injection vulnerabilities")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Security headers hardening checker with grading and weak-value analysis",
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--cookie", default="", help="Cookie header for authenticated checks")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--output-json", help="Write JSON report to file")

    args = parser.parse_args()

    headers = fetch_headers(args.url, args.insecure, args.cookie)
    results = analyze(headers)
    dangerous = check_dangerous(headers)
    grade, score = compute_grade(results)

    print_report(args.url, results, dangerous, grade, score)

    if args.output_json:
        report = {
            "url": args.url,
            "grade": grade,
            "score": score,
            "headers": [asdict(r) for r in results],
            "dangerous": [asdict(d) for d in dangerous],
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.output_json}")


if __name__ == "__main__":
    main()
