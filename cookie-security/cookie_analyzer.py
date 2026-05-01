"""
TOOL 8 — Cookie Security Analyzer
==================================
A production-quality CLI tool that fetches HTTP responses and performs a
comprehensive security analysis of all Set-Cookie headers.

Why this matters (interview-ready):
  Cookies store session identifiers, preferences, and tokens. If they lack
  proper security attributes, multiple attack classes become possible:
  - Missing Secure   → session hijack via MITM on HTTP connections
  - Missing HttpOnly → XSS can read document.cookie and exfiltrate sessions
  - Missing SameSite → CSRF attacks can ride along with cross-origin requests
  - SameSite=None    → explicitly allows cross-site sending (same as missing)
  - Overly broad Domain → sibling subdomains can read/write the cookie
  - No Expires/Max-Age on session cookies → they persist beyond browser close
  - Missing __Host-/__Secure- prefix → no domain-locking guarantee

Usage examples:
  python cookie_security_analyzer.py --url https://example.com
  python cookie_security_analyzer.py --url https://example.com/login --output-json report.json

Sample output:
------------------------------------------------
=== Cookie Security Analyzer ===
  Target : https://example.com/login
  Cookies: 3

  Cookie: sessionid
    Value  : abc123... (truncated)
    Domain : .example.com
    Path   : /
    Expires: Session (no Max-Age/Expires)
    Flags  : HttpOnly
    Missing: Secure, SameSite
    Severity: HIGH
    Risks:
      - MITM session hijack: cookie sent over HTTP if user visits http:// link
      - CSRF: cross-site requests will include this cookie
    Remediation:
      - Add Secure flag
      - Add SameSite=Lax or SameSite=Strict
      - Consider __Host- prefix for domain-locked cookies

  Cookie: prefs
    Value  : theme=dark
    Domain : .example.com
    Path   : /
    Expires: 2027-01-01 (365d)
    Flags  : Secure
    Missing: HttpOnly, SameSite
    Severity: MED
    Risks:
      - XSS can read/modify this cookie via document.cookie
    Remediation:
      - Add HttpOnly if cookie is not needed by client-side JS
      - Add SameSite=Lax

Limitations:
  - Only analyzes cookies from a single GET response; login flows may set more.
  - Cannot detect server-side session fixation or rotation policies.
  - SameSite defaults vary by browser (Chrome defaults to Lax since 2020).
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class CookieInfo:
    """Parsed cookie with all security-relevant attributes."""
    name: str
    value: str
    domain: str
    path: str
    expires: str        # human-readable expiry or "Session"
    max_age_seconds: Optional[int]
    secure: bool
    httponly: bool
    samesite: str       # "Strict", "Lax", "None", or ""
    raw: str


@dataclass
class CookieFinding:
    cookie_name: str
    severity: str       # LOW / MED / HIGH
    missing_flags: List[str]
    risks: List[str]
    remediation: List[str]


# ---------------------------------------------------------------------------
# Cookie extraction and parsing
# ---------------------------------------------------------------------------
_SSL_CTX = ssl.create_default_context()


def get_cookies(url: str) -> List[CookieInfo]:
    """Fetch a URL and extract individual Set-Cookie headers.

    Why we use get_all(): a single get() may combine headers incorrectly.
    We split carefully to handle Expires commas (e.g., "Thu, 01 Jan 2026").
    """
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "CookieSecAnalyzer/1.0")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_SSL_CTX))

    try:
        resp = opener.open(req, timeout=10)
    except urllib.error.HTTPError as e:
        resp = e

    # get_all returns each Set-Cookie as a separate string
    raw_cookies = resp.headers.get_all("Set-Cookie") or []

    cookies: List[CookieInfo] = []
    for raw in raw_cookies:
        cookies.append(_parse_one_cookie(raw))

    return cookies


def _parse_one_cookie(raw: str) -> CookieInfo:
    """Parse a single Set-Cookie string into structured attributes.

    Why manual parsing: Python's http.cookies.SimpleCookie drops attributes
    like SameSite and doesn't expose them reliably.
    """
    parts = [p.strip() for p in raw.split(";")]
    # First part is name=value
    name_value = parts[0]
    name, _, value = name_value.partition("=")
    name = name.strip()
    value = value.strip()

    # Parse attributes
    domain = ""
    path = ""
    expires = "Session"
    max_age: Optional[int] = None
    secure = False
    httponly = False
    samesite = ""

    for attr in parts[1:]:
        attr_lower = attr.lower().strip()
        if attr_lower == "secure":
            secure = True
        elif attr_lower == "httponly":
            httponly = True
        elif attr_lower.startswith("samesite="):
            samesite = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("domain="):
            domain = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("path="):
            path = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("expires="):
            expires = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("max-age="):
            try:
                max_age = int(attr.split("=", 1)[1].strip())
                expires = f"Max-Age={max_age}s"
            except ValueError:
                pass

    return CookieInfo(
        name=name, value=value, domain=domain, path=path or "/",
        expires=expires, max_age_seconds=max_age, secure=secure,
        httponly=httponly, samesite=samesite, raw=raw,
    )


# ---------------------------------------------------------------------------
# Security analysis
# ---------------------------------------------------------------------------
def analyze_cookie(cookie: CookieInfo, target_url: str) -> CookieFinding:
    """Analyze a single cookie for security issues.

    Why per-cookie analysis: different cookies have different risk profiles;
    session cookies are far more critical than preference cookies.
    """
    missing: List[str] = []
    risks: List[str] = []
    remediation: List[str] = []

    # Determine if this looks like a session/auth cookie (higher severity base)
    session_like = any(
        kw in cookie.name.lower()
        for kw in ("sess", "token", "auth", "jwt", "sid", "login", "csrf")
    )

    # --- Secure flag ---
    if not cookie.secure:
        missing.append("Secure")
        risks.append("MITM session hijack: cookie sent over HTTP if user visits an http:// link")
        remediation.append("Add Secure flag")

    # --- HttpOnly flag ---
    if not cookie.httponly:
        missing.append("HttpOnly")
        risks.append("XSS cookie theft: JavaScript can read this cookie via document.cookie")
        remediation.append("Add HttpOnly (unless cookie is intentionally read by client JS)")

    # --- SameSite ---
    ss = cookie.samesite.lower()
    if not ss:
        missing.append("SameSite")
        risks.append("CSRF: cross-site requests will include this cookie (browser default varies)")
        remediation.append("Add SameSite=Lax or SameSite=Strict")
    elif ss == "none":
        # SameSite=None explicitly allows cross-site — same risk as missing
        missing.append("SameSite (set to None)")
        risks.append("CSRF: SameSite=None explicitly allows cross-site sending")
        remediation.append("Change to SameSite=Lax unless cross-site use is intentional")

    # --- Domain scope ---
    # Why: a cookie scoped to ".example.com" is readable by all subdomains,
    # which means a compromised subdomain can steal sessions.
    if cookie.domain.startswith("."):
        # Count domain parts to detect overly broad scope
        parts = cookie.domain.strip(".").split(".")
        if len(parts) <= 2:  # e.g., .example.com
            risks.append(
                f"Broad domain scope ({cookie.domain}): readable by all subdomains"
            )
            remediation.append("Restrict domain to specific subdomain or use __Host- prefix")

    # --- __Host- / __Secure- prefix checks ---
    # Why: __Host- cookies must have Secure, Path=/, and no Domain — providing
    # strong binding to the exact origin.
    if cookie.name.startswith("__Host-"):
        if not cookie.secure or cookie.domain or cookie.path != "/":
            risks.append("__Host- prefix violated: must have Secure, no Domain, Path=/")
            remediation.append("Fix __Host- cookie to comply with requirements")
    elif cookie.name.startswith("__Secure-"):
        if not cookie.secure:
            risks.append("__Secure- prefix violated: must have Secure flag")
            remediation.append("Add Secure flag to __Secure- cookie")
    elif session_like:
        remediation.append("Consider __Host- prefix for domain-locked session cookies")

    # --- Lifetime analysis ---
    # Why: long-lived session cookies increase the window for replay attacks.
    if cookie.max_age_seconds is not None and cookie.max_age_seconds > 86400 * 30:
        days = cookie.max_age_seconds // 86400
        risks.append(f"Long-lived cookie ({days}d): increases replay attack window")
        remediation.append("Reduce Max-Age for session cookies (recommended: ≤24h)")

    # --- Severity ---
    if not missing and not risks:
        severity = "LOW"
    elif session_like and ("Secure" in missing or "HttpOnly" in missing):
        severity = "HIGH"
    elif len(missing) >= 2:
        severity = "HIGH"
    elif missing:
        severity = "MED"
    else:
        severity = "LOW"

    return CookieFinding(
        cookie_name=cookie.name,
        severity=severity,
        missing_flags=missing,
        risks=risks,
        remediation=remediation,
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_report(cookies: List[CookieInfo], findings: List[CookieFinding], url: str) -> None:
    print("=== Cookie Security Analyzer ===")
    print(f"  Target : {url}")
    print(f"  Cookies: {len(cookies)}")
    print()

    for cookie, finding in zip(cookies, findings):
        # Truncate long values for readability
        display_val = cookie.value[:40] + "..." if len(cookie.value) > 40 else cookie.value
        flags_present = []
        if cookie.secure:
            flags_present.append("Secure")
        if cookie.httponly:
            flags_present.append("HttpOnly")
        if cookie.samesite:
            flags_present.append(f"SameSite={cookie.samesite}")

        print(f"  Cookie: {cookie.name}")
        print(f"    Value   : {display_val}")
        print(f"    Domain  : {cookie.domain or '(origin)'}")
        print(f"    Path    : {cookie.path}")
        print(f"    Expires : {cookie.expires}")
        print(f"    Flags   : {', '.join(flags_present) or '(none)'}")
        print(f"    Missing : {', '.join(finding.missing_flags) or '(none)'}")
        print(f"    Severity: {finding.severity}")

        if finding.risks:
            print("    Risks:")
            for r in finding.risks:
                print(f"      - {r}")

        if finding.remediation:
            print("    Remediation:")
            for r in finding.remediation:
                print(f"      - {r}")

        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze cookie security attributes (Secure, HttpOnly, SameSite, scope, lifetime)",
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--output-json", help="Write JSON report to file")

    args = parser.parse_args()

    cookies = get_cookies(args.url)

    if not cookies:
        print("=== Cookie Security Analyzer ===")
        print(f"  Target : {args.url}")
        print("\n  No cookies found in response.")
        return

    findings = [analyze_cookie(c, args.url) for c in cookies]
    print_report(cookies, findings, args.url)

    if args.output_json:
        report = {
            "target": args.url,
            "cookies": [
                {
                    "name": c.name,
                    "domain": c.domain,
                    "path": c.path,
                    "secure": c.secure,
                    "httponly": c.httponly,
                    "samesite": c.samesite,
                    "expires": c.expires,
                    **asdict(f),
                }
                for c, f in zip(cookies, findings)
            ],
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"  Report written to {args.output_json}")


if __name__ == "__main__":
    main()
  
