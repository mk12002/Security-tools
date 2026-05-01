"""
TOOL 2 — Web Security Scanner (Misconfiguration Assessment)
===========================================================
A production-quality CLI scanner that checks common web security
misconfigurations **without exploitation**.

Why this exists (security reasoning):
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.) widen the
  attack surface for XSS, clickjacking, and protocol-downgrade attacks.
- Weak cookie flags allow session theft via scripts or insecure transport.
- Server/technology disclosure helps attackers fingerprint and target CVEs.
- Overly permissive CORS lets malicious origins read authenticated data.
- Reflected input hints at XSS risk; we only detect reflection, never exploit.

Usage examples:
  python web_scanner.py --url https://example.com
  python web_scanner.py --url https://example.com/search?q=test --timeout 10
  python web_scanner.py --url https://example.com --user-agent "SecBot/1.0"
  python web_scanner.py --url https://example.com --output-json report.json

Sample output:
------------------------------------------------
=== Web Security Scan ===
  Target : https://example.com/search?q=test
  Status : 200
  Server : nginx/1.18.0

[HIGH] Insecure cookie flags
  Found      : sessionid missing Secure, HttpOnly
  Why        : Session cookies stolen via XSS or insecure transport
  Remediation: Set Secure; HttpOnly; SameSite=Lax on all session cookies

[MED]  Missing Content-Security-Policy (CSP)
  Found      : content-security-policy header not present
  Why        : CSP restricts sources to reduce XSS impact
  Remediation: Start with default-src 'self' and refine iteratively

[MED]  Server info disclosure
  Found      : Server header reveals "nginx/1.18.0"
  Why        : Specific version info helps attackers target known CVEs
  Remediation: Suppress version info (e.g., server_tokens off in nginx)

[LOW]  Reflected input detected
  Found      : Token reflected in HTML body for parameter "q"
  Why        : Reflection is a prerequisite for reflected XSS
  Remediation: Contextually encode all output; validate input server-side

Limitations & false positives (interview talking points):
- Some apps omit CSP for legacy reasons; not always exploitable.
- Reflection does not prove XSS — output encoding may neutralize it.
- Cookie analysis only covers Set-Cookie headers in the response we receive.
- CORS wildcard (*) is safe when no credentials are sent; context matters.
- Single-page apps may set headers via meta tags, invisible to this scanner.
"""

from __future__ import annotations

import argparse
import html
import json
import random
import re
import ssl
import string
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from http.cookiejar import CookieJar
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Issue:
    """A single finding with context needed by both humans and SIEM."""
    level: str          # LOW / MED / HIGH
    title: str
    found: str
    why: str
    remediation: str


# ---------------------------------------------------------------------------
# HTTP fetching
# ---------------------------------------------------------------------------
def fetch_url(
    url: str, timeout: int, user_agent: str, *, follow_redirects: bool = True
) -> Tuple[int, Dict[str, str], bytes, str]:
    """Perform a safe HTTP(S) GET and return (status, headers, body, final_url).

    Why we build a custom opener:
    - Need both HTTP *and* HTTPS handlers (plain urllib only adds one).
    - CookieJar collects Set-Cookie properly across multi-value headers.
    - Optionally disable redirects for HTTPS-upgrade checks.
    - Tight timeout prevents hangs against slow or malicious servers.
    """
    ctx = ssl.create_default_context()

    handlers: list = [
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=ctx),
    ]
    if not follow_redirects:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            """Raise on redirect so callers can inspect the hop."""
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise urllib.error.HTTPError(newurl, code, msg, headers, fp)
        handlers.append(NoRedirect())

    jar = CookieJar()
    handlers.append(urllib.request.HTTPCookieProcessor(jar))

    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        },
    )

    resp = opener.open(req, timeout=timeout)
    status = resp.status

    # Collect headers — multiple values for the same key joined with "; "
    headers: Dict[str, str] = {}
    for key in resp.headers:
        vals = resp.headers.get_all(key)
        headers[key.lower()] = "; ".join(vals) if vals else ""

    body = resp.read(512_000)  # cap at 512 KB to avoid memory issues
    final_url = resp.url
    return status, headers, body, final_url


# ---------------------------------------------------------------------------
# HTTPS / TLS check
# ---------------------------------------------------------------------------
def check_https(url: str, timeout: int, user_agent: str) -> List[Issue]:
    """Verify the target is served over HTTPS and redirects from HTTP.

    Why: Plain HTTP exposes all traffic (credentials, cookies, tokens)
    to network-level attackers (public Wi-Fi, ARP spoofing, rogue AP).
    """
    issues: List[Issue] = []
    parsed = urllib.parse.urlsplit(url)

    if parsed.scheme == "http":
        issues.append(Issue(
            "HIGH",
            "Target served over plain HTTP",
            f"Scheme is http:// for {parsed.netloc}",
            "All traffic including credentials is visible to network attackers.",
            "Serve the application exclusively over HTTPS with a valid TLS certificate.",
        ))
        # Probe whether an HTTPS endpoint exists but isn't enforced
        https_url = urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))
        try:
            fetch_url(https_url, timeout, user_agent)
            issues.append(Issue(
                "MED",
                "HTTPS available but not enforced",
                f"HTTPS responds at {parsed.netloc} but HTTP does not redirect",
                "Users who type the URL without https:// are exposed.",
                "Add a 301 redirect from HTTP → HTTPS and enable HSTS.",
            ))
        except Exception:
            pass  # HTTPS not available; the first finding is sufficient

    return issues


# ---------------------------------------------------------------------------
# Security header analysis
# ---------------------------------------------------------------------------
# Each tuple: (header_name, severity, title, explanation, remediation)
_HEADER_CHECKS: List[Tuple[str, str, str, str, str]] = [
    (
        "content-security-policy",
        "MED", "Missing Content-Security-Policy (CSP)",
        "CSP restricts resource origins and mitigates XSS impact.",
        "Start with default-src 'self'; refine per resource type.",
    ),
    (
        "strict-transport-security",
        "MED", "Missing HSTS",
        "HSTS prevents protocol-downgrade and cookie-hijack attacks.",
        "Set Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    ),
    (
        "x-frame-options",
        "MED", "Missing X-Frame-Options",
        "Allows the page to be framed, enabling clickjacking attacks.",
        "Set X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors).",
    ),
    (
        "x-content-type-options",
        "LOW", "Missing X-Content-Type-Options",
        "MIME-sniffing can lead to XSS when serving user-uploaded content.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    (
        "referrer-policy",
        "LOW", "Missing Referrer-Policy",
        "Without this, full URLs (including tokens in query strings) may leak via Referer.",
        "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    ),
    (
        "permissions-policy",
        "LOW", "Missing Permissions-Policy",
        "Allows embedded content to access sensitive browser APIs (camera, mic, geolocation).",
        "Set Permissions-Policy to disable unused features (e.g., camera=(), microphone=()).",
    ),
]


def analyze_headers(headers: Dict[str, str]) -> List[Issue]:
    """Check for missing and misconfigured security headers.

    Why a table-driven approach: easy to extend with new headers without
    touching detection logic, and keeps the code reviewable in audits.
    """
    issues: List[Issue] = []

    for hdr, sev, title, why, fix in _HEADER_CHECKS:
        if hdr not in headers:
            issues.append(Issue(sev, title, f"{hdr} header not present", why, fix))

    # --- Weak CSP audit ---
    # Why: a CSP containing 'unsafe-inline' or 'unsafe-eval' largely negates
    # the protection CSP is designed to provide.
    csp = headers.get("content-security-policy", "")
    if csp:
        for weak in ("'unsafe-inline'", "'unsafe-eval'", "data:"):
            if weak in csp:
                issues.append(Issue(
                    "MED",
                    f"Weak CSP directive: {weak}",
                    f"CSP contains {weak}",
                    f"{weak} re-enables the attack vectors CSP is meant to block.",
                    f"Remove {weak}; use nonces or hashes for inline scripts instead.",
                ))

    return issues


# ---------------------------------------------------------------------------
# Server / technology disclosure
# ---------------------------------------------------------------------------
def check_info_disclosure(headers: Dict[str, str]) -> List[Issue]:
    """Flag headers that leak server software or framework versions.

    Why: Specific version strings (e.g., 'Apache/2.4.49') let attackers
    quickly look up known CVEs for that exact release.
    """
    issues: List[Issue] = []
    for hdr_name, label in [("server", "Server"), ("x-powered-by", "X-Powered-By")]:
        val = headers.get(hdr_name, "")
        if val:
            has_version = bool(re.search(r"\d+\.\d+", val))
            sev = "MED" if has_version else "LOW"
            issues.append(Issue(
                sev,
                f"{label} info disclosure",
                f'{label} header reveals "{val}"',
                "Version info helps attackers target known CVEs for that software.",
                f"Suppress or genericize the {label} header (e.g., server_tokens off).",
            ))

    return issues


# ---------------------------------------------------------------------------
# CORS misconfiguration
# ---------------------------------------------------------------------------
def check_cors(headers: Dict[str, str]) -> List[Issue]:
    """Detect overly permissive CORS configuration.

    Why: Access-Control-Allow-Origin: * combined with credentials lets any
    origin read authenticated responses — a full data-theft vector.
    """
    issues: List[Issue] = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()

    if acao == "*":
        if acac == "true":
            issues.append(Issue(
                "HIGH",
                "CORS wildcard with credentials",
                "Access-Control-Allow-Origin: * and Allow-Credentials: true",
                "Any origin can read authenticated responses — full data theft risk.",
                "Restrict ACAO to a specific trusted origin; never combine * with credentials.",
            ))
        else:
            issues.append(Issue(
                "LOW",
                "CORS wildcard origin",
                "Access-Control-Allow-Origin: *",
                "Any origin can read public responses (acceptable for truly public APIs).",
                "Restrict to specific origins unless the resource is intentionally public.",
            ))

    return issues


# ---------------------------------------------------------------------------
# XSS reflection check
# ---------------------------------------------------------------------------
def _random_token(n: int = 10) -> str:
    """Generate a unique canary token for reflection detection.

    Why a random token: avoids false positives from common words appearing
    naturally in the page, and is completely non-executable.
    """
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def xss_reflection_check(url: str, timeout: int, user_agent: str) -> List[Issue]:
    """Detect reflected input in query parameters and identify reflection context.

    Why context matters: reflection inside a tag attribute or <script> block
    is far more dangerous than inside a <p> text node with proper encoding.
    We inject only benign canary tokens — never executable payloads.
    """
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    issues: List[Issue] = []

    for param in params:
        token = f"zXs{_random_token()}"  # unique prefix unlikely to collide
        new_params = {k: v[:] for k, v in params.items()}
        new_params[param] = [token]

        new_query = urllib.parse.urlencode(new_params, doseq=True)
        test_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment)
        )

        try:
            status, _, body, _ = fetch_url(test_url, timeout, user_agent)
        except Exception:
            continue
        if status >= 400:
            continue

        text = body.decode("utf-8", errors="ignore")
        unescaped = html.unescape(text)

        if token not in text and token not in unescaped:
            continue

        # --- Determine reflection context for severity assessment ---
        # Why: XSS inside an attribute or script block is far more exploitable
        # than plain-text reflection in the document body.
        context = "HTML body"
        sev = "LOW"

        # Inside a tag attribute (e.g., value="zXs...")
        if re.search(rf'(?:value|href|src|action)\s*=\s*["\'][^"\']*{re.escape(token)}', text, re.I):
            context = "HTML attribute"
            sev = "MED"
        # Inside a <script> block
        if re.search(rf'<script[^>]*>.*?{re.escape(token)}.*?</script>', text, re.I | re.S):
            context = "JavaScript block"
            sev = "MED"

        issues.append(Issue(
            sev,
            "Reflected input detected",
            f'Token reflected in {context} for parameter "{param}"',
            "Reflection is a prerequisite for reflected XSS; context determines exploitability.",
            "Contextually encode all output; validate and sanitize input server-side.",
        ))

    return issues


# ---------------------------------------------------------------------------
# Cookie analysis
# ---------------------------------------------------------------------------
def analyze_cookies(headers: Dict[str, str]) -> List[Issue]:
    """Evaluate Set-Cookie attributes for security flags.

    Why these flags matter:
    - Secure: cookie only sent over HTTPS — prevents network sniffing.
    - HttpOnly: inaccessible to JavaScript — prevents theft via XSS.
    - SameSite: limits cross-origin sending — mitigates CSRF.

    Parsing note: Set-Cookie values can contain commas inside Expires dates
    (e.g., "Thu, 01 Jan 2026 …") so naive comma-splitting is WRONG.
    We split on the pattern ", <name>=" which starts a new cookie.
    """
    issues: List[Issue] = []
    raw = headers.get("set-cookie", "")
    if not raw:
        return issues

    # Robust split: ", <token>=" starts a new cookie; avoids breaking on Expires
    cookies = re.split(r',\s*(?=[A-Za-z_][A-Za-z0-9_]*=)', raw)

    for cookie in cookies:
        cookie = cookie.strip()
        if "=" not in cookie:
            continue

        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        missing: List[str] = []

        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")

        if not missing:
            continue

        # Higher severity for session-like cookies (more impact if stolen)
        session_like = any(kw in name.lower() for kw in ("sess", "token", "auth", "jwt", "sid"))
        sev = "HIGH" if session_like and ("Secure" in missing or "HttpOnly" in missing) else "MED"

        issues.append(Issue(
            sev,
            "Insecure cookie flags",
            f'"{name}" missing: {", ".join(missing)}',
            "Weak cookie flags allow session theft or cross-site misuse.",
            "Set Secure; HttpOnly; SameSite=Lax on all session cookies.",
        ))

    return issues


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def _print_summary(url: str, status: int, headers: Dict[str, str]) -> None:
    """Print a concise banner so the analyst knows what was scanned."""
    server = headers.get("server", "not disclosed")
    print("=== Web Security Scan ===")
    print(f"  Target : {url}")
    print(f"  Status : {status}")
    print(f"  Server : {server}")
    print()


def _issues_to_json(issues: List[Issue]) -> List[Dict[str, str]]:
    return [asdict(i) for i in issues]


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assess common web security misconfigurations (no exploitation)",
    )
    parser.add_argument("--url", required=True, help="Target URL (include query params for XSS reflection test)")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    parser.add_argument("--user-agent", default="WebSecScanner/1.0", help="Custom User-Agent string")
    parser.add_argument("--output-json", help="Write JSON report to file")

    args = parser.parse_args()
    all_issues: List[Issue] = []

    # --- Primary request ---
    try:
        status, headers, body, final_url = fetch_url(args.url, args.timeout, args.user_agent)
    except Exception as exc:
        print(f"[ERROR] Could not reach {args.url}: {exc}")
        return

    _print_summary(args.url, status, headers)

    # --- Run all checks ---
    all_issues.extend(check_https(args.url, args.timeout, args.user_agent))
    all_issues.extend(analyze_headers(headers))
    all_issues.extend(check_info_disclosure(headers))
    all_issues.extend(check_cors(headers))
    all_issues.extend(analyze_cookies(headers))
    all_issues.extend(xss_reflection_check(args.url, args.timeout, args.user_agent))

    if not all_issues:
        print("No issues detected.")
        return

    # Sort findings by severity: HIGH first, then MED, then LOW
    severity_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    all_issues.sort(key=lambda i: severity_order.get(i.level, 9))

    for i in all_issues:
        print(f"[{i.level}] {i.title}")
        print(f"  Found      : {i.found}")
        print(f"  Why        : {i.why}")
        print(f"  Remediation: {i.remediation}")
        print()

    # --- Optional JSON output for SIEM / pipeline ingestion ---
    if args.output_json:
        payload = {
            "target": args.url,
            "status": status,
            "issues": _issues_to_json(all_issues),
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"Report written to {args.output_json}")


if __name__ == "__main__":
    main()
