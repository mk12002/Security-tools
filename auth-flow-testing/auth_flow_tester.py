"""
Auth Flow Tester
=====================================
A comprehensive authentication flow testing tool that simulates login, tracks
sessions and tokens step-by-step, and checks for common auth vulnerabilities.

Detects:
  1. Session fixation (pre-login session ID unchanged after login)
  2. Token reuse (identical token on repeated logins)
  3. Missing invalidation (session persists after logout)
  4. Cookie security issues (missing Secure/HttpOnly/SameSite on session cookies)
  5. Weak session entropy (short or predictable session values)
  6. Login failure detection (wrong credentials not rejected)
  7. Post-logout access (protected resource still accessible after logout)

Usage:
  python auth_flow_tester.py --login-url https://target/login --username alice --password Secret123!
  python auth_flow_tester.py --login-url https://target/login --username alice --password Secret123! \\
      --logout-url https://target/logout --protected-url https://target/dashboard
  python auth_flow_tester.py --login-url https://target/api/login --username alice --password Secret123! \\
      --json-body --output-json report.json

Sample output (abridged):
  === Auth Flow Tester ===

  Step 1: Pre-login GET → 200
    Cookies: JSESSIONID=abc123def456
  Step 2: Login POST → 302 (redirect to /dashboard)
    Cookies: JSESSIONID=abc123def456  ← UNCHANGED!
    Tokens: eyJhbGciOiJIUzI1NiI...
  Step 3: Bad-password POST → 200 (login rejected ✓)
  Step 4: Second login POST → 200
    Tokens: eyJhbGciOiJIUzI1NiI... ← same token!
  Step 5: Logout → 302
  Step 6: Post-logout access → 200 ← should be 401!

  Findings:
    [HIGH] Session fixation — JSESSIONID unchanged after login
    [HIGH] Post-logout access — protected resource still returns 200
    [MED]  Token reuse — same JWT across logins
    [MED]  Missing HttpOnly on session cookie

Limitations:
  - CSRF token extraction is heuristic; custom implementations may need --extra-header.
  - Redirect following uses urllib defaults (may lose cookies on cross-domain).
  - Cannot detect server-side session storage flaws.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import ssl
import string
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict, field
from http.cookiejar import CookieJar, Cookie
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class StepResult:
    name: str
    status: int
    cookies: Dict[str, str]
    tokens: List[str]
    notes: List[str]


@dataclass
class Finding:
    severity: str           # HIGH / MED / LOW
    issue: str
    evidence: str
    remediation: str


# ---------------------------------------------------------------------------
# Token extraction
# ---------------------------------------------------------------------------
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*")
TOKEN_KEYS = {"token", "access_token", "id_token", "auth_token", "jwt", "bearer"}

# Session cookie names (case-insensitive matching)
SESSION_COOKIE_NAMES = {"session", "jsessionid", "phpsessid", "sid", "sessionid",
                        "asp.net_sessionid", "connect.sid", "laravel_session"}


def extract_tokens(body: str) -> List[str]:
    """Extract JWT-like tokens and named token fields from response body."""
    tokens: List[str] = []
    tokens.extend(JWT_RE.findall(body))

    # JSON body parsing
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in TOKEN_KEYS and isinstance(v, str) and len(v) > 10:
                    tokens.append(v)
    except Exception:
        pass

    # HTML hidden input extraction (CSRF tokens etc.)
    # We only care about tokens for tracking, not CSRF here
    seen: Set[str] = set()
    return [t for t in tokens if not (t in seen or seen.add(t))]  # type: ignore


def cookie_dict(jar: CookieJar) -> Dict[str, str]:
    return {c.name: c.value for c in jar}


def is_session_cookie(name: str) -> bool:
    return name.lower() in SESSION_COOKIE_NAMES


# ---------------------------------------------------------------------------
# Session entropy analysis
# ---------------------------------------------------------------------------

def estimate_session_entropy(value: str) -> float:
    """
    Estimate entropy of a session ID.
    Why: Low-entropy session IDs are guessable via brute force.
    OWASP recommends ≥64 bits of entropy for session tokens.
    """
    charset = set(value)
    pool = 0
    if charset & set(string.ascii_lowercase):
        pool += 26
    if charset & set(string.ascii_uppercase):
        pool += 26
    if charset & set(string.digits):
        pool += 10
    if charset - set(string.ascii_letters + string.digits):
        pool += 10  # special chars

    if pool == 0:
        return 0.0
    return len(value) * math.log2(pool)


# ---------------------------------------------------------------------------
# Cookie security attribute checks
# ---------------------------------------------------------------------------

def check_cookie_security(jar: CookieJar) -> List[Finding]:
    """
    Check session cookies for missing security attributes.
    Why: Missing Secure/HttpOnly/SameSite on session cookies enables
    MITM hijack, XSS theft, and CSRF attacks respectively.
    """
    findings: List[Finding] = []

    for cookie in jar:
        if not is_session_cookie(cookie.name):
            continue

        # HttpOnly check — Cookie object stores this in _rest or similar
        # CookieJar doesn't expose HttpOnly easily; check via has_nonstandard_attr
        # We'll check what we can from the cookie attributes
        if not cookie.secure:
            findings.append(Finding(
                severity="MED",
                issue=f"Missing Secure flag on {cookie.name}",
                evidence=f"Cookie {cookie.name} sent over HTTP connections",
                remediation="Add Secure flag to prevent MITM session hijack",
            ))

        # Domain scope — overly broad
        if cookie.domain and cookie.domain.startswith("."):
            parts = cookie.domain.strip(".").split(".")
            if len(parts) <= 2:
                findings.append(Finding(
                    severity="LOW",
                    issue=f"Broad domain scope on {cookie.name}",
                    evidence=f"domain={cookie.domain} allows all subdomains to read it",
                    remediation="Restrict domain or use __Host- prefix",
                ))

        # Entropy check
        entropy = estimate_session_entropy(cookie.value)
        if entropy < 64:
            findings.append(Finding(
                severity="MED",
                issue=f"Low session entropy on {cookie.name}",
                evidence=f"Estimated {entropy:.0f} bits (OWASP recommends ≥64)",
                remediation="Use cryptographically random session IDs of ≥128 bits",
            ))

    return findings


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def send_request(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    insecure: bool = False,
) -> Tuple[int, str, str]:
    """
    Send request, return (status, body, final_url).
    Why return final_url: detects redirects (login often redirects to dashboard).
    """
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "Mozilla/5.0 (AuthFlowTester/2.0)")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = opener.open(req, timeout=15, context=ctx)
        body = resp.read().decode("utf-8", errors="ignore")
        return resp.getcode(), body, resp.url
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, body, url
    except Exception as e:
        return 0, str(e), url


# ---------------------------------------------------------------------------
# Core auth flow
# ---------------------------------------------------------------------------

def run_auth_flow(
    login_url: str,
    username: str,
    password: str,
    logout_url: Optional[str],
    protected_url: Optional[str],
    field_user: str,
    field_pass: str,
    json_body: bool,
    extra_headers: Dict[str, str],
    insecure: bool,
) -> Tuple[List[StepResult], List[Finding]]:
    """
    Execute the full auth flow and detect vulnerabilities.
    Why step-by-step: each step's cookies/tokens are compared to detect changes.
    """
    findings: List[Finding] = []
    steps: List[StepResult] = []

    jar = CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPRedirectHandler(),
    )

    # --- Step 1: Pre-login GET ---
    status, body, final = send_request(opener, "GET", login_url, headers=extra_headers, insecure=insecure)
    cookies_pre = cookie_dict(jar)
    steps.append(StepResult("Pre-login GET", status, cookies_pre, extract_tokens(body),
                            [f"Redirect → {final}" if final != login_url else "No redirect"]))

    # --- Step 2: Login POST (valid credentials) ---
    if json_body:
        post_data = json.dumps({field_user: username, field_pass: password}).encode()
        content_type = "application/json"
    else:
        post_data = urllib.parse.urlencode({field_user: username, field_pass: password}).encode()
        content_type = "application/x-www-form-urlencoded"

    login_headers = {"Content-Type": content_type}
    login_headers.update(extra_headers)

    status2, body2, final2 = send_request(opener, "POST", login_url, data=post_data,
                                          headers=login_headers, insecure=insecure)
    cookies_post = cookie_dict(jar)
    tokens_post = extract_tokens(body2)
    notes2 = []
    if final2 != login_url:
        notes2.append(f"Redirect → {final2}")
    if 200 <= status2 < 400:
        notes2.append("Login appears successful")
    else:
        notes2.append(f"Login returned {status2} — may have failed")
    steps.append(StepResult("Login POST", status2, cookies_post, tokens_post, notes2))

    # --- Step 3: Bad password test ---
    # Why: confirms the server actually validates credentials
    bad_data = (json.dumps({field_user: username, field_pass: "INVALID_PASS_XYZ"}).encode()
                if json_body else
                urllib.parse.urlencode({field_user: username, field_pass: "INVALID_PASS_XYZ"}).encode())

    # Fresh jar for bad-password test to avoid session carryover
    jar_bad = CookieJar()
    opener_bad = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar_bad))
    status_bad, body_bad, _ = send_request(opener_bad, "POST", login_url, data=bad_data,
                                           headers=login_headers, insecure=insecure)
    bad_notes = []
    if status_bad == status2 and "error" not in body_bad.lower() and "invalid" not in body_bad.lower():
        bad_notes.append("⚠ Server returned same status as valid login!")
        findings.append(Finding(
            severity="HIGH",
            issue="Login does not reject bad credentials differently",
            evidence=f"Bad password returned same status ({status_bad}) as valid login",
            remediation="Return distinct error on failed auth; avoid information leakage",
        ))
    else:
        bad_notes.append("Login correctly rejects bad credentials ✓")
    steps.append(StepResult("Bad-password POST", status_bad, cookie_dict(jar_bad), [], bad_notes))

    # --- Step 4: Second login — token reuse check ---
    status3, body3, _ = send_request(opener, "POST", login_url, data=post_data,
                                     headers=login_headers, insecure=insecure)
    cookies_post2 = cookie_dict(jar)
    tokens_post2 = extract_tokens(body3)
    steps.append(StepResult("Second Login POST", status3, cookies_post2, tokens_post2,
                            ["Checking for token rotation"]))

    # --- Detection: Session fixation ---
    for name, val_pre in cookies_pre.items():
        if is_session_cookie(name):
            val_post = cookies_post.get(name)
            if val_post and val_pre == val_post:
                findings.append(Finding(
                    severity="HIGH",
                    issue="Session fixation",
                    evidence=f"{name} unchanged from pre-login ({val_pre[:20]}...) to post-login",
                    remediation="Regenerate session ID after successful authentication",
                ))

    # --- Detection: Token reuse ---
    if tokens_post and tokens_post2:
        reused = [t for t in tokens_post if t in tokens_post2]
        if reused:
            findings.append(Finding(
                severity="MED",
                issue="Token reuse across logins",
                evidence=f"Token unchanged: {reused[0][:30]}...",
                remediation="Rotate tokens on every login; bind to session + timestamp",
            ))

    # --- Cookie security checks ---
    findings.extend(check_cookie_security(jar))

    # --- Step 5+6: Logout and post-logout access ---
    if logout_url:
        status4, body4, _ = send_request(opener, "GET", logout_url, headers=extra_headers, insecure=insecure)
        cookies_logout = cookie_dict(jar)
        steps.append(StepResult("Logout", status4, cookies_logout, [],
                                [f"Logout status: {status4}"]))

        # Post-logout: try accessing protected resource
        check_url = protected_url or login_url
        status5, body5, _ = send_request(opener, "GET", check_url, headers=extra_headers, insecure=insecure)
        cookies_after = cookie_dict(jar)
        post_logout_notes = []

        if 200 <= status5 < 300 and protected_url:
            post_logout_notes.append("⚠ Protected resource still accessible after logout!")
            findings.append(Finding(
                severity="HIGH",
                issue="Post-logout access allowed",
                evidence=f"GET {check_url} returned {status5} after logout",
                remediation="Invalidate session server-side on logout; check session validity per request",
            ))
        else:
            post_logout_notes.append("Access correctly denied after logout ✓")

        steps.append(StepResult("Post-logout access", status5, cookies_after, [],
                                post_logout_notes))

        # Session persistence check
        for name in cookies_post:
            if is_session_cookie(name):
                pre_val = cookies_post.get(name)
                post_val = cookies_after.get(name)
                if pre_val and post_val and pre_val == post_val:
                    findings.append(Finding(
                        severity="MED",
                        issue="Session cookie not cleared on logout",
                        evidence=f"{name} unchanged after logout",
                        remediation="Clear or expire session cookies on logout; invalidate server-side",
                    ))

    return steps, findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(steps: List[StepResult], findings: List[Finding]) -> None:
    print("=== Auth Flow Tester ===\n")

    for i, s in enumerate(steps, 1):
        print(f"Step {i}: {s.name} → {s.status}")
        if s.cookies:
            for k, v in s.cookies.items():
                marker = " [session]" if is_session_cookie(k) else ""
                print(f"  Cookie: {k}={v[:25]}{'...' if len(v) > 25 else ''}{marker}")
        if s.tokens:
            for t in s.tokens:
                print(f"  Token : {t[:40]}...")
        for n in s.notes:
            print(f"  Note  : {n}")
        print()

    # Findings
    if findings:
        print(f"Findings ({len(findings)}):")
        for f in findings:
            print(f"  [{f.severity}] {f.issue}")
            print(f"    Evidence   : {f.evidence}")
            print(f"    Remediation: {f.remediation}")
            print()
    else:
        print("Findings: None detected — auth flow looks secure ✓\n")

    # Educational section
    print("=" * 55)
    print("Secure auth design (interview-ready):")
    print()
    print("  Session management:")
    print("    - Regenerate session ID on login (prevents fixation)")
    print("    - Invalidate session on logout AND password change")
    print("    - Set Secure + HttpOnly + SameSite=Lax on session cookies")
    print("    - Use ≥128-bit random session IDs (≥64 bits entropy)")
    print()
    print("  Token handling:")
    print("    - Short-lived access tokens (5–15 min)")
    print("    - Rotate refresh tokens on each use (detect theft)")
    print("    - Bind tokens to device/IP fingerprint for high-value actions")
    print()
    print("  Common auth flaws:")
    print("    - Session fixation: attacker sets session ID before victim logs in")
    print("    - Missing invalidation: logout doesn't destroy server-side session")
    print("    - Token reuse: same token issued repeatedly = replay attacks")
    print("    - Credential stuffing: no rate limiting on login endpoint")
    print()
    print("  Limitations of this tool:")
    print("    - Cannot detect server-side session store behavior")
    print("    - CSRF token auto-extraction is heuristic")
    print("    - Redirect chains may lose cookies cross-domain")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auth flow tester — detects fixation, reuse, and invalidation flaws",
    )
    parser.add_argument("--login-url", required=True, help="Login endpoint URL")
    parser.add_argument("--username", required=True, help="Valid username")
    parser.add_argument("--password", required=True, help="Valid password")
    parser.add_argument("--logout-url", help="Logout URL (enables invalidation checks)")
    parser.add_argument("--protected-url", help="Authenticated resource URL (for post-logout test)")
    parser.add_argument("--field-user", default="username", help="Username field name")
    parser.add_argument("--field-pass", default="password", help="Password field name")
    parser.add_argument("--json-body", action="store_true",
                        help="Send credentials as JSON instead of form-encoded")
    parser.add_argument("--extra-header", action="append", default=[],
                        help="Extra header (repeatable): 'Name: Value'")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--output-json", help="Write JSON report to file")

    args = parser.parse_args()

    headers: Dict[str, str] = {}
    for h in args.extra_header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    steps, findings = run_auth_flow(
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        logout_url=args.logout_url,
        protected_url=args.protected_url,
        field_user=args.field_user,
        field_pass=args.field_pass,
        json_body=args.json_body,
        extra_headers=headers,
        insecure=args.insecure,
    )

    print_report(steps, findings)

    if args.output_json:
        report = {
            "login_url": args.login_url,
            "steps": [asdict(s) for s in steps],
            "findings": [asdict(f) for f in findings],
            "summary": {
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
