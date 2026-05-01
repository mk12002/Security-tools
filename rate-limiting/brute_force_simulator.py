"""
TOOL 6 — Rate Limit / Brute-Force Simulator
============================================
A production-quality CLI tool to simulate brute-force login attempts and
observe rate-limiting behavior. This is a SAFE assessment tool — it detects
defenses, not bypasses them.

How rate limiting works (interview-ready):
  Rate limiting constrains request frequency by IP, user, session, or API key.
  Common implementations:
  - Fixed window: N requests per time period (e.g., 5/min).
  - Sliding window: rolling count prevents burst-then-wait gaming.
  - Token bucket: smooth, burst-tolerant rate control.
  - Tarpitting: server progressively increases response delay.

How attackers bypass it:
  - Distributed IPs (botnets, rotating proxies).
  - Credential stuffing across many accounts (per-user limits miss it).
  - Slow "low-and-slow" attempts that stay under thresholds.
  - Header manipulation (X-Forwarded-For spoofing if trusted).

How to test ethically:
  - Use a dedicated test account with explicit permission.
  - Keep attempt counts small (--max-attempts flag).
  - Use --stop-on-trigger to halt as soon as rate limiting is observed.
  - Never target real user accounts or production systems without authorization.

Usage examples:
  python rate_limit_simulator.py --url https://example.com/login --username testuser \
    --password-list passwords.txt --delay 0.5

  python rate_limit_simulator.py --url https://example.com/api/auth --username admin \
    --password-list passwords.txt --content-type json --user-field email --pass-field pass

  python rate_limit_simulator.py --generate-sample passwords.txt

  python rate_limit_simulator.py --url https://example.com/login --username testuser \
    --password-list passwords.txt --stop-on-trigger --output-json report.json

Sample output:
------------------------------------------------
=== Rate Limit Simulator ===
  Target     : https://example.com/login
  User       : testuser
  Delay      : 0.5s
  Content    : form
  Max attempts: 50

  #   Status  Time   Size   Behavior
  001  200    142ms  4521b  normal
  002  200    138ms  4521b  normal
  003  200    145ms  4521b  normal
  004  200    310ms  4521b  progressive delay (tarpit)
  005  429     32ms   128b  HTTP 429 — Retry-After: 30s

  Rate limit first triggered at attempt #4 (progressive delay)
  Strongest defense observed: HTTP 429 at attempt #5

  Summary: 5 attempts | 2 rate-limit signals | 0 successful logins

Limitations:
  - Detection is heuristic; silent server-side throttling is invisible.
  - Retry-After may not always be present or accurate.
  - Progressive delay detection depends on network jitter.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import ssl
import string
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
class AttemptResult:
    """Single login attempt observation."""
    number: int
    password: str       # masked for output, full for JSON
    status: int
    elapsed_ms: int
    body_size: int
    behavior: str       # human label
    retry_after: str    # Retry-After header value, if any
    success: bool       # did the login appear to succeed?


# ---------------------------------------------------------------------------
# Detection keywords
# ---------------------------------------------------------------------------
# Why keyword lists: many apps never return 429 but signal rate limiting via
# page content. These are the most common real-world patterns.

LOCKOUT_KEYWORDS = [
    "account locked", "account has been locked",
    "too many attempts", "too many requests",
    "temporarily locked", "temporarily blocked",
    "try again later", "please wait",
    "rate limit exceeded", "throttled",
    "slow down",
]

CAPTCHA_KEYWORDS = [
    "captcha", "recaptcha", "hcaptcha",
    "verify you are human", "challenge required",
    "g-recaptcha", "cf-turnstile",
]

# Success indicators: if any of these appear after an attempt, the password
# may have worked. We flag this clearly so the tester knows.
SUCCESS_KEYWORDS = [
    "welcome", "dashboard", "logged in",
    "login successful", "authentication successful",
    "redirect", "set-cookie",
]

# Failure indicators (helps distinguish "normal failed login" from "blocked")
FAILURE_KEYWORDS = [
    "invalid password", "incorrect password",
    "invalid credentials", "authentication failed",
    "bad credentials", "login failed",
]


# ---------------------------------------------------------------------------
# Behavior detection
# ---------------------------------------------------------------------------
def _detect_behavior(
    status: int,
    headers: Dict[str, str],
    body: str,
    elapsed_ms: int,
    baseline_ms: int,
    baseline_size: int,
    body_size: int,
) -> Tuple[str, str, bool]:
    """Analyze response to classify behavior.

    Returns (behavior_label, retry_after_value, login_success).

    Detection hierarchy (highest confidence first):
    1. HTTP 429 — explicit rate limit.
    2. HTTP 503 — service-level throttling.
    3. CAPTCHA keywords — challenge injected.
    4. Lockout keywords — account or IP blocked.
    5. Progressive delay — response significantly slower than baseline.
    6. Response size anomaly — body size changed drastically (new page).
    7. Success detection — login appeared to work.
    """
    body_lower = body.lower()
    retry_after = headers.get("retry-after", "")

    # 1. Explicit rate limit
    if status == 429:
        ra_msg = f" — Retry-After: {retry_after}" if retry_after else ""
        return f"HTTP 429{ra_msg}", retry_after, False

    # 2. Service unavailable (sometimes used for throttling)
    if status == 503:
        return "HTTP 503 (possible throttling)", retry_after, False

    # 3. CAPTCHA
    if any(kw in body_lower for kw in CAPTCHA_KEYWORDS):
        return "CAPTCHA challenge detected", retry_after, False

    # 4. Lockout
    if any(kw in body_lower for kw in LOCKOUT_KEYWORDS):
        return "LOCKOUT message detected", retry_after, False

    # 5. Progressive delay: >2× baseline + 500ms guards against jitter
    if baseline_ms > 0 and elapsed_ms > (baseline_ms * 2 + 500):
        return f"progressive delay (tarpit: {elapsed_ms}ms vs baseline {baseline_ms}ms)", retry_after, False

    # 6. Response size anomaly (new page injected — possible soft block)
    # Why: some apps serve a completely different page when they block you.
    if baseline_size > 0 and abs(body_size - baseline_size) > baseline_size * 0.5 and body_size < baseline_size:
        # Body shrank significantly — likely a block/error page
        if not any(kw in body_lower for kw in FAILURE_KEYWORDS):
            return "response size anomaly (possible soft block)", retry_after, False

    # 7. Success detection
    if status in (200, 302, 303) and any(kw in body_lower for kw in SUCCESS_KEYWORDS):
        return "LOGIN SUCCESS", retry_after, True

    return "normal", retry_after, False


# ---------------------------------------------------------------------------
# HTTP request
# ---------------------------------------------------------------------------
_SSL_CTX = ssl.create_default_context()


def _send_login(
    url: str,
    username: str,
    password: str,
    user_field: str,
    pass_field: str,
    content_type: str,
    user_agent: str,
    timeout: int,
) -> Tuple[int, Dict[str, str], str, int]:
    """Send a login request and return (status, headers, body, elapsed_ms).

    Supports both form-encoded and JSON content types because modern APIs
    increasingly use JSON while traditional web apps use form data.
    """
    payload_dict = {user_field: username, pass_field: password}

    if content_type == "json":
        data = json.dumps(payload_dict).encode("utf-8")
        ct_header = "application/json"
    else:
        data = urllib.parse.urlencode(payload_dict).encode("utf-8")
        ct_header = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", ct_header)
    req.add_header("User-Agent", user_agent)

    handler = urllib.request.HTTPSHandler(context=_SSL_CTX)
    opener = urllib.request.build_opener(handler)

    start = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(256_000).decode("utf-8", errors="ignore")
            elapsed = int((time.monotonic() - start) * 1000)
            return resp.status, headers, body, elapsed
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        elapsed = int((time.monotonic() - start) * 1000)
        return e.code, headers, body, elapsed
    except Exception:
        elapsed = int((time.monotonic() - start) * 1000)
        return 0, {}, "", elapsed


# ---------------------------------------------------------------------------
# Main simulation
# ---------------------------------------------------------------------------
def simulate(
    url: str,
    username: str,
    passwords: List[str],
    delay: float,
    timeout: int,
    user_field: str,
    pass_field: str,
    content_type: str,
    user_agent: str,
    max_attempts: int,
    stop_on_trigger: bool,
) -> List[AttemptResult]:
    """Run brute-force simulation and return all attempt observations.

    Why baseline: we need a reference point for timing and body size so we
    can detect progressive delays and response-size anomalies reliably.
    """
    results: List[AttemptResult] = []
    cap = min(len(passwords), max_attempts)

    # First attempt establishes baseline
    status, headers, body, elapsed = _send_login(
        url, username, passwords[0], user_field, pass_field,
        content_type, user_agent, timeout,
    )
    baseline_ms = elapsed
    baseline_size = len(body)

    behavior, retry_after, success = _detect_behavior(
        status, headers, body, elapsed, baseline_ms, baseline_size, len(body),
    )
    results.append(AttemptResult(
        1, passwords[0], status, elapsed, len(body), behavior, retry_after, success,
    ))

    if stop_on_trigger and behavior not in ("normal", "LOGIN SUCCESS"):
        return results

    for i in range(1, cap):
        time.sleep(delay)
        status, headers, body, elapsed = _send_login(
            url, username, passwords[i], user_field, pass_field,
            content_type, user_agent, timeout,
        )
        behavior, retry_after, success = _detect_behavior(
            status, headers, body, elapsed, baseline_ms, baseline_size, len(body),
        )
        results.append(AttemptResult(
            i + 1, passwords[i], status, elapsed, len(body),
            behavior, retry_after, success,
        ))

        if stop_on_trigger and behavior not in ("normal", "LOGIN SUCCESS"):
            break
        if success:
            break  # always stop on successful login

    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def _mask(password: str) -> str:
    """Mask passwords in human output for safety."""
    if len(password) <= 2:
        return "**"
    return password[0] + "*" * (len(password) - 2) + password[-1]


def print_results(results: List[AttemptResult]) -> None:
    """Human-readable table output."""
    print(f"  {'#':>3s}  {'Status':>6s}  {'Time':>6s}  {'Size':>6s}  Behavior")

    for r in results:
        s = str(r.status) if r.status else "ERR"
        print(f"  {r.number:03d}  {s:>6s}  {r.elapsed_ms:>4d}ms  {r.body_size:>5d}b  {r.behavior}")


def print_summary(results: List[AttemptResult]) -> None:
    """Print analysis summary."""
    triggers = [r for r in results if r.behavior not in ("normal",)]
    rate_limits = [r for r in results if r.behavior not in ("normal", "LOGIN SUCCESS")]
    successes = [r for r in results if r.success]

    print()
    if rate_limits:
        first = rate_limits[0]
        print(f"  Rate limit first triggered at attempt #{first.number} ({first.behavior})")

        # Find strongest signal
        severity = {"HTTP 429": 3, "HTTP 503": 2, "CAPTCHA": 2, "LOCKOUT": 2, "tarpit": 1}
        strongest = max(rate_limits, key=lambda r: max(
            (v for k, v in severity.items() if k.lower() in r.behavior.lower()), default=0
        ))
        if strongest != first:
            print(f"  Strongest defense observed: {strongest.behavior} at attempt #{strongest.number}")
    else:
        print("  No rate limiting detected in this run.")

    if successes:
        print(f"\n  ⚠ LOGIN SUCCESS at attempt #{successes[0].number} (password: {_mask(successes[0].password)})")

    print(f"\n  Summary: {len(results)} attempts | {len(rate_limits)} rate-limit signals | {len(successes)} successful logins")


# ---------------------------------------------------------------------------
# Sample password list generator
# ---------------------------------------------------------------------------
def generate_sample_passwords(path: str) -> None:
    """Write a small, realistic test password list.

    Why: allows the tool to be self-testable without external files.
    """
    common = [
        "password", "123456", "admin", "letmein", "welcome",
        "monkey", "dragon", "master", "qwerty", "login",
        "abc123", "starwars", "trustno1", "iloveyou", "sunshine",
        "princess", "football", "shadow", "superman", "michael",
    ]
    with open(path, "w", encoding="utf-8") as f:
        for pwd in common:
            f.write(pwd + "\n")
    print(f"Sample password list ({len(common)} entries) written to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate brute-force attempts to observe rate-limiting defenses (ethical assessment only)",
    )
    parser.add_argument("--url", help="Login endpoint URL")
    parser.add_argument("--username", help="Username to test")
    parser.add_argument("--password-list", help="File with passwords (one per line)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between attempts in seconds (default: 1.0)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--user-field", default="username", help="Login form username field name (default: username)")
    parser.add_argument("--pass-field", default="password", help="Login form password field name (default: password)")
    parser.add_argument("--content-type", choices=["form", "json"], default="form",
                        help="Request body format (default: form)")
    parser.add_argument("--user-agent", default="RateLimitTester/1.0", help="Custom User-Agent")
    parser.add_argument("--max-attempts", type=int, default=50, help="Safety cap on attempts (default: 50)")
    parser.add_argument("--stop-on-trigger", action="store_true",
                        help="Stop immediately when rate limiting is detected")
    parser.add_argument("--output-json", help="Write JSON report to file")
    parser.add_argument("--generate-sample", help="Generate a sample password list file and exit")

    args = parser.parse_args()

    # Sample generation mode
    if args.generate_sample:
        generate_sample_passwords(args.generate_sample)
        return

    # Validate required args for simulation mode
    if not args.url or not args.username or not args.password_list:
        parser.error("--url, --username, and --password-list are required for simulation")

    with open(args.password_list, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    if not passwords:
        print("[ERROR] Password list is empty.")
        return

    print("=== Rate Limit Simulator ===")
    print(f"  Target      : {args.url}")
    print(f"  User        : {args.username}")
    print(f"  Delay       : {args.delay}s")
    print(f"  Content     : {args.content_type}")
    print(f"  Max attempts: {args.max_attempts}")
    if args.stop_on_trigger:
        print(f"  Mode        : stop on first rate-limit trigger")
    print()

    results = simulate(
        args.url, args.username, passwords, args.delay, args.timeout,
        args.user_field, args.pass_field, args.content_type,
        args.user_agent, args.max_attempts, args.stop_on_trigger,
    )

    print_results(results)
    print_summary(results)

    # JSON output
    if args.output_json:
        report = {
            "target": args.url,
            "username": args.username,
            "total_attempts": len(results),
            "results": [asdict(r) for r in results],
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n  Report written to {args.output_json}")


if __name__ == "__main__":
    main()
