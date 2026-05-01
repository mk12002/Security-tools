"""
TOOL 3 — JWT Analyzer (Security Review)
========================================
A production-quality CLI tool for analyzing JSON Web Tokens (JWTs) without
performing exploitation. Designed for backend security reviewers and SOC analysts.

JWT structure (interview-ready explanation):
  A JWT is three Base64URL-encoded segments separated by dots:
    <header>.<payload>.<signature>
  - Header:    algorithm (alg), token type (typ), key hints (kid, jku, jwk, x5u)
  - Payload:   claims — identity (sub, iss, aud), timing (exp, iat, nbf), anti-replay (jti)
  - Signature: HMAC or RSA/EC proof that header+payload have not been tampered with

Common JWT attacks this tool detects:
  1. alg=none bypass — token is unsigned, server may accept it if alg validation is missing
  2. HS/RS confusion — server expects RS256 (asymmetric) but attacker switches to HS256
     and signs with the public key as HMAC secret
  3. jku/jwk/x5u injection — attacker points to their own key server via header fields
  4. Stripped signature — alg says HS256 but signature segment is empty
  5. Expired / not-yet-valid tokens — exp/nbf timing issues
  6. Excessive lifetime — tokens valid for days/weeks increase replay window
  7. Sensitive data in payload — PII, secrets, or credentials in the unencrypted payload

Usage examples:
  python jwt_analyzer.py --token eyJhbGciOiJI...
  python jwt_analyzer.py --token-file token.txt
  echo "eyJhbGci..." | python jwt_analyzer.py --token -
  python jwt_analyzer.py --token eyJ... --output-json report.json
  python jwt_analyzer.py --generate-sample

Sample output:
------------------------------------------------
=== JWT Analyzer ===

── Header ──
  alg : HS256
  typ : JWT
  kid : key-1

── Payload (standard claims) ──
  iss : https://id.example.com
  sub : user-123
  aud : api
  exp : 2026-04-29T12:30:00Z (EXPIRED — 2h ago)
  iat : 2026-04-28T12:30:00Z
  jti : (missing)

── Payload (custom claims) ──
  role  : admin
  email : alice@example.com

── Findings ──
  [CRITICAL] Token is expired (exp was 2h ago)
  [WARN]     Symmetric algorithm (HS256) — ensure secret is strong (≥256-bit)
  [WARN]     Missing claim: jti — no replay protection
  [WARN]     Sensitive key in payload: "email" may contain PII
  [INFO]     Token lifetime: 24h 0m (consider shorter for high-privilege tokens)

Limitations:
- No cryptographic verification without a secret/key — structural analysis only.
- HS/RS confusion is heuristic; actual risk depends on server implementation.
- PII detection uses keyword matching, not content inspection.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """Single security finding with severity for triage."""
    level: str      # INFO / WARN / CRITICAL
    message: str


# ---------------------------------------------------------------------------
# JWT decoding
# ---------------------------------------------------------------------------
def _b64url_decode(segment: str) -> bytes:
    """Base64URL-decode a JWT segment.

    Why: JWTs use Base64URL encoding without padding. Standard base64
    decoders choke without the padding, so we restore it.
    """
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def parse_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    """Split and decode a JWT into (header, payload, raw_signature).

    No cryptographic verification — purely structural decoding.
    Why: We want to inspect tokens the same way an attacker would: decode
    without needing the secret, then assess what's exposed.
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"JWT must have 3 dot-separated parts (got {len(parts)}). "
            "Format: header.payload.signature"
        )

    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="ignore"))
    except Exception as exc:
        raise ValueError(f"Cannot decode JWT header: {exc}") from exc

    try:
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="ignore"))
    except Exception as exc:
        raise ValueError(f"Cannot decode JWT payload: {exc}") from exc

    return header, payload, parts[2]


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

# Standard registered claims (RFC 7519 §4.1)
_REGISTERED_CLAIMS = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

# Keys in the payload that hint at sensitive / PII data
_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "ssn", "credit_card", "cc_number",
    "email", "phone", "address", "dob", "date_of_birth", "national_id",
    "api_key", "apikey", "access_token", "refresh_token",
}

# Header fields that, if present, allow attacker-controlled key sources
_DANGEROUS_HEADER_FIELDS = {
    "jku": "JSON Web Key Set URL — attacker can point to their own key server",
    "jwk": "Embedded JSON Web Key — attacker can embed their own public key",
    "x5u": "X.509 URL — attacker can supply their own certificate chain",
}


def _format_epoch(epoch: Any) -> Optional[dt.datetime]:
    """Convert a numeric epoch to datetime, or None on failure."""
    try:
        return dt.datetime.utcfromtimestamp(int(epoch))
    except Exception:
        return None


def _human_delta(delta: dt.timedelta) -> str:
    """Render a timedelta as a human-friendly string like '2h 15m'."""
    total_seconds = int(abs(delta.total_seconds()))
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def analyze_header(header: Dict[str, Any]) -> List[Finding]:
    """Analyze the JWT header for algorithm and key-source risks."""
    findings: List[Finding] = []
    alg = str(header.get("alg", "")).strip()
    alg_upper = alg.upper()

    # ── alg=none (unsigned token) ──
    # Why critical: if the server accepts alg=none it skips signature
    # verification entirely, letting anyone forge tokens.
    if alg_upper == "NONE" or alg == "":
        findings.append(Finding(
            "CRITICAL",
            'alg=none / empty — token is unsigned; server MUST reject these',
        ))

    # ── Symmetric algorithms (HS*) ──
    # Why: the signing secret must be kept private and strong (≥256-bit).
    # If the server also holds an RSA public key, HS/RS confusion is possible.
    elif alg_upper.startswith("HS"):
        findings.append(Finding(
            "WARN",
            f"Symmetric algorithm ({alg}) — ensure secret is strong (≥256-bit) and never exposed",
        ))
        findings.append(Finding(
            "WARN",
            "HS/RS confusion risk: if server expects RS* but accepts HS*, "
            "attacker can sign with the public key as HMAC secret",
        ))

    # ── Dangerous header fields (jku, jwk, x5u) ──
    # Why: these let the token point to an external key source. If the server
    # fetches and trusts them without allowlisting, an attacker forges tokens.
    for field, desc in _DANGEROUS_HEADER_FIELDS.items():
        if field in header:
            findings.append(Finding(
                "CRITICAL",
                f'Header contains "{field}": {desc}. Value: {header[field]}',
            ))

    return findings


def analyze_payload(payload: Dict[str, Any]) -> List[Finding]:
    """Analyze the JWT payload for timing, claim, and data-exposure risks."""
    findings: List[Finding] = []
    now = dt.datetime.utcnow()

    # ── Expiration (exp) ──
    exp_val = payload.get("exp")
    if exp_val is None:
        findings.append(Finding("WARN", "Missing exp claim — token may never expire"))
    else:
        exp_dt = _format_epoch(exp_val)
        if exp_dt is None:
            findings.append(Finding("WARN", "exp is not a valid numeric timestamp"))
        elif exp_dt < now:
            ago = _human_delta(now - exp_dt)
            findings.append(Finding("CRITICAL", f"Token is expired (exp was {ago} ago)"))

    # ── Not-before (nbf) ──
    nbf_val = payload.get("nbf")
    if nbf_val is not None:
        nbf_dt = _format_epoch(nbf_val)
        if nbf_dt and nbf_dt > now:
            until = _human_delta(nbf_dt - now)
            findings.append(Finding("WARN", f"Token not yet valid (nbf is {until} in the future)"))

    # ── Lifetime analysis (exp - iat) ──
    # Why: long-lived tokens widen the replay window. For high-privilege
    # tokens (admin roles, write scopes) shorter lifetimes are best practice.
    iat_val = payload.get("iat")
    if exp_val is not None and iat_val is not None:
        exp_dt = _format_epoch(exp_val)
        iat_dt = _format_epoch(iat_val)
        if exp_dt and iat_dt:
            lifetime = exp_dt - iat_dt
            lifetime_hours = lifetime.total_seconds() / 3600
            msg = f"Token lifetime: {_human_delta(lifetime)}"
            if lifetime_hours > 24:
                findings.append(Finding("WARN", f"{msg} — excessively long; consider ≤1h for sensitive ops"))
            elif lifetime_hours > 1:
                findings.append(Finding("INFO", f"{msg} (consider shorter for high-privilege tokens)"))
            else:
                findings.append(Finding("INFO", msg))

    # ── Missing standard claims ──
    for claim in ["iss", "sub", "aud", "iat", "jti"]:
        if claim not in payload:
            reason = {
                "iss": "no issuer verification possible",
                "sub": "no subject binding",
                "aud": "no audience restriction — token accepted anywhere",
                "iat": "no issuance time for freshness checks",
                "jti": "no replay protection",
            }.get(claim, "")
            findings.append(Finding("WARN", f"Missing claim: {claim} — {reason}"))

    # ── Sensitive data exposure ──
    # Why: the JWT payload is only Base64URL-encoded, NOT encrypted. Any PII
    # or secrets are readable by anyone who intercepts the token.
    for key in payload:
        if key.lower() in _SENSITIVE_KEYS:
            findings.append(Finding(
                "WARN",
                f'Sensitive key in payload: "{key}" may contain PII/secrets '
                "(payload is Base64-encoded, not encrypted)",
            ))

    return findings


def analyze_signature(header: Dict[str, Any], signature: str) -> List[Finding]:
    """Check for stripped-signature attacks.

    Why: An attacker can change alg to HS256, empty the signature, and if the
    server has a bug in its verification path, the token may be accepted.
    """
    findings: List[Finding] = []
    alg_upper = str(header.get("alg", "")).upper()

    if not signature and alg_upper != "NONE":
        findings.append(Finding(
            "CRITICAL",
            f"Signature segment is EMPTY but alg={header.get('alg')} — possible stripped-signature attack",
        ))

    return findings


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def _ts_display(payload: Dict[str, Any], key: str, now: dt.datetime) -> str:
    """Format a timestamp claim with a human-readable annotation."""
    val = payload.get(key)
    if val is None:
        return "(missing)"
    d = _format_epoch(val)
    if d is None:
        return str(val)
    formatted = d.strftime("%Y-%m-%dT%H:%M:%SZ")
    if key == "exp" and d < now:
        return f"{formatted}  (EXPIRED — {_human_delta(now - d)} ago)"
    if key == "nbf" and d > now:
        return f"{formatted}  (NOT YET VALID — {_human_delta(d - now)} from now)"
    return formatted


def print_report(
    header: Dict[str, Any],
    payload: Dict[str, Any],
    findings: List[Finding],
) -> None:
    """Human-readable, interview-presentable output."""
    now = dt.datetime.utcnow()

    print("=== JWT Analyzer ===\n")

    # Header
    print("── Header ──")
    for k, v in header.items():
        print(f"  {k:10s}: {v}")

    # Payload — standard claims
    print("\n── Payload (standard claims) ──")
    for claim in ["iss", "sub", "aud", "exp", "iat", "nbf", "jti"]:
        if claim in ("exp", "iat", "nbf"):
            print(f"  {claim:10s}: {_ts_display(payload, claim, now)}")
        elif claim in payload:
            print(f"  {claim:10s}: {payload[claim]}")
        else:
            print(f"  {claim:10s}: (missing)")

    # Payload — custom (non-registered) claims
    custom = {k: v for k, v in payload.items() if k not in _REGISTERED_CLAIMS}
    if custom:
        print("\n── Payload (custom claims) ──")
        for k, v in custom.items():
            # Truncate long values to keep output readable
            display = str(v)
            if len(display) > 80:
                display = display[:77] + "..."
            print(f"  {k:10s}: {display}")

    # Findings grouped by severity
    print("\n── Findings ──")
    severity_order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.level, 9))

    if not sorted_findings:
        print("  No issues found.")
    for f in sorted_findings:
        tag = f"[{f.level}]"
        print(f"  {tag:12s} {f.message}")

    print()


# ---------------------------------------------------------------------------
# Sample token generator
# ---------------------------------------------------------------------------
def generate_sample_tokens() -> List[Tuple[str, str]]:
    """Create sample JWTs for testing. No real signing — signature is dummy.

    Returns list of (label, token_string).
    """
    def _encode(header: dict, payload: dict, sig: str = "fakesig") -> str:
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"{h}.{p}.{sig}"

    now_ts = int(dt.datetime.utcnow().timestamp())
    samples = []

    # 1. Normal token
    samples.append(("Normal HS256 token", _encode(
        {"alg": "HS256", "typ": "JWT"},
        {"iss": "https://id.example.com", "sub": "user-123", "aud": "api",
         "exp": now_ts + 3600, "iat": now_ts, "jti": "abc-123", "role": "user"},
    )))

    # 2. Expired token
    samples.append(("Expired token", _encode(
        {"alg": "HS256", "typ": "JWT"},
        {"iss": "https://id.example.com", "sub": "user-456",
         "exp": now_ts - 7200, "iat": now_ts - 10800},
    )))

    # 3. alg=none
    samples.append(("alg=none (unsigned)", _encode(
        {"alg": "none", "typ": "JWT"},
        {"sub": "admin", "role": "admin", "exp": now_ts + 3600},
        sig="",
    )))

    # 4. Token with sensitive data + jku
    samples.append(("Sensitive data + jku injection", _encode(
        {"alg": "RS256", "typ": "JWT", "jku": "https://evil.com/jwks.json"},
        {"sub": "user-789", "email": "alice@corp.com", "password": "hunter2",
         "exp": now_ts + 86400 * 30, "iat": now_ts},
    )))

    # 5. Stripped signature
    samples.append(("Stripped signature attack", _encode(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "admin", "exp": now_ts + 3600, "iat": now_ts},
        sig="",
    )))

    return samples


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------
def _read_token(args) -> Optional[str]:
    """Read a JWT from --token, --token-file, or stdin (--token -)."""
    if args.token:
        if args.token == "-":
            return sys.stdin.read().strip()
        return args.token.strip()
    if args.token_file:
        with open(args.token_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze JWTs for common security risks (no exploitation)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--token", help='JWT string to analyze (use "-" to read from stdin)')
    group.add_argument("--token-file", help="Read JWT from a file")
    group.add_argument(
        "--generate-sample",
        action="store_true",
        help="Print sample JWTs for testing and exit",
    )
    parser.add_argument("--output-json", help="Write findings to JSON file")

    args = parser.parse_args()

    # ── Sample generation mode ──
    if args.generate_sample:
        samples = generate_sample_tokens()
        for label, tok in samples:
            print(f"# {label}")
            print(tok)
            print()
        return

    # ── Normal analysis mode ──
    token = _read_token(args)
    if not token:
        parser.error("Provide --token, --token-file, or --generate-sample")

    try:
        header, payload, signature = parse_jwt(token)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return

    # Run all detectors
    findings: List[Finding] = []
    findings.extend(analyze_header(header))
    findings.extend(analyze_payload(payload))
    findings.extend(analyze_signature(header, signature))

    # Human-readable report
    print_report(header, payload, findings)

    # Optional JSON output
    if args.output_json:
        report = {
            "header": header,
            "payload": {k: str(v) for k, v in payload.items()},
            "findings": [asdict(f) for f in findings],
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"Report written to {args.output_json}")


if __name__ == "__main__":
    main()
