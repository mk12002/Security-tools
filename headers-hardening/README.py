# Security Headers Hardening Checker

## Problem Statement
Security headers are the cheapest defense layer for web applications. A single missing header can enable XSS, clickjacking, MIME sniffing, or cross-origin data theft. Many teams don't know which headers matter or what values are strong.

## Threat Model
- **Attacker**: XSS attacker (no CSP), network attacker (no HSTS), clickjacker (no X-Frame-Options)
- **Techniques**: Exploiting missing browser security controls
- **Goal**: Execute scripts, steal data, or manipulate user actions

## What the Tool Does
Checks 10 security headers with value-quality analysis:
1. **Content-Security-Policy** — checks for unsafe-inline, unsafe-eval, wildcards
2. **Strict-Transport-Security** — validates max-age ≥1 year, includeSubDomains
3. **X-Content-Type-Options** — must be "nosniff"
4. **X-Frame-Options** — must be DENY or SAMEORIGIN
5. **Referrer-Policy** — flags leaky values (unsafe-url, origin)
6. **Permissions-Policy** — restricts camera, mic, geolocation
7. **Cross-Origin-Opener-Policy** — Spectre isolation
8. **Cross-Origin-Resource-Policy** — prevents cross-origin resource loading
9. **Cross-Origin-Embedder-Policy** — requires CORP for embedded resources
10. **X-XSS-Protection** — deprecated; flags dangerous "1" value

Plus: information leakage detection (Server, X-Powered-By headers), letter grade A–F.

## Detection Logic
- Fetch response headers from target URL
- For each header: check presence → if present, validate value quality
- Weak values get half credit; missing gets zero
- Compute weighted score (0–100) → map to letter grade
- Check for dangerous info-leaking headers that should be removed

## Example Usage
```bash
python headers_checker.py --url https://example.com
python headers_checker.py --url https://example.com --cookie "session=abc" --output-json report.json
```

## Risks & False Positives
- Some headers are only relevant for HTML responses (not JSON APIs)
- CSP quality depends on application-specific script sources
- COOP/CORP/COEP may break legitimate cross-origin integrations

## Limitations
- Checks a single URL; headers may vary per path or content-type
- CSP audit is surface-level; use csp-evaluator for deep analysis
- Cannot detect header injection vulnerabilities

## Interview Talking Points
- "CSP is the most impactful header — it prevents XSS even when input validation fails"
- "X-XSS-Protection '1' is actually dangerous — it can be exploited to selectively disable scripts"
- "HSTS preload means the browser will NEVER connect via HTTP, even on first visit"
- "I grade headers because executives need a single score, not a list of technical findings"
- "COOP/CORP/COEP are the modern cross-origin isolation headers required for SharedArrayBuffer"
