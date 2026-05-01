# Rate Limit / Brute Force Simulator

## Problem Statement
Login endpoints without rate limiting allow credential stuffing and brute-force attacks at scale. This tool tests whether a target properly throttles repeated authentication attempts.

## Threat Model
- **Attacker**: Automated tool (Hydra, custom script) attempting credential stuffing
- **Techniques**: Rapid sequential login attempts with different passwords
- **Goal**: Find valid credentials before being blocked

## What the Tool Does
Sends configurable login attempts and observes server throttling behavior:
1. Submits N login attempts with known-bad passwords
2. Detects rate limiting via status codes (429, 403) or response changes
3. Parses Retry-After headers for lockout duration
4. Tracks response size anomalies (different error pages)
5. Supports form-encoded and JSON content types
6. Configurable field names for username/password
7. Safety cap prevents accidental account lockout

## Detection Logic
- Baseline: first request establishes "normal" failed-login response
- Progressive: send attempts and watch for status code changes
- Trigger detection: 429/403 status, "rate limit"/"too many" in body, Retry-After header
- Stop-on-trigger option halts immediately when limit is detected

## Example Usage
```bash
python brute_force_simulator.py --url https://target/login --username admin --attempts 20
python brute_force_simulator.py --url https://target/api/auth --username admin --attempts 50 --json-body
```

## Risks & False Positives
- Some apps lock accounts (not just rate-limit); use a test account
- Rate limiting may be per-session, per-IP, or global — results vary
- CDN/WAF rate limiting may trigger before app-level limits

## Limitations
- Cannot test distributed brute force (multiple source IPs)
- Account lockout duration is not always detectable
- CAPTCHA-based rate limiting not detected

## Interview Talking Points
- "Rate limiting is defense-in-depth — it doesn't replace strong passwords but raises attack cost"
- "I distinguish between 429 (rate limit) and 403 (account lockout) because they have different implications"
- "Real attackers use credential stuffing lists, not brute force — rate limiting helps for both"
- "The safety cap demonstrates responsible testing practice"
