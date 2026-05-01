# Auth Flow Tester

## Problem Statement
Authentication flows are complex multi-step processes where subtle flaws (session fixation, missing invalidation, token reuse) enable account takeover. These bugs are rarely caught by scanners.

## Threat Model
- **Attacker**: Account takeover via session manipulation or token replay
- **Techniques**: Session fixation (pre-set session ID), token replay, post-logout access
- **Goal**: Hijack another user's authenticated session

## What the Tool Does
Simulates a complete auth lifecycle and checks for vulnerabilities:
1. Pre-login GET — captures initial session cookies
2. Login POST — tracks session changes and tokens
3. Bad-password test — verifies credentials are actually validated
4. Second login — checks for token rotation
5. Logout (optional) — tests session invalidation
6. Post-logout access (optional) — verifies protected resources are denied

Detects: session fixation, token reuse, missing invalidation, weak session entropy, cookie security issues.

## Detection Logic
- Session fixation: compare session cookie before/after login — if unchanged, it's vulnerable
- Token reuse: compare JWT/tokens across two valid logins — if identical, rotation is missing
- Missing invalidation: access protected URL after logout — if 200, session persists
- Entropy: estimate bits of randomness in session value — OWASP requires ≥64 bits
- Cookie security: check Secure/HttpOnly/SameSite on session cookies

## Example Usage
```bash
python auth_flow_tester.py --login-url https://target/login --username alice --password Secret123!
python auth_flow_tester.py --login-url https://target/login --username alice --password Secret123! \
    --logout-url https://target/logout --protected-url https://target/dashboard
```

## Risks & False Positives
- Session cookies may legitimately persist across logins (stateless architectures)
- Token reuse may be acceptable for short-lived tokens with server-side revocation
- Entropy estimation overestimates for structured session IDs

## Limitations
- CSRF token extraction is heuristic
- Cannot detect server-side session store flaws
- Redirect chains may lose cookies cross-domain

## Interview Talking Points
- "Session fixation is when the attacker sets the session ID before the victim logs in — the fix is regeneration"
- "Post-logout access testing is critical — many apps clear the cookie but don't invalidate server-side"
- "I test bad passwords to verify the endpoint actually validates credentials, not just returns 200 for everything"
- "OWASP recommends ≥128-bit random session IDs to prevent brute-force guessing"
