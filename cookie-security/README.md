# Cookie Security Analyzer

## Problem Statement
Cookies store session identifiers and tokens. Missing security attributes (Secure, HttpOnly, SameSite) enable session hijacking, XSS cookie theft, and CSRF attacks.

## Threat Model
- **Attacker**: Network attacker (MITM for missing Secure), XSS attacker (missing HttpOnly), cross-site attacker (missing SameSite)
- **Techniques**: Session hijacking, cookie theft via JavaScript, CSRF riding
- **Goal**: Steal or abuse session cookies

## What the Tool Does
Fetches a URL and performs per-cookie security analysis:
1. Parses each Set-Cookie header individually (handles Expires commas correctly)
2. Checks Secure, HttpOnly, SameSite attributes
3. Flags SameSite=None as equivalent to missing
4. Analyzes Domain scope (overly broad = subdomain takeover risk)
5. Validates __Host- and __Secure- prefix requirements
6. Checks cookie lifetime (long-lived session cookies = replay risk)
7. Identifies session-like cookies for elevated severity

## Detection Logic
- Per-cookie attribute extraction from raw Set-Cookie header
- Session detection: name matching common patterns (session, sid, token, auth)
- Severity: session cookies missing critical flags = HIGH; preference cookies = MED
- __Host- prefix validation: must have Secure, Path=/, no Domain

## Example Usage
```bash
python cookie_analyzer.py --url https://example.com
python cookie_analyzer.py --url https://example.com/login --output-json cookies.json
```

## Risks & False Positives
- Some cookies intentionally lack HttpOnly (needed by client-side JS)
- SameSite defaults vary by browser (Chrome defaults to Lax since 2020)
- Broad domain may be intentional for SSO architectures

## Limitations
- Only analyzes cookies from a single GET response
- Cannot detect server-side session fixation or rotation
- HttpOnly detection limited by Python's cookie parsing

## Interview Talking Points
- "Missing Secure means the cookie travels over HTTP — a coffee-shop MITM can steal it"
- "SameSite=None is worse than missing because it's an explicit opt-out of CSRF protection"
- "__Host- prefix is the strongest cookie binding — it guarantees origin-locked, Secure, no domain"
- "I check lifetime because a session cookie with Max-Age=30d gives attackers a huge replay window"
