# 02 — Web Security Scanner

## Problem Statement
Web applications often ship with missing security headers, reflected XSS vulnerabilities, CORS misconfigurations, and TLS issues. A quick automated scan catches low-hanging fruit before deeper manual testing.

## Threat Model
- **Attacker**: Opportunistic scanner or targeted attacker probing for common web weaknesses
- **Techniques**: Header inspection, parameter reflection, CORS probing
- **Goal**: Find exploitable entry points (XSS, data leakage, clickjacking)

## What the Tool Does
Performs 6 categories of checks against a target URL:
1. HTTPS/TLS certificate validation
2. Security header presence and quality (CSP, HSTS, X-Frame-Options, etc.)
3. Weak CSP directive audit (unsafe-inline, unsafe-eval, wildcards)
4. CORS misconfiguration (wildcard origin, credential leakage)
5. Server information disclosure (Server header, X-Powered-By)
6. XSS reflection detection with context awareness (HTML/attribute/JS)

## Detection Logic
- Headers: presence check + value validation against OWASP recommendations
- CORS: sends Origin header and checks Access-Control-Allow-Origin response
- XSS: injects a canary string into URL parameters, checks if it appears unescaped in response body, identifies rendering context

## Example Usage
```bash
python web_scanner.py --url https://example.com
python web_scanner.py --url https://example.com/search?q=test --output-json scan.json
```

## Risks & False Positives
- XSS reflection doesn't guarantee exploitability (output encoding may still apply)
- CORS "misconfiguration" may be intentional for public APIs
- Some headers are only relevant for HTML responses, not APIs

## Limitations
- Single-page scan; doesn't crawl or discover endpoints
- No JavaScript rendering (misses DOM XSS)
- Cannot bypass WAFs or authentication

## Interview Talking Points
- "I check XSS context (HTML body vs attribute vs JS) because the exploit payload differs for each"
- "CORS with credentials is the critical check — wildcard alone isn't always dangerous"
- "This represents the 'quick scan' phase before deeper manual testing"
