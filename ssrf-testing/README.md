# SSRF Detection Tester

## Problem Statement
SSRF (Server-Side Request Forgery) lets attackers make the server perform internal network requests, exposing private services and cloud metadata credentials. It's a critical vulnerability in cloud environments.

## Threat Model
- **Attacker**: External user who can supply URLs to server-side fetchers (image importers, webhooks, PDF generators)
- **Techniques**: Internal IP injection, bypass encodings, cloud metadata access
- **Goal**: Access internal services, steal IAM credentials, read local files

## What the Tool Does
Injects 14 categorized payloads and compares responses against a safe baseline:
1. **Localhost variants** — 127.0.0.1, localhost, decimal IP, hex IP, octal, IPv6, shortened
2. **Cloud metadata** — AWS (169.254.169.254), Azure IMDS, GCP metadata
3. **Private networks** — 10.x, 192.168.x
4. **Protocol tricks** — file://, DNS rebinding (nip.io)

Multi-signal analysis: timing, size, status, content keywords, errors.

## Detection Logic
- Establish baseline with safe external URL (example.com)
- Send each payload and measure response time, size, status, content
- Compare against baseline: timing delta >800ms, size delta >200 bytes, status change
- Scan response body for metadata keywords (iam, access-key, token, etc.)
- Categorize payloads by what WAF bypass they test

## Example Usage
```bash
python ssrf_tester.py --url "https://target/api/fetch" --param url
python ssrf_tester.py --url "https://target/api/fetch" --param url --cookie "sess=abc" --output-json report.json
```

## Risks & False Positives
- Network jitter causes timing false positives
- Some apps sanitize all URLs uniformly (no differential signal)
- Bypass encodings may trigger WAF alerts in production

## Limitations
- Detection-only; does not exfiltrate data or exploit
- Cannot confirm blind SSRF without out-of-band channels
- POST body injection requires --method POST

## Interview Talking Points
- "I test bypass encodings because WAFs often block '127.0.0.1' literally but miss decimal (2130706433)"
- "Cloud metadata SSRF is critical — one request can steal IAM tokens with full AWS account access"
- "IMDSv2 mitigates basic SSRF by requiring a PUT-based token before metadata access"
- "Baseline comparison reduces false positives — timing is only meaningful relative to known-safe"
