# File Upload Vulnerability Tester

## Problem Statement
Unrestricted file upload (OWASP A04) can lead to remote code execution if attackers upload web shells. Upload filters often check only one signal (extension OR MIME type), which is trivially bypassed.

## Threat Model
- **Attacker**: Web attacker with access to a file upload form
- **Techniques**: Dual extensions, MIME mismatch, polyglot files, .htaccess upload
- **Goal**: Upload executable code (web shell) and gain server-side code execution

## What the Tool Does
Submits 12 attack test cases against an upload endpoint:
1. Baseline (normal upload)
2. Dual extension (.jpg.php)
3. Alternative PHP extension (.phtml)
4. Null-byte injection (%00)
5. Case variation (.PhP)
6. MIME mismatch (image filename + PHP content-type)
7. Reverse mismatch (.php filename + image MIME)
8. Polyglot (valid JPEG magic bytes + embedded PHP)
9. .htaccess upload (reconfigures Apache)
10. SVG with XSS (stored XSS via inline JavaScript)
11. JSP extension (Java servers)
12. Long filename (truncation attack)

Then analyzes responses for acceptance signals.

## Detection Logic
- Send multipart upload with crafted filename + content-type
- Check HTTP status (2xx = likely accepted)
- Scan response body for success/rejection keywords
- Assign severity based on what was accepted (PHP shell = HIGH, SVG XSS = MED)

## Example Usage
```bash
python upload_tester.py --url https://target/upload --file photo.jpg
python upload_tester.py --url https://target/upload --file photo.jpg --cookie "session=abc" --output-json report.json
python upload_tester.py --generate-sample
```

## Risks & False Positives
- HTTP 200 doesn't always mean file was stored (some apps return 200 with error in body)
- Cannot confirm execution without browsing the uploaded URL
- Some test cases may trigger WAF alerts

## Limitations
- Cannot verify server-side execution
- Auth-protected endpoints require --cookie or --header
- Doesn't test content-length limits or chunked upload bypasses

## Interview Talking Points
- "Polyglot files pass magic-byte validation but still contain executable code"
- ".htaccess upload is devastating because it can make ANY extension executable"
- "Defense requires layered checks: extension allowlist + magic bytes + re-encoding + storage isolation"
- "I test 12 vectors because real filters often block one technique but miss others"
