# Input Fuzzer

## Problem Statement
Input validation flaws (SQLi, XSS, SSTI, path traversal, command injection) remain the top web vulnerability class. Fuzzing parameters with known-bad payloads quickly identifies weak input handling.

## Threat Model
- **Attacker**: Web attacker targeting form fields, URL parameters, or API inputs
- **Techniques**: Injection payloads crafted to trigger errors or unexpected behavior
- **Goal**: Achieve code execution, data extraction, or file system access

## What the Tool Does
Sends categorized attack payloads to target parameters and analyzes responses:
1. **SQLi** — error-based detection via database error signatures
2. **XSS** — reflection detection (payload appears in response)
3. **SSTI** — template expression evaluation (e.g., 49 appears for {{7*7}})
4. **Path traversal** — sensitive file content detection (/etc/passwd markers)
5. **Command injection** — OS command output detection

Plus: baseline comparison, timing anomaly detection, WAF detection, custom payload files.

## Detection Logic
- Send baseline request → record status, size, timing
- Send each payload → compare response against baseline
- SQLi: regex match against 20+ database error patterns (MySQL, PostgreSQL, MSSQL, Oracle)
- XSS: check if exact payload string appears in response body
- SSTI: check if computed result (e.g., "49") appears when "{{7*7}}" was sent
- Timing: flag responses >2x baseline as potential blind injection

## Example Usage
```bash
python input_fuzzer.py --url "https://target/search" --param q
python input_fuzzer.py --url "https://target/api" --param id --payloads custom.txt
```

## Risks & False Positives
- XSS reflection doesn't guarantee exploitability (encoding may prevent execution)
- Timing anomalies can be network jitter, not injection
- SSTI "49" could appear naturally in page content

## Limitations
- No DOM-based detection (requires JavaScript rendering)
- Blind SQLi requires timing analysis which is noisy
- Single-parameter testing; doesn't test parameter interaction

## Interview Talking Points
- "I use 5 payload categories because each targets a different vulnerability class"
- "Baseline comparison is critical — without it, you can't distinguish anomalies from normal behavior"
- "WAF detection matters because it changes how you interpret blocked responses"
- "Error-based SQLi is the easiest to detect; blind SQLi needs timing or out-of-band channels"
