# Simple IDS (Intrusion Detection System)

## Problem Statement
Organizations need to detect attacks in progress. A basic IDS scans logs for known-bad signatures and statistical anomalies, generating alerts for SOC analyst triage.

## Threat Model
- **Attacker**: External or internal actor conducting reconnaissance, brute force, or injection attacks
- **Techniques**: Port scanning, credential stuffing, SQLi/XSS payloads, known scanner tools
- **Goal**: Gain unauthorized access or exfiltrate data

## What the Tool Does
Processes web/server logs through two detection engines:
1. **Signature engine** — rule-based pattern matching:
   - Brute-force failures (repeated 401/403)
   - Scanning behavior (many unique paths from one IP)
   - Attack payloads in URLs (SQLi, XSS, path traversal, command injection)
   - Known scanner user-agents (nikto, sqlmap, gobuster)
   - Sensitive endpoint probing (/admin, /.git, /.env)
2. **Anomaly engine** — statistical outlier detection:
   - Z-score on request volume and path diversity
   - Optional IsolationForest ML model
3. **Alert generator** — deduplicates, prioritizes, adds MITRE ATT&CK mapping

## Detection Logic
- Parse logs (CLF, JSON, key-value formats supported)
- Aggregate per-IP statistics (total, unique paths, error rate, methods)
- Apply threshold rules → generate signature alerts
- Compute z-scores or ML outlier scores → generate anomaly alerts
- Deduplicate by (category, IP) and sort by severity

## Example Usage
```bash
python simple_ids.py --generate-sample sample.log
python simple_ids.py --logfile sample.log --output-json alerts.json
python simple_ids.py --logfile access.log --ruleset rules.json
```

## Risks & False Positives
- Legitimate crawlers (Googlebot) may trigger scanning alerts
- Shared IPs (corporate NAT) inflate per-IP request counts
- Anomaly engine needs >50 events to produce meaningful results

## Limitations
- Passive alerting only; does not block or respond
- Log format parsing is best-effort
- Real IDS (Snort/Suricata) inspects packets, not just logs

## Interview Talking Points
- "Signature IDS has low false positives for known patterns but misses zero-days"
- "Anomaly IDS catches novel attacks but needs baseline tuning per environment"
- "MITRE ATT&CK mapping helps analysts understand attacker intent and prioritize response"
- "I deduplicate by (category, IP) because SOC analysts triage by source, not by event"
