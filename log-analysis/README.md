# Log Analyzer + Anomaly Detection

## Problem Statement
Security teams drown in log data. Attackers hide in volume — brute-force attempts, password sprays, and credential stuffing blend into thousands of legitimate auth events. Manual review doesn't scale.

## Threat Model
- **Attacker**: External actor attempting credential access via automated tools
- **Techniques**: Brute force (many passwords, one user), password spray (one password, many users), credential stuffing (leaked username:password pairs)
- **Goal**: Gain unauthorized access to accounts

## What the Tool Does
Parses SSH/syslog/key-value/JSON logs and applies multiple detection engines:
1. **Brute-force detection** — repeated failures from one IP against one user
2. **Password spray detection** — single IP targeting many users with few attempts each
3. **Credential stuffing detection** — many unique user+IP pairs failing simultaneously
4. **Behavioral anomaly** — unusual hour-of-day activity per user
5. **ML anomaly** — IsolationForest on per-IP feature vectors (optional sklearn)
6. **Signal correlation** — combines multiple weak signals into high-confidence alerts

## Detection Logic
1. Parse each log line into structured events (IP, user, status, timestamp)
2. Aggregate events into per-IP and per-user statistics
3. Apply threshold-based rules (e.g., >5 failures in 5 minutes)
4. Apply statistical/ML outlier detection on feature vectors
5. Correlate: if an IP triggers both spray AND anomaly, elevate to HIGH

## Example Usage
```bash
python log_analyzer.py --logfile /var/log/auth.log --output-json report.json
python log_analyzer.py --generate-sample sample.log
```

## Risks & False Positives
- Shared IPs (NAT/VPN) can trigger brute-force alerts for legitimate users
- Password spray thresholds need tuning per environment
- ML anomaly detection needs sufficient data volume (>100 events)

## Limitations
- No real-time streaming; processes complete log files
- Timestamp parsing is best-effort across formats
- Cannot determine if an attack succeeded (only flags attempts)

## Interview Talking Points
- "I chose IsolationForest because it handles high-dimensional outliers without labeled data"
- "Signal correlation reduces false positives by requiring multiple weak indicators"
- "Password spray is harder to detect than brute force because per-user attempt counts stay low"
- "This mirrors how SIEM correlation rules work in production SOCs"
