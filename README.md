# 🛡️ Security Tools Portfolio

> **"Why should you hire me as a security engineer?"**

This repository contains **14 production-quality security tools** I built to simulate real-world application and infrastructure security assessments. Each tool is CLI-based, interview-explainable, and grounded in real AppSec & Blue Team scenarios.

**The focus is on:**
- 🔍 Detection over exploitation
- 🗣️ Clear explainability to developers and stakeholders
- 🛡️ Defense-aware testing
- ⚙️ Engineering discipline (modular code, clean outputs, documentation)

---

## 🎯 Security Domains Covered

| Domain | Tools | Story |
|--------|-------|-------|
| **🔐 Identity & Access** | JWT Analyzer, Rate Limit Simulator, Auth Flow Tester, Password Analyzer | "I understand auth end-to-end — implementation, abuse, and defense." |
| **🌐 Web Application Security** | Web Scanner, Input Fuzzer, File Upload Tester, Headers Checker, Cookie Analyzer | "I test modern web apps the way AppSec teams do." |
| **☁️ Cloud & Infrastructure** | S3 Bucket Checker, SSRF Tester | "I understand cloud-native attack surfaces." |
| **🛡️ Defensive / Blue Team** | Log Analyzer, Simple IDS, HTTP Flow Visualizer | "I think like a defender, not just an attacker." |

---

## 📂 Repository Structure

Each folder = one security problem domain. Each tool:
- Has a **README** with problem statement, threat model, detection logic, and interview talking points
- Is **CLI-based** with `argparse` for professional usage
- **Explains detection logic** in comments (why, not just what)
- Includes **sample output** and **limitations**

```
security-tools-portfolio/
├── 01-log-analysis/          Log Analyzer + Anomaly Detection
├── 02-web-scanner/           Web Security Scanner (headers, XSS, CORS)
├── 03-jwt-analysis/          JWT Token Analyzer
├── 04-cloud-misconfig/       Cloud Bucket Exposure Checker (AWS/GCS/Azure)
├── 05-input-fuzzing/         Input Fuzzer (SQLi, XSS, SSTI, path traversal)
├── 06-rate-limiting/         Rate Limit / Brute Force Simulator
├── 07-http-visibility/       HTTP Flow Visualizer (redirects, cookies)
├── 08-cookie-security/       Cookie Security Analyzer
├── 09-password-security/     Password Strength + Hash Analyzer
├── 10-intrusion-detection/   Simple IDS (signature + anomaly)
├── 11-file-upload-testing/   File Upload Vulnerability Tester
├── 12-ssrf-testing/          SSRF Detection Tester
├── 13-auth-flow-testing/     Auth Flow Tester (fixation, reuse, invalidation)
├── 14-headers-hardening/     Security Headers Hardening Checker
└── README.md                 ← You are here
```

---

## 🧰 Tools Overview

| # | Tool | Key Features | Language |
|---|------|-------------|----------|
| 01 | **Log Analyzer** | Brute-force, password spray, credential stuffing, ML anomaly (IsolationForest), signal correlation | Python |
| 02 | **Web Scanner** | HTTPS/TLS, 6 security headers, weak CSP, CORS misconfiguration, XSS reflection | Python |
| 03 | **JWT Analyzer** | alg=none, HS/RS confusion, jku/jwk injection, lifetime analysis, sensitive data scan | Python |
| 04 | **S3 Checker** | AWS/GCS/Azure, LIST/READ/WRITE/ACL, static hosting, batch mode | Python |
| 05 | **Input Fuzzer** | 5 payload categories, SQL error signatures, SSTI, timing anomaly, WAF detection | Python |
| 06 | **Rate Limit Simulator** | Form + JSON, success detection, Retry-After parsing, safety cap | Python |
| 07 | **HTTP Flow Visualizer** | Redirect chain, cookie jar tracking, cookie change detection, colorized output | Python |
| 08 | **Cookie Analyzer** | Per-cookie parsing, SameSite/Secure/HttpOnly, __Host- prefix, domain scope, lifetime | Python |
| 09 | **Password Analyzer** | Entropy estimation, crack time calculation, bcrypt vs SHA-256 demo, pattern detection | Python |
| 10 | **Simple IDS** | Signature rules + anomaly (z-score/ML), MITRE ATT&CK mapping, sample log generator | Python |
| 11 | **Upload Tester** | 12 attack vectors (dual ext, polyglot, .htaccess, SVG XSS), response analysis | Python |
| 12 | **SSRF Tester** | 14 payloads (bypass encodings), metadata keyword detection, multi-signal analysis | Python |
| 13 | **Auth Flow Tester** | Session fixation, token reuse, missing invalidation, post-logout access, entropy check | Python |
| 14 | **Headers Checker** | 10 headers, weak-value analysis, letter grade A–F, info leakage detection | Python |

---

## 🚀 Quick Start

All tools are single-file Python scripts with no mandatory external dependencies.

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/security-tools-portfolio.git
cd security-tools-portfolio

# Run any tool
python 01-log-analysis/log_analyzer.py --help
python 14-headers-hardening/headers_checker.py --url https://example.com
python 10-intrusion-detection/simple_ids.py --generate-sample sample.log
```

**Optional dependencies** (for ML features):
```bash
pip install scikit-learn bcrypt
```

---

## 🎓 Interview Positioning

### "Tell me about a security project you built."

> "I built a portfolio of 14 security assessment tools covering AppSec, cloud security, identity, and blue team operations. Each tool is designed the way I'd build internal tooling at a security team — modular, CLI-driven, with clear detection logic and limitations documented. For example, my IDS uses both signature rules with MITRE ATT&CK mapping and statistical anomaly detection, which mirrors how real SOC tooling works."

### "How do you think about false positives?"

> "Every tool I built includes a 'Limitations' section because I believe responsible security testing means understanding what you CAN'T detect. My SSRF tester uses baseline comparison to reduce false positives — timing deltas are only meaningful relative to a known-safe request."

### "Do you understand defense, not just offense?"

> "Absolutely. My Log Analyzer and IDS are purely defensive tools. My Headers Checker doesn't just flag missing headers — it grades the existing values and explains WHY weak CSP with unsafe-inline defeats the purpose. I always include remediation advice because findings without fixes aren't useful."

---

## 📝 Design Principles

1. **Detection over exploitation** — Tools identify risks; they don't weaponize them
2. **Explain the "why"** — Comments explain security reasoning, not just code mechanics
3. **Production patterns** — argparse CLI, JSON output, error handling, dataclasses
4. **Interview-ready** — Each tool can be explained in 2-3 minutes with threat model + limitations
5. **No external dependencies** — Core functionality works with Python stdlib only

---

## 📜 License

This portfolio is for educational and professional demonstration purposes.
Tools are detection-only and should only be used against systems you own or have authorization to test.
