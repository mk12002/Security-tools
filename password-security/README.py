# Password Strength + Hash Analyzer

## Problem Statement
Weak passwords and fast hashing algorithms are the root cause of most credential breaches. Understanding entropy, crack time, and hash cost is fundamental to secure system design.

## Threat Model
- **Attacker**: Offline attacker with leaked password hashes and GPU hardware
- **Techniques**: Dictionary attacks, rule-based cracking, brute-force with hashcat/john
- **Goal**: Recover plaintext passwords from hashed values

## What the Tool Does
Analyzes a password's strength and demonstrates hashing security:
1. **Entropy estimation** — character class pool × length
2. **Pattern detection** — common words, keyboard walks, dates, sequences, leetspeak
3. **Crack time estimation** — at SHA-256 GPU speed (10B/s) and bcrypt speed (100/s)
4. **Hash demonstration** — MD5, SHA-256, salted SHA-256, and bcrypt side-by-side
5. **Slowdown factor** — shows how many times slower bcrypt is than SHA-256
6. **Salt demonstration** — proves identical passwords hash differently with unique salts

## Detection Logic
- Entropy = len(password) × log2(character_pool_size)
- Patterns reduce effective entropy via heuristic penalties
- Crack time = 2^entropy / (2 × guesses_per_second)
- Multiple pattern detectors: seasonal words, keyboard walks, sequential chars, dates

## Example Usage
```bash
python password_analyzer.py --password "Summer2024!"
python password_analyzer.py --password "correct horse battery staple" --output-json report.json
```

## Risks & False Positives
- Entropy overestimates patterned passwords (theoretical vs effective entropy)
- Crack time assumes specific hardware; cloud attackers may have more
- Pattern detection is heuristic and may miss custom patterns

## Limitations
- No dictionary file bundled; uses heuristic pattern matching
- Cannot evaluate server-side controls (lockout, MFA)
- Does not test actual hash cracking

## Interview Talking Points
- "Fast hashes are dangerous because 10B guesses/sec on GPU means 8-char passwords fall in hours"
- "bcrypt's cost parameter doubles attacker time for each increment — cost=12 means ~100 hashes/sec"
- "Rainbow tables are defeated by unique per-user salts — bcrypt includes salt automatically"
- "I recommend Argon2id > bcrypt > scrypt for new systems; PBKDF2 is acceptable with high iterations"
