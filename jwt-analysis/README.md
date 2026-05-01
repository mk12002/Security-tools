# JWT Token Analyzer

## Problem Statement
JWTs are used everywhere for stateless auth, but misconfigured tokens enable signature bypass, privilege escalation, and token forgery. Many developers don't understand the security implications of algorithm choices.

## Threat Model
- **Attacker**: Authenticated user attempting privilege escalation, or attacker with a captured token
- **Techniques**: Algorithm confusion (alg=none, HS/RS), header injection (jku/jwk/x5u), signature stripping
- **Goal**: Forge tokens, escalate privileges, or extend session lifetime

## What the Tool Does
Decodes and analyzes JWT tokens for known vulnerabilities:
1. Header/payload decode and display
2. Algorithm confusion checks (alg=none, HS256 on RS256-signed tokens)
3. Header injection vectors (jku, jwk, x5u, kid)
4. Signature presence/absence detection
5. Lifetime analysis (exp, iat, nbf validation)
6. Sensitive data detection in payload (passwords, SSNs, emails)
7. Sample vulnerable token generator for testing

## Detection Logic
- Decode base64url header → check `alg` field against known-weak values
- Check for injectable header fields that can redirect key verification
- Validate time claims against current time with configurable skew
- Scan payload values against sensitive data regex patterns

## Example Usage
```bash
python jwt_analyzer.py --token "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0."
python jwt_analyzer.py --generate-sample
```

## Risks & False Positives
- A token using HS256 isn't necessarily vulnerable — it depends on key management
- "Sensitive data" detection may flag non-sensitive fields with similar patterns
- Expired tokens may be intentionally expired (not a current vulnerability)

## Limitations
- Cannot verify signatures without the secret/public key
- Does not test actual exploitation (doesn't send forged tokens to servers)
- Custom claim validation logic is application-specific

## Interview Talking Points
- "The alg=none attack works because some libraries trust the token's own algorithm claim"
- "HS/RS confusion exploits libraries that use the public key as HMAC secret"
- "jku injection lets attackers point verification to their own key server"
- "I always check nbf (not-before) because premature token use indicates replay"
