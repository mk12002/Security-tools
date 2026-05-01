# HTTP Flow Visualizer

## Problem Statement
Authentication and redirect flows are opaque in standard tools. Understanding exactly which cookies are set, modified, or lost during multi-step HTTP flows is critical for security testing.

## Threat Model
- **Attacker**: Session hijacker observing redirect chains, or analyst investigating auth flow behavior
- **Techniques**: Cookie manipulation, open redirect exploitation, session fixation via redirects
- **Goal**: Understand the complete request/response lifecycle for security analysis

## What the Tool Does
Follows HTTP redirect chains step-by-step and visualizes:
1. Each hop's request headers (including cookies sent)
2. Each hop's response status, headers, and Set-Cookie directives
3. Cookie jar state changes between hops (+new, ~changed, -removed)
4. Authentication header highlighting
5. Colorized terminal output for readability

## Detection Logic
- Issues initial request and follows 3xx redirects manually (not via urllib auto-redirect)
- Maintains a cookie jar and tracks per-hop changes
- Compares cookie values between hops to detect modifications
- Highlights security-relevant headers (Authorization, Set-Cookie)

## Example Usage
```bash
python http_flow_visualizer.py --url https://target/login --follow
python http_flow_visualizer.py --url https://target/oauth/callback --color
```

## Risks & False Positives
- Cookie changes may be normal application behavior (not necessarily a vulnerability)
- Redirect chains may behave differently with/without JavaScript

## Limitations
- No JavaScript rendering (cannot follow JS-based redirects)
- Cookie parsing uses SimpleCookie which may miss edge cases
- Cannot visualize WebSocket or streaming connections

## Interview Talking Points
- "I built this because understanding the HTTP lifecycle is fundamental to security testing"
- "Cookie change tracking between redirects helps identify session fixation opportunities"
- "Open redirects in OAuth flows can lead to token theft — this tool makes the chain visible"
- "This is the manual equivalent of Burp Suite's request/response history"
