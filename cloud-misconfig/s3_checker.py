"""
TOOL 4 — Cloud Bucket Exposure Checker
=======================================
A production-quality CLI tool to assess cloud storage bucket exposure using
safe, non-invasive HTTP checks. Supports AWS S3, Google Cloud Storage (GCS),
and Azure Blob Storage.

How S3 / cloud bucket public access works (interview-ready):
- Buckets can be public via bucket policies, ACLs, or provider-level settings.
- Exposure can be split into LIST (enumerate objects), READ (download objects),
  WRITE (upload / overwrite objects), and ACL-readable (see permission grants).
- AWS "Block Public Access", GCP "Uniform Bucket-Level Access", and Azure
  "Disable Blob Public Access" are meant to prevent this, but misconfigurations
  still happen.

Real-world breach examples (high level, for interview context):
- Capital One (2019): misconfigured WAF + S3 role exposed 100M+ records.
- Twitch (2021): misconfigured server exposed 125 GB of source code via storage.
- Multiple healthcare/voter-data leaks traced to public S3 LIST + READ.

Usage examples:
  python s3_bucket_checker.py --bucket-name my-company-logs
  python s3_bucket_checker.py --bucket-name my-bucket --region eu-west-1
  python s3_bucket_checker.py --bucket-name my-gcs-bucket --provider gcs
  python s3_bucket_checker.py --bucket-name myaccount --container pics --provider azure
  python s3_bucket_checker.py --bucket-list buckets.txt --output-json report.json

Sample output:
------------------------------------------------
=== Cloud Bucket Exposure Check ===
  Provider : aws
  Bucket   : my-company-logs
  Region   : us-east-1 (auto-detected)
  URL      : https://my-company-logs.s3.us-east-1.amazonaws.com

  [HIGH] Public LIST    : YES — bucket contents (object names) are visible
  [HIGH] Public READ    : YES — objects can be downloaded by anyone
  [HIGH] Public WRITE   : YES — anyone can upload or overwrite objects
  [MED]  Public ACL     : YES — permission grants are visible
  [MED]  Static hosting : YES — bucket is configured as a website

Remediation:
  - Enable S3 Block Public Access at account + bucket level
  - Remove public ACL grants (AllUsers / AuthenticatedUsers)
  - Restrict bucket policy to specific IAM principals
  - Disable static website hosting unless intentional

Limitations:
- HTTP checks confirm exposure but cannot inspect IAM policies.
- 403 may mean "private" or "exists but this specific action is denied".
- Public read is hard to prove without a known object key; we infer from listing.
- Write check uploads a tiny test object; delete it manually if found.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import ssl
import string
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    level: str      # LOW / MED / HIGH
    check: str      # e.g. "Public LIST"
    result: bool    # True = exposed
    detail: str     # human explanation


@dataclass
class BucketReport:
    provider: str
    bucket: str
    region: str
    url: str
    exists: bool
    findings: List[Finding]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
# Shared SSL context — verifies certs but works broadly
_SSL_CTX = ssl.create_default_context()


def _http_request(
    url: str, method: str = "GET", data: Optional[bytes] = None, timeout: int = 8
) -> Tuple[int, Dict[str, str], str]:
    """Perform an HTTP request and return (status, headers_dict, body).

    Why a single helper: all checks need consistent timeout, SSL, and error
    handling. Centralizing prevents silent failures.
    """
    req = urllib.request.Request(url, method=method, data=data)
    try:
        handler = urllib.request.HTTPSHandler(context=_SSL_CTX)
        opener = urllib.request.build_opener(handler)
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(256_000).decode("utf-8", errors="ignore")
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, headers, body
    except Exception:
        return 0, {}, ""


# ---------------------------------------------------------------------------
# Provider URL builders
# ---------------------------------------------------------------------------
def _s3_url(bucket: str, region: Optional[str]) -> str:
    if region:
        return f"https://{bucket}.s3.{region}.amazonaws.com"
    return f"https://{bucket}.s3.amazonaws.com"


def _gcs_url(bucket: str) -> str:
    return f"https://storage.googleapis.com/{bucket}"


def _azure_url(account: str, container: Optional[str]) -> str:
    """Azure Blob: account is the storage account, container is optional."""
    if container:
        return f"https://{account}.blob.core.windows.net/{container}"
    return f"https://{account}.blob.core.windows.net/$web"


# ---------------------------------------------------------------------------
# S3-specific checks
# ---------------------------------------------------------------------------
def _s3_auto_detect_region(bucket: str) -> Optional[str]:
    """Auto-detect region from S3 redirect headers.

    Why: S3 returns a 301 with an x-amz-bucket-region header when the
    request hits the wrong regional endpoint. This avoids requiring the
    user to know the region upfront.
    """
    status, headers, _ = _http_request(f"https://{bucket}.s3.amazonaws.com", method="HEAD")
    region = headers.get("x-amz-bucket-region")
    if region:
        return region
    # Some 403s also include the header
    if status in (301, 307, 403) and "x-amz-bucket-region" in headers:
        return headers["x-amz-bucket-region"]
    return None


def _check_exists(url: str) -> bool:
    """Check if a bucket exists. 404 = no; 403/301/307/200 = yes."""
    status, _, _ = _http_request(url, method="HEAD")
    return status in (200, 301, 307, 403)


def _check_public_list(url: str, provider: str) -> Tuple[bool, str, List[str]]:
    """Check if bucket listing is public. Returns (exposed, detail, sample_keys).

    Why we extract sample keys: if listing works, we can use a real key to
    test public READ — much more reliable than guessing random keys.
    """
    if provider == "aws":
        check_url = url + "?list-type=2&max-keys=5"
        marker = "<ListBucketResult"
    elif provider == "gcs":
        check_url = url + "?max-keys=5"
        marker = "<ListBucketResult"
    elif provider == "azure":
        check_url = url + "?restype=container&comp=list&maxresults=5"
        marker = "<EnumerationResults"
    else:
        return False, "", []

    status, _, body = _http_request(check_url)
    if status == 200 and marker in body:
        # Extract a few object keys for the read check
        keys = re.findall(r"<Key>([^<]+)</Key>", body)[:3]
        if not keys:
            keys = re.findall(r"<Name>([^<]+)</Name>", body)[:3]
        count_match = re.search(r"<KeyCount>(\d+)</KeyCount>", body)
        count = count_match.group(1) if count_match else "unknown"
        return True, f"Listing returned {count} keys", keys
    return False, "", []


def _check_public_read(url: str, sample_keys: List[str]) -> Tuple[bool, str]:
    """Check if objects are publicly readable.

    Strategy: if we have real keys from listing, test one. Otherwise test
    a random key and interpret 404 as "inconclusive".
    """
    if sample_keys:
        key = sample_keys[0]
        # URL-encode the key in case it has special chars
        test_url = url.rstrip("/") + "/" + urllib.request.quote(key, safe="")
        status, _, _ = _http_request(test_url)
        if status == 200:
            return True, f'Object "{key}" is publicly downloadable'
        return False, f'Object "{key}" returned {status}'

    # No keys available — probe with a random name
    rand_key = "probe-" + "".join(random.choices(string.ascii_lowercase, k=10))
    status, _, _ = _http_request(url.rstrip("/") + "/" + rand_key)
    if status == 200:
        return True, "Random key returned 200 (unexpected — may be a catch-all)"
    if status == 404:
        return False, "Random key returned 404 (read MAY still be public but unconfirmed)"
    return False, f"Random key returned {status}"


def _check_public_write(url: str) -> Tuple[bool, str]:
    """Check if public uploads are allowed.

    Why: we upload a tiny object with a unique random name so we never
    overwrite existing data. The key starts with ".scantest-" to be
    easily identifiable and deletable.
    """
    rand_key = ".scantest-" + "".join(random.choices(string.ascii_lowercase, k=12))
    test_url = url.rstrip("/") + "/" + rand_key
    status, _, _ = _http_request(test_url, method="PUT", data=b"bucket-exposure-test")
    if status in (200, 201, 204):
        return True, f"Upload succeeded (status {status}) — object: {rand_key}"
    return False, f"Upload returned {status}"


def _check_public_acl(url: str, provider: str) -> Tuple[bool, str]:
    """Check if bucket ACL is publicly readable (AWS/GCS only).

    Why: if ?acl returns 200, anyone can see who has access. This is a
    reconnaissance goldmine for attackers.
    """
    if provider == "azure":
        return False, "ACL check not applicable for Azure Blob"
    status, _, body = _http_request(url + "?acl")
    if status == 200:
        # Look for dangerous grants
        public_grants = []
        if "AllUsers" in body:
            public_grants.append("AllUsers")
        if "AuthenticatedUsers" in body:
            public_grants.append("AuthenticatedUsers")
        if "allUsers" in body:  # GCS format
            public_grants.append("allUsers")
        if "allAuthenticatedUsers" in body:
            public_grants.append("allAuthenticatedUsers")
        detail = f"ACL readable; grants include: {', '.join(public_grants)}" if public_grants else "ACL readable (no obvious public grants)"
        return True, detail
    return False, f"ACL returned {status}"


def _check_static_hosting(bucket: str, region: Optional[str]) -> Tuple[bool, str]:
    """Check if S3 static website hosting is enabled.

    Why: website-enabled buckets serve content on a different endpoint
    (.s3-website-<region>.amazonaws.com) and behave like a web server,
    widening the attack surface.
    """
    r = region or "us-east-1"
    website_url = f"http://{bucket}.s3-website-{r}.amazonaws.com"
    status, _, _ = _http_request(website_url)
    if status in (200, 301, 302):
        return True, f"Website endpoint responds ({status})"
    return False, f"Website endpoint returned {status}"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def assess_bucket(
    bucket: str,
    provider: str = "aws",
    region: Optional[str] = None,
    container: Optional[str] = None,
) -> BucketReport:
    """Run all checks for a single bucket and return a structured report."""

    # Build base URL
    if provider == "aws":
        if not region:
            region = _s3_auto_detect_region(bucket) or "us-east-1"
        url = _s3_url(bucket, region)
    elif provider == "gcs":
        url = _gcs_url(bucket)
        region = "global"
    elif provider == "azure":
        url = _azure_url(bucket, container)
        region = "global"
    else:
        url = _s3_url(bucket, region)
        region = region or "us-east-1"

    findings: List[Finding] = []

    # Existence
    if not _check_exists(url):
        return BucketReport(provider, bucket, region or "", url, False, [])

    # LIST
    list_exposed, list_detail, sample_keys = _check_public_list(url, provider)
    findings.append(Finding(
        "HIGH" if list_exposed else "LOW",
        "Public LIST",
        list_exposed,
        list_detail if list_exposed else "Listing is not public",
    ))

    # READ (use real keys from listing when available)
    read_exposed, read_detail = _check_public_read(url, sample_keys)
    findings.append(Finding(
        "HIGH" if read_exposed else "LOW",
        "Public READ",
        read_exposed,
        read_detail,
    ))

    # WRITE
    write_exposed, write_detail = _check_public_write(url)
    findings.append(Finding(
        "HIGH" if write_exposed else "LOW",
        "Public WRITE",
        write_exposed,
        write_detail,
    ))

    # ACL
    acl_exposed, acl_detail = _check_public_acl(url, provider)
    findings.append(Finding(
        "MED" if acl_exposed else "LOW",
        "Public ACL",
        acl_exposed,
        acl_detail,
    ))

    # Static hosting (AWS only)
    if provider == "aws":
        hosting_exposed, hosting_detail = _check_static_hosting(bucket, region)
        findings.append(Finding(
            "MED" if hosting_exposed else "LOW",
            "Static hosting",
            hosting_exposed,
            hosting_detail,
        ))

    return BucketReport(provider, bucket, region or "", url, True, findings)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_report(report: BucketReport) -> None:
    """Human-readable output with severity labels."""
    print("=== Cloud Bucket Exposure Check ===")
    print(f"  Provider : {report.provider}")
    print(f"  Bucket   : {report.bucket}")
    print(f"  Region   : {report.region}")
    print(f"  URL      : {report.url}")
    print()

    if not report.exists:
        print("  Result: Bucket does not exist or is unreachable.")
        return

    exposed_any = False
    for f in report.findings:
        tag = "YES" if f.result else "NO"
        print(f"  [{f.level:4s}] {f.check:14s}: {tag} — {f.detail}")
        if f.result:
            exposed_any = True

    # Remediation
    print()
    if exposed_any:
        print("Remediation:")
        if report.provider == "aws":
            print("  - Enable S3 Block Public Access at account + bucket level")
            print("  - Remove public ACL grants (AllUsers / AuthenticatedUsers)")
            print("  - Restrict bucket policy to specific IAM principals")
            print("  - Disable static website hosting unless intentional")
        elif report.provider == "gcs":
            print("  - Enable Uniform Bucket-Level Access")
            print("  - Remove allUsers / allAuthenticatedUsers bindings")
            print("  - Use IAM Conditions for fine-grained control")
        elif report.provider == "azure":
            print("  - Set 'Allow Blob public access' to Disabled on the storage account")
            print("  - Review container access level (Private vs Blob vs Container)")
            print("  - Use Shared Access Signatures (SAS) for controlled access")
    else:
        print("  No public exposure detected from HTTP checks.")


def report_to_dict(report: BucketReport) -> dict:
    return {
        "provider": report.provider,
        "bucket": report.bucket,
        "region": report.region,
        "url": report.url,
        "exists": report.exists,
        "findings": [asdict(f) for f in report.findings],
    }


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assess cloud storage bucket exposure via safe HTTP checks",
    )
    parser.add_argument("--bucket-name", help="Single bucket name to check")
    parser.add_argument("--bucket-list", help="File with one bucket name per line (batch mode)")
    parser.add_argument("--provider", choices=["aws", "gcs", "azure"], default="aws",
                        help="Cloud provider (default: aws)")
    parser.add_argument("--region", help="AWS region (auto-detected if omitted)")
    parser.add_argument("--container", help="Azure Blob container name (Azure only)")
    parser.add_argument("--output-json", help="Write JSON report to file")

    args = parser.parse_args()

    if not args.bucket_name and not args.bucket_list:
        parser.error("Provide --bucket-name or --bucket-list")

    # Collect bucket names
    buckets: List[str] = []
    if args.bucket_name:
        buckets.append(args.bucket_name)
    if args.bucket_list:
        with open(args.bucket_list, "r") as f:
            buckets.extend(line.strip() for line in f if line.strip())

    all_reports: List[BucketReport] = []
    for bucket in buckets:
        report = assess_bucket(bucket, args.provider, args.region, args.container)
        print_report(report)
        all_reports.append(report)
        if len(buckets) > 1:
            print("\n" + "=" * 50 + "\n")

    if args.output_json:
        payload = [report_to_dict(r) for r in all_reports]
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\nJSON report written to {args.output_json}")


if __name__ == "__main__":
    main()
