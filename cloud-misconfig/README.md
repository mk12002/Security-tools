# Cloud Bucket Exposure Checker

## Problem Statement
Misconfigured cloud storage buckets (AWS S3, GCS, Azure Blob) are one of the most common causes of data breaches. Companies accidentally leave sensitive data publicly accessible.

## Threat Model
- **Attacker**: Internet-wide scanner (like GrayhatWarfare) probing for open buckets
- **Techniques**: Unauthenticated LIST/READ/WRITE requests to predictable bucket names
- **Goal**: Access sensitive data (PII, credentials, backups) or upload malicious content

## What the Tool Does
Tests cloud storage buckets across three providers for:
1. Public LIST access (directory listing)
2. Public READ access (file download)
3. Public WRITE access (upload test — non-destructive)
4. ACL exposure (permission metadata readable)
5. Static website hosting enabled (increases discoverability)
6. Batch mode for testing multiple buckets from a file

## Detection Logic
- Constructs provider-specific URLs (s3.amazonaws.com, storage.googleapis.com, blob.core.windows.net)
- Sends unauthenticated HTTP requests and interprets status codes
- 200 on LIST = public directory; 200 on GET = public read; 200 on PUT = public write
- Checks for XML/JSON responses indicating ACL exposure

## Example Usage
```bash
python s3_checker.py --bucket my-company-backups --provider aws
python s3_checker.py --bucket-file targets.txt --output-json results.json
```

## Risks & False Positives
- Some buckets are intentionally public (static websites, open datasets)
- 403 doesn't always mean "secure" — it may mean "exists but restricted"
- WRITE test uses a harmless probe file but should still only target owned buckets

## Limitations
- Cannot test authenticated access (would need AWS/GCP/Azure credentials)
- Doesn't check bucket policies or IAM roles
- Regional detection is heuristic for AWS

## Interview Talking Points
- "I check all three major cloud providers because organizations use multi-cloud"
- "The difference between 403 and 404 leaks bucket existence — useful for enumeration"
- "Static hosting check matters because it means the bucket is web-accessible by design"
- "Real breaches (Capital One, Twitch) started with misconfigured bucket access"
