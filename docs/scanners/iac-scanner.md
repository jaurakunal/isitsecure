# IaC Scanner

**Type:** SAST | **Severity:** Low–Critical | **Category:** Infrastructure Misconfiguration

## What It Does

Scans Terraform files (`.tf` and `.tfvars`; AWS resources only, CloudFormation is not read) with regular expressions over the file text:

- **Open security group ingress** — `0.0.0.0/0` or `::/0` on any port except 80 and 443 (High)
- **Overly permissive IAM** — wildcard action `"*"` (High) or wildcard resource `"*"` (Medium)
- **Hardcoded secrets** — secret-shaped values (cloud keys, API keys, database URLs, JWTs) in variable `default` values (Critical)
- **Public S3 buckets** — `acl = "public-read"` or `"public-read-write"` (High)
- **Secrets Manager** — `recovery_window_in_days = 0` (Medium)
- **ALB HTTP listener** — an HTTP listener that forwards instead of redirecting to HTTPS (Medium)
- **ECS public IP** — `assign_public_ip = true` (Low)
- **Short log retention** — CloudWatch `retention_in_days` of 7 or fewer (Low)

Not covered today: unencrypted storage, missing S3 public access blocks, CloudTrail/VPC Flow Log checks and default VPC usage.

## Why It Matters

Infrastructure misconfigurations are the root cause of most cloud data breaches:
- Public S3 buckets have leaked data from hundreds of companies
- Overly permissive IAM roles let attackers escalate from one compromised service to full account control
- Missing encryption means stolen backups or snapshots expose all data

## Real-World Breaches

Public S3 buckets have exposed data from hundreds of companies. Notable examples include **Twitch (2021)** — an AWS misconfiguration contributed to the leak of Twitch's entire source code and payout data. **Accenture (2017)** — four AWS S3 buckets were left public, exposing secret API data, authentication credentials, and decryption keys.

## How to Fix

```hcl
# GOOD: Private S3 bucket with encryption
resource "aws_s3_bucket" "data" {
  bucket = "my-app-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```
