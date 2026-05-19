# IaC Scanner

**Type:** SAST | **Severity:** High–Critical | **Category:** Infrastructure Misconfiguration

## What It Does

Scans Infrastructure as Code files (Terraform, CloudFormation) for:

- **Public S3 buckets** — `acl = "public-read"` or missing public access blocks
- **Unencrypted storage** — S3 buckets and RDS instances without encryption at rest
- **Overly permissive IAM** — `Action: "*"` or `Resource: "*"` in IAM policies
- **Missing logging** — CloudTrail, VPC Flow Logs, S3 access logging disabled
- **Default VPC usage** — resources deployed in the default VPC

## Why It Matters

Infrastructure misconfigurations are the root cause of most cloud data breaches:
- Public S3 buckets have leaked data from hundreds of companies
- Overly permissive IAM roles let attackers escalate from one compromised service to full account control
- Missing encryption means stolen backups or snapshots expose all data

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
