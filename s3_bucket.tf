# ===================================================================
# S3 Bucket - Central Audit Log Storage (FOUNDATION)
# ===================================================================
# Security Design Decisions:
# - Single bucket = single encryption key, single lifecycle, single point of audit
# - SSE-KMS with dedicated key = envelope encryption, key rotation, audit trail on key usage
# - Versioning enabled = protection against accidental deletion, MFA delete optional
# - Bucket policies enforce TLS, deny non-encrypted puts, restrict to audit roles only
# - Lifecycle transitions to IA/Glacier/Deep Archive = Free Tier cost optimization
# - 7-year retention = common compliance requirement (SOX, PCI, etc.)
# ===================================================================

# -------------------------------------------------------------------
# KMS Key for Audit Log Encryption (Dedicated - not aws/s3 managed)
# -------------------------------------------------------------------
# WHY dedicated key:
# - Separate key policy from other services
# - Explicit key rotation (annual)
# - CloudTrail logs KMS key usage (who decrypted what, when)
# - Can restrict to specific roles/services only
# - Free Tier: 1 custom key = free, key requests = $0.03/10k

resource "aws_kms_key" "audit_logs" {
  description             = "Audit logs encryption key - ${var.environment}"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true
  multi_region            = false
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "audit-logs-key-policy"
    Statement = [
      # Root account full access (required for key management)
      {
        Sid       = "AllowRootAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      # CloudTrail service needs to encrypt log files
      {
        Sid       = "AllowCloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:Encrypt", "kms:ReEncrypt*"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${var.account_id}:trail/*"
          }
        }
      },
      # Config service needs to encrypt snapshots
      {
        Sid       = "AllowConfigEncrypt"
        Effect    = "Allow"
        Principal = { Service = "config.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:Encrypt", "kms:ReEncrypt*"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:config:arn" = "arn:${data.aws_partition.current.partition}:config:${data.aws_region.current.name}:${var.account_id}:*"
          }
        }
      },
      # GuardDuty needs to encrypt findings
      {
        Sid       = "AllowGuardDutyEncrypt"
        Effect    = "Allow"
        Principal = { Service = "guardduty.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:Encrypt", "kms:ReEncrypt*"]
        Resource  = "*"
      },
      # Member read roles need decrypt for Athena queries
      {
        Sid       = "AllowMemberRolesDecrypt"
        Effect    = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.member2_network.arn,
            aws_iam_role.member3_storage.arn,
            aws_iam_role.member4_compliance.arn,
            aws_iam_role.member5_detection.arn,
            aws_iam_role.audit_admin.arn
          ]
        }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:s3:arn" = "arn:${data.aws_partition.current.partition}:s3:::audit-logs-${var.account_id}-${var.region}/*"
          }
        }
      },
      # Allow audit admin role to manage key (if exists)
      {
        Sid       = "AllowAuditAdminManage"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${var.account_id}:role/AuditAdmin*" }
        Action    = ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListRetirableGrants"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "audit_logs" {
  name          = "alias/audit-logs-${var.environment}"
  target_key_id = aws_kms_key.audit_logs.key_id
}

# -------------------------------------------------------------------
# S3 Bucket for Centralized Audit Logs
# -------------------------------------------------------------------
# WHY single bucket with prefixes:
# - Single lifecycle policy manages all log types
# - Single bucket policy enforces encryption/TLS
# - Single KMS key encrypts everything
# - Athena can query across prefixes with partition projection
# - Easier IAM: one bucket ARN for all read roles

resource "aws_s3_bucket" "audit_logs" {
  bucket = "audit-logs-${var.account_id}-${var.region}-${random_string.bucket_suffix.result}"
  force_destroy = false  # Safety: prevent accidental destruction with logs inside
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
    # MFA delete requires MFA token on delete - enable for production
    # mfa_delete = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit_logs.arn
    }
    bucket_key_enabled = true  # Reduces KMS request costs (Free Tier friendly)
  }
}

# Block public access - audit logs must never be public
resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enforce TLS 1.2+ for all requests
resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLSRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.audit_logs.arn,
          "${aws_s3_bucket.audit_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedPuts"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyIncorrectKMSKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.audit_logs.arn
          }
        }
      },
      # Allow CloudTrail to write logs
      {
        Sid       = "AllowCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
        Action    = ["s3:PutObject", "s3:GetBucketAcl"]
        Resource  = [
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/*",
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/AWSLogs/${var.account_id}/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      # Allow Config to write snapshots
      {
        Sid       = "AllowConfigWrite"
        Effect    = "Allow"
        Principal = { Service = "config.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
        Action    = ["s3:PutObject", "s3:GetBucketAcl"]
        Resource  = [
          "${aws_s3_bucket.audit_logs.arn}/config/*",
          "${aws_s3_bucket.audit_logs.arn}/config/snapshots/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      # Allow GuardDuty to write findings
      {
        Sid       = "AllowGuardDutyWrite"
        Effect    = "Allow"
        Principal = { Service = "guardduty.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
        Action    = ["s3:PutObject"]
        Resource  = "${aws_s3_bucket.audit_logs.arn}/guardduty/*"
      },
      # Allow VPC Flow Logs to write
      {
        Sid       = "AllowVPCFlowLogsWrite"
        Effect    = "Allow"
        Principal = { Service = "vpc-flow-logs.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
        Action    = ["s3:PutObject"]
        Resource  = "${aws_s3_bucket.audit_logs.arn}/vpc/*"
      },
      # Allow ELB to write access logs
      {
        Sid       = "AllowELBWrite"
        Effect    = "Allow"
        Principal = { Service = "elasticloadbalancing.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
        Action    = ["s3:PutObject"]
        Resource  = "${aws_s3_bucket.audit_logs.arn}/elb/*"
      }
    ]
  })
}

# -------------------------------------------------------------------
# Lifecycle Configuration (Cost Optimization for Free Tier)
# -------------------------------------------------------------------
# WHY these transitions:
# - Standard -> IA after 30 days: logs rarely accessed after 30 days
# - IA -> Glacier after 90 days: compliance requires retention, rarely queried
# - Glacier -> Deep Archive after 365 days: long-term cold storage
# - Delete after 7 years: common compliance (SOX, PCI, HIPAA)
# - Free Tier: 5GB Standard free, transitions reduce cost to ~$1/TB/month

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    id     = "audit-logs-lifecycle"
    status = "Enabled"
    filter {
      prefix = ""  # Apply to all objects
    }
    transition {
      days          = var.retention_days_standard
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = var.retention_days_glacier
      storage_class = "GLACIER"
    }
    transition {
      days          = var.retention_days_deep_archive
      storage_class = "DEEP_ARCHIVE"
    }
    expiration {
      days = var.retention_days_delete
    }
    noncurrent_version_expiration {
      noncurrent_days = var.retention_days_delete
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# -------------------------------------------------------------------
# Bucket Logging (Audit the Audit Bucket)
# -------------------------------------------------------------------
# WHY: Meta-auditing - who accessed the audit logs bucket?
# Logs go to same bucket under /bucket-access-logs/ prefix

resource "aws_s3_bucket_logging" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  target_bucket = aws_s3_bucket.audit_logs.id
  target_prefix = "bucket-access-logs/"
}

# -------------------------------------------------------------------
# Outputs for downstream modules
# -------------------------------------------------------------------
output "bucket_id" {
  value       = aws_s3_bucket.audit_logs.id
  description = "Audit logs S3 bucket name"
}

output "bucket_arn" {
  value       = aws_s3_bucket.audit_logs.arn
  description = "Audit logs S3 bucket ARN"
}

output "kms_key_id" {
  value       = aws_kms_key.audit_logs.key_id
  description = "KMS key ID for audit logs encryption"
}

output "kms_key_arn" {
  value       = aws_kms_key.audit_logs.arn
  description = "KMS key ARN for audit logs encryption"
}

# Prefixes for each log type (used by other modules)
output "prefixes" {
  value = {
    cloudtrail_mgmt  = "cloudtrail/management/"
    cloudtrail_data  = "cloudtrail/data/s3/"
    vpc_flowlogs     = "vpc/flowlogs/"
    elb_accesslogs   = "elb/accesslogs/"
    config_snapshots = "config/snapshots/"
    guardduty        = "guardduty/findings/"
  }
  description = "S3 key prefixes for each log type"
}