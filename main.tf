# ===================================================================
# Main - Audit Logs Module Orchestration (Member 1)
# ===================================================================
# This module contains all audit log components in a single directory.
# All resources are defined in the companion .tf files in this directory.
# No submodules - single module deployment.
#
# Dependency Order (Terraform handles this automatically):
# 1. versions.tf          - Provider configuration
# 2. variables.tf         - Input variables
# 3. s3_bucket.tf         - S3 bucket, KMS key, lifecycle, bucket policy (FOUNDATION)
# 4. cloudtrail.tf        - CloudTrail management + data events, CW metrics/alarms
# 5. vpc_flowlogs.tf      - VPC Flow Logs (Parquet), Athena tables, views
# 6. elb_logs.tf          - ELB Access Logs, Athena tables, views
# 7. config_recorder.tf   - AWS Config recorder, Athena tables, views
# 8. guardduty.tf         - GuardDuty detector, publishing, Athena tables, views
# 9. athena.tf            - Athena workgroup, database, shared tables/views
# 10. iam_roles.tf        - Least-privilege IAM roles per member
# 11. outputs.tf          - Consolidated handoff packages
# 12. example.tf          - Example usage
# ===================================================================

# ===================================================================
# DATA SOURCES
# ===================================================================
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# ===================================================================
# RANDOM / NAMING
# ===================================================================
resource "random_string" "bucket_suffix" {
  length  = 8
  lower   = true
  upper   = false
  number  = true
  special = false
  keepers = {
    account_id = var.account_id
    region     = var.region
  }
}