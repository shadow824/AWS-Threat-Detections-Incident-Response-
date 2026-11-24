# ===================================================================
# Variables - Audit Logs Module (Member 1)
# ===================================================================
# Security: All sensitive values should be passed via environment variables
# or tfvars files (never committed). Use `terraform plan -var-file=secrets.tfvars`

variable "account_id" {
  description = "AWS Account ID (12 digits)"
  type        = string
  validation {
    condition     = length(var.account_id) == 12 && can(regex("^\\d{12}$", var.account_id))
    error_message = "Account ID must be 12 digits."
  }
}

variable "region" {
  description = "AWS Region for resources"
  type        = string
  default     = "us-east-1"
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d$", var.region))
    error_message = "Region must be valid AWS region format (e.g., us-east-1)."
  }
}

variable "environment" {
  description = "Environment name for tagging"
  type        = string
  default     = "free-tier"
  validation {
    condition     = contains(["free-tier", "dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: free-tier, dev, staging, prod."
  }
}

# ===================================================================
# Organization / Free Tier Controls
# ===================================================================
variable "org_ready" {
  description = "Set true when account joins AWS Organization (enables Organization Trail)"
  type        = bool
  default     = false
}

variable "is_free_tier" {
  description = "Enables Free Tier cost optimizations (REJECT-only flow logs, limited data events)"
  type        = bool
  default     = true
}

# ===================================================================
# Network Configuration (Member 2 needs)
# ===================================================================
variable "vpc_ids" {
  description = "List of VPC IDs to enable Flow Logs for"
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for id in var.vpc_ids : can(regex("^vpc-[a-f0-9]{8,17}$", id))])
    error_message = "Each VPC ID must be valid format (vpc-xxxxxxxx)."
  }
}

variable "flowlogs_traffic_type" {
  description = "Traffic type for VPC Flow Logs: ALL (paid) or REJECT (free tier)"
  type        = string
  default     = "REJECT"
  validation {
    condition     = contains(["ALL", "REJECT", "ACCEPT"], var.flowlogs_traffic_type)
    error_message = "Traffic type must be ALL, REJECT, or ACCEPT."
  }
}

# ===================================================================
# CloudTrail Data Events (Member 3 needs - S3 buckets to monitor)
# ===================================================================
variable "cloudtrail_data_event_buckets" {
  description = "S3 bucket ARNs to enable CloudTrail Data Events for (costs money). Empty = no data events."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for arn in var.cloudtrail_data_event_buckets : can(regex("^arn:aws:s3:::[a-z0-9.-]+/?$", arn))])
    error_message = "Each bucket ARN must be valid format (arn:aws:s3:::bucket-name/)."
  }
}

# ===================================================================
# AWS Config (Member 4 needs)
# ===================================================================
variable "config_resource_types" {
  description = "Resource types to record in AWS Config (limit on Free Tier - keep under 10k items/month)"
  type        = list(string)
  default     = [
    "AWS::EC2::Instance",
    "AWS::EC2::SecurityGroup",
    "AWS::IAM::Role",
    "AWS::IAM::User",
    "AWS::S3::Bucket",
    "AWS::Lambda::Function"
  ]
}

variable "config_recording_frequency" {
  description = "Config snapshot delivery frequency"
  type        = string
  default     = "TwentyFour_Hours"
  validation {
    condition     = contains(["Continuous", "TwentyFour_Hours"], var.config_recording_frequency)
    error_message = "Must be Continuous or TwentyFour_Hours."
  }
}

# ===================================================================
# GuardDuty (Member 5 needs)
# ===================================================================
variable "enable_guardduty" {
  description = "Enable GuardDuty detector (30-day free trial, then paid)"
  type        = bool
  default     = true
}

variable "guardduty_publishing_frequency" {
  description = "GuardDuty findings publishing frequency"
  type        = string
  default     = "FIFTEEN_MINUTES"
  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_publishing_frequency)
    error_message = "Must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

# ===================================================================
# Retention / Lifecycle (Compliance)
# ===================================================================
variable "retention_days_standard" {
  description = "Days before transitioning to STANDARD_IA"
  type        = number
  default     = 30
}

variable "retention_days_glacier" {
  description = "Days before transitioning to GLACIER"
  type        = number
  default     = 90
}

variable "retention_days_deep_archive" {
  description = "Days before transitioning to DEEP_ARCHIVE"
  type        = number
  default     = 365
}

variable "retention_days_delete" {
  description = "Days before permanent deletion (7 years = 2555 days for compliance)"
  type        = number
  default     = 2555
}

# ===================================================================
# KMS / Encryption
# ===================================================================
variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days (7-30)"
  type        = number
  default     = 30
  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "Deletion window must be between 7 and 30 days."
  }
}

# ===================================================================
# Athena / Query Configuration
# ===================================================================
variable "athena_workgroup_name" {
  description = "Athena workgroup name for audit queries"
  type        = string
  default     = "audit-logs-workgroup"
}

# ===================================================================
# Member IAM Roles (Least Privilege)
# ===================================================================
variable "member_iam_principals" {
  description = "Map of member ID to IAM principal ARN that can assume read roles"
  type        = map(string)
  default     = {}
  # Example:
  # member_iam_principals = {
  #   "member-2" = "arn:aws:iam::123456789012:role/team-network-role"
  #   "member-3" = "arn:aws:iam::123456789012:role/team-storage-role"
  #   "member-4" = "arn:aws:iam::123456789012:role/team-compliance-role"
  #   "member-5" = "arn:aws:iam::123456789012:role/team-detection-role"
  # }
}