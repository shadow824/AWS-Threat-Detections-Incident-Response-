# ===================================================================
# CloudTrail - API Activity Logging (Management + Data Events)
# ===================================================================
# Security Design Decisions:
# - Multi-region trail = captures global services (IAM, CloudFront, Route53)
# - Log file validation = SHA-256 hash chain detects tampering
# - CloudWatch Logs integration = real-time alerting, metric filters
# - Data events only for critical S3 buckets = cost control (Free Tier)
# - Organization trail = disabled on Free Tier, enabled via org_ready flag
# - Include global service events = IAM changes captured in us-east-1
# ===================================================================

# -------------------------------------------------------------------
# CloudWatch Log Group for CloudTrail
# -------------------------------------------------------------------
# WHY: Real-time log delivery for metric filters/alarms
# Retention: 30 days (cost control), full logs in S3 forever

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/audit-${var.environment}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.audit_logs.arn
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "cloudtrail-cloudwatch-logs-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "cloudtrail.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "cloudtrail_cw" {
  name = "cloudtrail-cloudwatch-logs-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = aws_cloudwatch_log_group.cloudtrail.arn
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cloudtrail_cw" {
  role       = aws_iam_role.cloudtrail_cw.name
  policy_arn = aws_iam_policy.cloudtrail_cw.arn
}

# -------------------------------------------------------------------
# CloudTrail Management Events Trail (FREE on Free Tier)
# -------------------------------------------------------------------
# WHY management events:
# - Captures ALL control plane API calls (Create, Update, Delete, List, Describe)
# - IAM changes, Security Group changes, EC2 launches, S3 bucket changes
# - Source of truth for "who did what, when, from where"
# - Free Tier: First trail free, management events free

resource "aws_cloudtrail" "management" {
  name                          = "audit-management-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  s3_key_prefix                 = "cloudtrail/management/"
  enable_logging                = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_organization_trail         = var.org_ready
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail.arn
  kms_key_id                    = aws_kms_key.audit_logs.arn

  # Event selectors - management events only (free)
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = []  # No data events in management trail
    }
  }

  # Insight selectors - API error rate, call rate anomalies (paid feature)
  # insight_selector {
  #   insight_type = "ApiCallRateInsight"
  # }
  # insight_selector {
  #   insight_type = "ApiErrorRateInsight"
  # }
}

# -------------------------------------------------------------------
# CloudTrail Data Events Trail (S3 Object-Level) - PAID
# -------------------------------------------------------------------
# WHY data events:
# - Object-level API calls: GetObject, PutObject, DeleteObject, ListObjects
# - Member 3 needs this for S3 forensic evidence (who accessed what object)
# - Costs: $0.10 per 100k events (Free Tier: not included)
# - Only enable for CRITICAL buckets (var.cloudtrail_data_event_buckets)

resource "aws_cloudtrail" "s3_data" {
  count = length(var.cloudtrail_data_event_buckets) > 0 ? 1 : 0

  name                          = "audit-s3-data-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  s3_key_prefix                 = "cloudtrail/data/s3/"
  enable_logging                = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = false
  is_organization_trail         = var.org_ready
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail.arn
  kms_key_id                    = aws_kms_key.audit_logs.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = false
    data_resource {
      type   = "AWS::S3::Object"
      values = var.cloudtrail_data_event_buckets  # e.g., ["arn:aws:s3:::critical-bucket/"]
    }
  }
}

# -------------------------------------------------------------------
# CloudTrail Data Events for Lambda (Optional - for Member 5)
# -------------------------------------------------------------------
# WHY: Lambda invocation logging for serverless attack detection
# Enable if Member 5 needs function-level visibility

resource "aws_cloudtrail" "lambda_data" {
  count = var.enable_lambda_data_events ? 1 : 0

  name                          = "audit-lambda-data-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  s3_key_prefix                 = "cloudtrail/data/lambda/"
  enable_logging                = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  is_organization_trail         = var.org_ready
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail.arn
  kms_key_id                    = aws_kms_key.audit_logs.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = false
    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${var.account_id}:*"]
    }
  }
}

variable "enable_lambda_data_events" {
  description = "Enable CloudTrail data events for Lambda functions (costs money)"
  type        = bool
  default     = false
}

# -------------------------------------------------------------------
# Metric Filters for Real-Time Alerting (CloudWatch)
# -------------------------------------------------------------------
# WHY: Turn log patterns into metrics -> alarms -> SNS -> Member 5 detection
# These are FREE on Free Tier (10 metric filters, 10 alarms)

resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  name           = "root-account-usage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $$.userIdentity.type = \"Root\" }"
  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "AuditLogs/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "iam-policy-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($$.eventName = \"PutUserPolicy\") || ($$.eventName = \"PutRolePolicy\") || ($$.eventName = \"PutGroupPolicy\") || ($$.eventName = \"AttachUserPolicy\") || ($$.eventName = \"AttachRolePolicy\") || ($$.eventName = \"AttachGroupPolicy\") || ($$.eventName = \"CreatePolicy\") || ($$.eventName = \"DeletePolicy\") || ($$.eventName = \"CreatePolicyVersion\") || ($$.eventName = \"DeletePolicyVersion\") }"
  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "AuditLogs/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "sg_changes" {
  name           = "security-group-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($$.eventName = \"AuthorizeSecurityGroupIngress\") || ($$.eventName = \"AuthorizeSecurityGroupEgress\") || ($$.eventName = \"RevokeSecurityGroupIngress\") || ($$.eventName = \"RevokeSecurityGroupEgress\") || ($$.eventName = \"CreateSecurityGroup\") || ($$.eventName = \"DeleteSecurityGroup\") }"
  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "AuditLogs/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "kms_key_changes" {
  name           = "kms-key-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($$.eventName = \"DisableKey\") || ($$.eventName = \"ScheduleKeyDeletion\") || ($$.eventName = \"PutKeyPolicy\") || ($$.eventName = \"CreateGrant\") || ($$.eventName = \"RetireGrant\") }"
  metric_transformation {
    name      = "KMSKeyChanges"
    namespace = "AuditLogs/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  name           = "cloudtrail-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($$.eventName = \"StopLogging\") || ($$.eventName = \"DeleteTrail\") || ($$.eventName = \"UpdateTrail\") || ($$.eventName = \"PutEventSelectors\") }"
  metric_transformation {
    name      = "CloudTrailChanges"
    namespace = "AuditLogs/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "config_changes" {
  name           = "config-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($$.eventName = \"StopConfigurationRecorder\") || ($$.eventName = \"DeleteDeliveryChannel\") || ($$.eventName = \"PutConfigurationRecorder\") || ($$.eventName = \"PutDeliveryChannel\") }"
  metric_transformation {
    name      = "ConfigChanges"
    namespace = "AuditLogs/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "console_login_failure" {
  name           = "console-login-failure"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($$.eventName = \"ConsoleLogin\") && ($$.errorMessage = \"Failed authentication\") }"
  metric_transformation {
    name      = "ConsoleLoginFailure"
    namespace = "AuditLogs/Security"
    value     = "1"
  }
}

# -------------------------------------------------------------------
# CloudWatch Alarms (Notify Member 5 / Security Hub)
# -------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "root-account-usage-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "AuditLogs/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Root account used - investigate immediately"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_stopped" {
  alarm_name          = "cloudtrail-stopped-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrailChanges"
  namespace           = "AuditLogs/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CloudTrail modified/stopped - potential tampering"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "config_stopped" {
  alarm_name          = "config-stopped-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConfigChanges"
  namespace           = "AuditLogs/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "AWS Config modified/stopped - compliance gap"
  treat_missing_data  = "notBreaching"
}

# -------------------------------------------------------------------
# Outputs
# -------------------------------------------------------------------

output "management_trail_arn" {
  value       = aws_cloudtrail.management.arn
  description = "Management CloudTrail ARN"
}

output "management_trail_name" {
  value       = aws_cloudtrail.management.name
  description = "Management CloudTrail name"
}

output "s3_data_trail_arn" {
  value       = length(var.cloudtrail_data_event_buckets) > 0 ? aws_cloudtrail.s3_data[0].arn : null
  description = "S3 Data Events CloudTrail ARN (if enabled)"
}

output "cloudwatch_log_group_arn" {
  value       = aws_cloudwatch_log_group.cloudtrail.arn
  description = "CloudWatch Log Group ARN for CloudTrail"
}

output "metric_filter_names" {
  value = [
    "root-account-usage",
    "iam-policy-changes",
    "security-group-changes",
    "kms-key-changes",
    "cloudtrail-changes",
    "config-changes",
    "console-login-failure"
  ]
  description = "CloudWatch metric filter names for Member 5 to create alarms"
}