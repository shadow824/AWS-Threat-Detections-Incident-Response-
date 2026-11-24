# ===================================================================
# AWS Config - Resource Configuration History (Member 4)
# ===================================================================
# Security Design Decisions:
# - Targeted resource types (not all) = Free Tier cost control (first 10k free)
# - 24-hour snapshot frequency = balance between granularity and cost
# - S3 delivery to same bucket = centralized, encrypted, lifecycle managed
# - Config Rules = separate module (Member 4 owns rules, Member 1 provides recorder)
# - Global resource types (IAM) recorded in us-east-1 only
# ===================================================================

# -------------------------------------------------------------------
# IAM Role for Config Service
# -------------------------------------------------------------------
# WHY dedicated role: least privilege - only PutObject to config prefix

resource "aws_iam_role" "config" {
  name = "aws-config-service-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "config.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = var.account_id
        }
      }
    }]
  })
}

resource "aws_iam_policy" "config" {
  name = "aws-config-service-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl"
        ]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/config/snapshots/*",
          "${aws_s3_bucket.audit_logs.arn}/config/history/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "config:PutConfigRule",
          "config:DeleteConfigRule",
          "config:PutConfigurationRecorder",
          "config:DeleteConfigurationRecorder",
          "config:PutDeliveryChannel",
          "config:DeleteDeliveryChannel",
          "config:StartConfigurationRecorder",
          "config:StopConfigurationRecorder",
          "config:PutEvaluations"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = aws_iam_policy.config.arn
}

# -------------------------------------------------------------------
# Config Delivery Channel
# -------------------------------------------------------------------

resource "aws_config_delivery_channel" "main" {
  name           = "audit-config-delivery-${var.environment}"
  s3_bucket_name = aws_s3_bucket.audit_logs.id
  s3_key_prefix  = "config/snapshots/"
  snapshot_delivery_properties {
    delivery_frequency = var.config_recording_frequency  # TwentyFour_Hours (free tier friendly)
  }
}

# -------------------------------------------------------------------
# Config Configuration Recorder
# -------------------------------------------------------------------
# WHY targeted resource types:
# - Free Tier: first 10,000 configuration items/month free
# - Recording ALL types exceeds free tier quickly
# - Member 4 adds Config Rules for compliance checks

resource "aws_config_configuration_recorder" "main" {
  name     = "audit-config-recorder-${var.environment}"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = true  # IAM resources (global)
    resource_types                = var.config_resource_types
  }
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = var.enable_config
}

variable "enable_config" {
  description = "Enable AWS Config recorder"
  type        = bool
  default     = true
}

# -------------------------------------------------------------------
# Config Recorder for Global Resources (IAM) - us-east-1 only
# -------------------------------------------------------------------
# WHY separate: global resources (IAM, CloudFront) only recorded in us-east-1
# If this module runs in non-us-east-1, global resources still recorded
# but recorder must exist in us-east-1. This handles it via provider alias.

# Note: For multi-region, deploy this module in us-east-1 with global types
# and other regions without include_global_resource_types

# -------------------------------------------------------------------
# Athena Table for Config Snapshots
# -------------------------------------------------------------------
# WHY: Member 4 queries config history for drift detection, compliance

resource "aws_athena_named_query" "config_snapshots_table" {
  database = aws_athena_database.audit.name
  name     = "create-config-snapshots-table"
  query = <<-SQL
    CREATE EXTERNAL TABLE IF NOT EXISTS config_snapshots (
      fileversion STRING,
      configsnapshotid STRING,
      configurationitems ARRAY<STRUCT<
        version: STRING,
        accountid: STRING,
        configurationitemcapturetime: STRING,
        configurationitemstatus: STRING,
        configurationstateid: STRING,
        arn: STRING,
        resourcetype: STRING,
        resourceid: STRING,
        resourcename: STRING,
        awsregion: STRING,
        availabilityzone: STRING,
        configuration: STRING,
        supplementaryconfiguration: MAP<STRING, STRING>,
        tags: MAP<STRING, STRING>,
        relatedevents: ARRAY<STRING>,
        relationships: ARRAY<STRUCT<
          resourcetype: STRING,
          resourceid: STRING,
          resourcename: STRING,
          relationshipname: STRING
        >>
      >>
    )
    PARTITIONED BY (year STRING, month STRING, day STRING)
    ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.JsonSerDe'
    LOCATION 's3://${aws_s3_bucket.audit_logs.bucket}/config/snapshots/AWSLogs/${var.account_id}/Config/${var.region}/'
    TBLPROPERTIES (
      'projection.enabled' = 'true',
      'projection.year.type' = 'integer',
      'projection.year.range' = '2020,2030',
      'projection.month.type' = 'integer',
      'projection.month.range' = '1,12',
      'projection.day.type' = 'integer',
      'projection.day.range' = '1,31',
      'storage.location.template' = 's3://${aws_s3_bucket.audit_logs.bucket}/config/snapshots/AWSLogs/${var.account_id}/Config/${var.region}/$${year}/$${month}/$${day}/'
    );
  SQL
}

# Flattened view for easier querying
resource "aws_athena_named_query" "config_resources_view" {
  database = aws_athena_database.audit.name
  name     = "view-config-resources"
  query = <<-SQL
    CREATE OR REPLACE VIEW config_resources AS
    SELECT
      ci.configurationitemcapturetime as capture_time,
      ci.configurationitemstatus as status,
      ci.arn,
      ci.resourcetype,
      ci.resourceid,
      ci.resourcename,
      ci.awsregion,
      ci.availabilityzone,
      ci.configuration,
      ci.tags,
      ci.relationships
    FROM config_snapshots
    CROSS JOIN UNNEST(configurationitems) AS t(ci);
  SQL
}

# -------------------------------------------------------------------
# Shared Views for Member 4 (Compliance)
# -------------------------------------------------------------------

# Unapproved changes (resources without Approved tag)
resource "aws_athena_named_query" "view_unapproved_changes" {
  database = aws_athena_database.audit.name
  name     = "view-unapproved-changes"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.unapproved_changes AS
    SELECT
      capture_time,
      arn,
      resourcetype,
      resourceid,
      resourcename,
      status,
      tags,
      relationships
    FROM config_resources
    WHERE status IN ('ResourceDiscovered', 'ResourceDeleted', 'ResourceNotRecorded')
       OR (tags IS NOT NULL AND tags['Approved'] != 'true')
       OR tags IS NULL
    ORDER BY capture_time DESC;
  SQL
}

# Security group changes
resource "aws_athena_named_query" "view_sg_changes" {
  database = aws_athena_database.audit.name
  name     = "view-sg-changes"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.sg_changes AS
    SELECT
      capture_time,
      arn,
      resourceid,
      resourcename,
      status,
      configuration,
      tags
    FROM config_resources
    WHERE resourcetype = 'AWS::EC2::SecurityGroup'
      AND status IN ('ResourceDiscovered', 'ResourceDeleted', 'OK')
    ORDER BY capture_time DESC;
  SQL
}

# IAM role/policy changes
resource "aws_athena_named_query" "view_iam_changes" {
  database = aws_athena_database.audit.name
  name     = "view-iam-changes"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.iam_changes AS
    SELECT
      capture_time,
      arn,
      resourcetype,
      resourceid,
      resourcename,
      status,
      configuration,
      tags
    FROM config_resources
    WHERE resourcetype IN ('AWS::IAM::Role', 'AWS::IAM::User', 'AWS::IAM::Policy', 'AWS::IAM::Group')
      AND status IN ('ResourceDiscovered', 'ResourceDeleted', 'OK')
    ORDER BY capture_time DESC;
  SQL
}

# S3 bucket configuration changes
resource "aws_athena_named_query" "view_s3_bucket_changes" {
  database = aws_athena_database.audit.name
  name     = "view-s3-bucket-changes"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.s3_bucket_changes AS
    SELECT
      capture_time,
      arn,
      resourceid,
      resourcename,
      status,
      configuration,
      tags
    FROM config_resources
    WHERE resourcetype = 'AWS::S3::Bucket'
      AND status IN ('ResourceDiscovered', 'ResourceDeleted', 'OK')
    ORDER BY capture_time DESC;
  SQL
}

# Resource drift detection (comparing consecutive snapshots)
resource "aws_athena_named_query" "view_resource_drift" {
  database = aws_athena_database.audit.name
  name     = "view-resource-drift"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.resource_drift AS
    WITH ranked AS (
      SELECT
        *,
        ROW_NUMBER() OVER (PARTITION BY arn ORDER BY capture_time DESC) as rn
      FROM config_resources
      WHERE status = 'OK'
    )
    SELECT
      curr.arn,
      curr.resourcetype,
      curr.resourceid,
      curr.resourcename,
      curr.capture_time as current_capture,
      prev.capture_time as previous_capture,
      curr.configuration as current_config,
      prev.configuration as previous_config
    FROM ranked curr
    JOIN ranked prev ON curr.arn = prev.arn AND prev.rn = 2
    WHERE curr.rn = 1
      AND curr.configuration != prev.configuration
    ORDER BY curr.capture_time DESC;
  SQL
}

# -------------------------------------------------------------------
# Outputs
# -------------------------------------------------------------------

output "config_recorder_name" {
  value       = aws_config_configuration_recorder.main.name
  description = "AWS Config recorder name"
}

output "delivery_channel_name" {
  value       = aws_config_delivery_channel.main.name
  description = "AWS Config delivery channel name"
}

output "config_snapshots_prefix" {
  value       = "config/snapshots/"
  description = "S3 prefix for Config snapshots"
}

output "config_athena_tables" {
  value = {
    snapshots = "config_snapshots"
    resources = "config_resources"
  }
  description = "Athena table names for Config data"
}

output "config_shared_views" {
  value = [
    "shared.unapproved_changes",
    "shared.sg_changes",
    "shared.iam_changes",
    "shared.s3_bucket_changes",
    "shared.resource_drift"
  ]
  description = "Shared Athena views for Member 4 compliance"
}

output "member4_iam_role_arn" {
  value       = aws_iam_role.config.arn
  description = "IAM role ARN for Config service (Member 4)"
}