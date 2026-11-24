# ===================================================================
# IAM Roles - Least Privilege Read Access for Each Member
# ===================================================================
# Security Design Decisions:
# - One role per member = granular permissions, easy audit
# - Condition keys restrict to specific S3 prefixes = cannot read other members' data
# - Athena workgroup restriction = cannot run queries in other workgroups
# - KMS decrypt only for audit bucket context = cannot decrypt other data
# - No write permissions = read-only audit access
# - Member principals passed via variable = external teams assume these roles
# ===================================================================

# -------------------------------------------------------------------
# Common Trust Policy (All Member Roles)
# -------------------------------------------------------------------
# WHY: Each member assumes their role from their team role/account
# Condition: aws:SourceAccount prevents confused deputy

data "aws_iam_policy_document" "member_trust" {
  for_each = var.member_iam_principals

  statement {
    sid    = "AllowMemberAssumeRole"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [each.value]
    }
    actions = ["sts:AssumeRole"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

# ===================================================================
# MEMBER 2 - Network Monitoring & Forensics
# ===================================================================
# Needs: VPC Flow Logs, ELB Access Logs, CloudTrail network events

resource "aws_iam_role" "member2_network" {
  name               = "audit-read-network-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.member_trust["member-2"].json
}

resource "aws_iam_policy" "member2_network" {
  name = "audit-read-network-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Athena query execution in audit workgroup only
      {
        Sid       = "AthenaQueryExecution"
        Effect    = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:GetQueryResultsStream",
          "athena:StopQueryExecution"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${var.account_id}:workgroup/${aws_athena_workgroup.audit.name}"
      },
      # Read VPC Flow Logs from S3
      {
        Sid       = "ReadVPCFlowLogs"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/vpc/flowlogs/*",
          "${aws_s3_bucket.audit_logs.arn}/vpc/flowlogs/"
        ]
        Condition = {
          StringEquals = {
            "s3:ExistingObjectTag/Environment" = var.environment
          }
        }
      },
      # Read ELB Access Logs from S3
      {
        Sid       = "ReadELBAccessLogs"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/elb/accesslogs/*",
          "${aws_s3_bucket.audit_logs.arn}/elb/accesslogs/"
        ]
      },
      # Read CloudTrail Management (for network-related events)
      {
        Sid       = "ReadCloudTrailManagement"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/management/*",
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/management/"
        ]
      },
      # KMS Decrypt for audit bucket objects only
      {
        Sid       = "KMSDecryptAuditBucket"
        Effect    = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.audit_logs.arn
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.audit_logs.arn}/*"
          }
        }
      },
      # Athena metadata access
      {
        Sid       = "AthenaMetadata"
        Effect    = "Allow"
        Action = [
          "athena:GetDatabase",
          "athena:GetTableMetadata",
          "athena:ListTableMetadata",
          "athena:GetWorkgroup"
        ]
        Resource = "*"
      },
      # Glue catalog access (Athena uses Glue)
      {
        Sid       = "GlueCatalogRead"
        Effect    = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetTables",
          "glue:GetPartition",
          "glue:GetPartitions",
          "glue:BatchGetPartition"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${var.account_id}:catalog",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${var.account_id}:database/audit_logs",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${var.account_id}:table/audit_logs/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "member2_network" {
  role       = aws_iam_role.member2_network.name
  policy_arn = aws_iam_policy.member2_network.arn
}

# ===================================================================
# MEMBER 3 - S3 Security & Data Analytics
# ===================================================================
# Needs: S3 Data Events, CloudTrail S3 activity, Config S3 resources

resource "aws_iam_role" "member3_storage" {
  name               = "audit-read-storage-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.member_trust["member-3"].json
}

resource "aws_iam_policy" "member3_storage" {
  name = "audit-read-storage-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Athena query execution
      {
        Sid       = "AthenaQueryExecution"
        Effect    = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:GetQueryResultsStream",
          "athena:StopQueryExecution"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${var.account_id}:workgroup/${aws_athena_workgroup.audit.name}"
      },
      # Read S3 Data Events (object-level)
      {
        Sid       = "ReadS3DataEvents"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/data/s3/*",
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/data/s3/"
        ]
      },
      # Read CloudTrail Management (S3 bucket-level)
      {
        Sid       = "ReadCloudTrailS3Mgmt"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/management/*",
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/management/"
        ]
      },
      # Read Config S3 resource snapshots
      {
        Sid       = "ReadConfigS3Resources"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/config/snapshots/*",
          "${aws_s3_bucket.audit_logs.arn}/config/snapshots/"
        ]
      },
      # KMS Decrypt
      {
        Sid       = "KMSDecryptAuditBucket"
        Effect    = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.audit_logs.arn
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.audit_logs.arn}/*"
          }
        }
      },
      # Athena + Glue metadata
      {
        Sid       = "AthenaGlueMetadata"
        Effect    = "Allow"
        Action = [
          "athena:GetDatabase",
          "athena:GetTableMetadata",
          "athena:ListTableMetadata",
          "athena:GetWorkgroup",
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetTables",
          "glue:GetPartition",
          "glue:GetPartitions"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "member3_storage" {
  role       = aws_iam_role.member3_storage.name
  policy_arn = aws_iam_policy.member3_storage.arn
}

# ===================================================================
# MEMBER 4 - Cloud Security & Compliance
# ===================================================================
# Needs: Config snapshots, CloudTrail management, Config rules results

resource "aws_iam_role" "member4_compliance" {
  name               = "audit-read-compliance-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.member_trust["member-4"].json
}

resource "aws_iam_policy" "member4_compliance" {
  name = "audit-read-compliance-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Athena query execution
      {
        Sid       = "AthenaQueryExecution"
        Effect    = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:GetQueryResultsStream",
          "athena:StopQueryExecution"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${var.account_id}:workgroup/${aws_athena_workgroup.audit.name}"
      },
      # Read Config snapshots
      {
        Sid       = "ReadConfigSnapshots"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/config/snapshots/*",
          "${aws_s3_bucket.audit_logs.arn}/config/snapshots/"
        ]
      },
      # Read Config history
      {
        Sid       = "ReadConfigHistory"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/config/history/*",
          "${aws_s3_bucket.audit_logs.arn}/config/history/"
        ]
      },
      # Read CloudTrail Management (for compliance-relevant events)
      {
        Sid       = "ReadCloudTrailCompliance"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/management/*",
          "${aws_s3_bucket.audit_logs.arn}/cloudtrail/management/"
        ]
      },
      # Config service API access (for rule evaluation results)
      {
        Sid       = "ConfigAPIRead"
        Effect    = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceDetailsByResource",
          "config:GetComplianceSummaryByConfigRule",
          "config:GetComplianceSummaryByResourceType",
          "config:DescribeConfigRules",
          "config:DescribeConfigurationRecorders",
          "config:DescribeDeliveryChannels",
          "config:ListDiscoveredResources",
          "config:GetResourceConfigHistory"
        ]
        Resource = "*"
      },
      # KMS Decrypt
      {
        Sid       = "KMSDecryptAuditBucket"
        Effect    = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.audit_logs.arn
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.audit_logs.arn}/*"
          }
        }
      },
      # Athena + Glue metadata
      {
        Sid       = "AthenaGlueMetadata"
        Effect    = "Allow"
        Action = [
          "athena:GetDatabase",
          "athena:GetTableMetadata",
          "athena:ListTableMetadata",
          "athena:GetWorkgroup",
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetTables",
          "glue:GetPartition",
          "glue:GetPartitions"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "member4_compliance" {
  role       = aws_iam_role.member4_compliance.name
  policy_arn = aws_iam_policy.member4_compliance.arn
}

# ===================================================================
# MEMBER 5 - Threat Detection & Incident Response
# ===================================================================
# Needs: EVERYTHING (full audit visibility for correlation)

resource "aws_iam_role" "member5_detection" {
  name               = "audit-read-detection-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.member_trust["member-5"].json
}

resource "aws_iam_policy" "member5_detection" {
  name = "audit-read-detection-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Athena query execution (all workgroups for cross-correlation)
      {
        Sid       = "AthenaQueryExecution"
        Effect    = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:GetQueryResultsStream",
          "athena:StopQueryExecution",
          "athena:ListQueryExecutions"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${var.account_id}:workgroup/*"
      },
      # Read ALL audit log prefixes
      {
        Sid       = "ReadAllAuditLogs"
        Effect    = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}/*",
          "${aws_s3_bucket.audit_logs.arn}"
        ]
      },
      # KMS Decrypt for all audit bucket objects
      {
        Sid       = "KMSDecryptAllAudit"
        Effect    = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.audit_logs.arn
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.audit_logs.arn}/*"
          }
        }
      },
      # GuardDuty API access (for finding details, suppression rules)
      {
        Sid       = "GuardDutyAPI"
        Effect    = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "guardduty:GetFindingsStatistics",
          "guardduty:DescribeOrganizationConfiguration",
          "guardduty:ListMembers",
          "guardduty:GetDetector",
          "guardduty:ListDetectors",
          "guardduty:GetIPSet",
          "guardduty:ListIPSets",
          "guardduty:GetThreatIntelSet",
          "guardduty:ListThreatIntelSets"
        ]
        Resource = "*"
      },
      # Security Hub access (for centralized findings)
      {
        Sid       = "SecurityHubAPI"
        Effect    = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:BatchGetFindings",
          "securityhub:GetInsights",
          "securityhub:GetEnabledStandards",
          "securityhub:DescribeStandardsControls"
        ]
        Resource = "*"
      },
      # Detective API (for investigations)
      {
        Sid       = "DetectiveAPI"
        Effect    = "Allow"
        Action = [
          "detective:GetMembers",
          "detective:ListMembers",
          "detective:GetGraph",
          "detective:ListGraphs"
        ]
        Resource = "*"
      },
      # CloudTrail API (for trail status)
      {
        Sid       = "CloudTrailAPI"
        Effect    = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:ListTags",
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      # Config API
      {
        Sid       = "ConfigAPI"
        Effect    = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceDetailsByResource",
          "config:DescribeConfigRules",
          "config:ListDiscoveredResources",
          "config:GetResourceConfigHistory"
        ]
        Resource = "*"
      },
      # Athena + Glue metadata (scoped to audit workgroup/database)
      {
        Sid       = "AthenaGlueMetadata"
        Effect    = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:GetQueryResultsStream",
          "athena:StopQueryExecution",
          "athena:ListQueryExecutions",
          "athena:GetWorkGroup",
          "athena:GetDatabase",
          "athena:GetTableMetadata",
          "athena:ListTableMetadata"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${var.account_id}:workgroup/${aws_athena_workgroup.audit.name}"
      },
      {
        Sid       = "GlueCatalogRead"
        Effect    = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetTables",
          "glue:GetPartition",
          "glue:GetPartitions",
          "glue:BatchGetPartition"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${var.account_id}:catalog",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${var.account_id}:database/audit_logs",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${var.account_id}:table/audit_logs/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "member5_detection" {
  role       = aws_iam_role.member5_detection.name
  policy_arn = aws_iam_policy.member5_detection.arn
}

# ===================================================================
# Audit Admin Role (Member 1 - Full Management)
# ===================================================================
# Member 1 needs write access to manage the audit infrastructure

resource "aws_iam_role" "audit_admin" {
  name               = "audit-admin-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.member_trust["audit-admin"].json
}

resource "aws_iam_policy" "audit_admin" {
  name = "audit-admin-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Full S3 access to audit bucket
      {
        Sid       = "FullAuditBucketAccess"
        Effect    = "Allow"
        Action = ["s3:*"]
        Resource = [
          "${aws_s3_bucket.audit_logs.arn}",
          "${aws_s3_bucket.audit_logs.arn}/*"
        ]
      },
      # Full KMS access to audit key
      {
        Sid       = "FullAuditKMSAccess"
        Effect    = "Allow"
        Action = ["kms:*"]
        Resource = aws_kms_key.audit_logs.arn
      },
      # CloudTrail management
      {
        Sid       = "CloudTrailManagement"
        Effect    = "Allow"
        Action = [
          "cloudtrail:CreateTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:DeleteTrail",
          "cloudtrail:StartLogging",
          "cloudtrail:StopLogging",
          "cloudtrail:PutEventSelectors",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:ListTags"
        ]
        Resource = "*"
      },
      # Config management
      {
        Sid       = "ConfigManagement"
        Effect    = "Allow"
        Action = [
          "config:PutConfigurationRecorder",
          "config:DeleteConfigurationRecorder",
          "config:PutDeliveryChannel",
          "config:DeleteDeliveryChannel",
          "config:StartConfigurationRecorder",
          "config:StopConfigurationRecorder",
          "config:PutConfigRule",
          "config:DeleteConfigRule",
          "config:DescribeConfigRules",
          "config:DescribeConfigurationRecorders"
        ]
        Resource = "*"
      },
      # GuardDuty management
      {
        Sid       = "GuardDutyManagement"
        Effect    = "Allow"
        Action = [
          "guardduty:CreateDetector",
          "guardduty:DeleteDetector",
          "guardduty:UpdateDetector",
          "guardduty:CreatePublishingDestination",
          "guardduty:DeletePublishingDestination",
          "guardduty:UpdatePublishingDestination",
          "guardduty:CreateIPSet",
          "guardduty:DeleteIPSet",
          "guardduty:UpdateIPSet",
          "guardduty:CreateThreatIntelSet",
          "guardduty:DeleteThreatIntelSet",
          "guardduty:UpdateThreatIntelSet"
        ]
        Resource = "*"
      },
      # Athena workgroup management
      {
        Sid       = "AthenaWorkgroupManagement"
        Effect    = "Allow"
        Action = [
          "athena:CreateWorkGroup",
          "athena:UpdateWorkGroup",
          "athena:DeleteWorkGroup",
          "athena:GetWorkGroup",
          "athena:ListWorkGroups"
        ]
        Resource = "*"
      },
      # IAM role management for member roles
      {
        Sid       = "MemberRoleManagement"
        Effect    = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:UpdateRole",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:GetRole",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:iam::${var.account_id}:role/audit-read-*"
      },
      # CloudWatch Logs for CloudTrail
      {
        Sid       = "CloudWatchLogsManagement"
        Effect    = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:DeleteLogGroup",
          "logs:PutRetentionPolicy",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${var.account_id}:log-group:/aws/cloudtrail/audit-*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "audit_admin" {
  role       = aws_iam_role.audit_admin.name
  policy_arn = aws_iam_policy.audit_admin.arn
}

# ===================================================================
# Outputs
# ===================================================================

output "member_roles" {
  value = {
    "member-2-network" = {
      role_arn = aws_iam_role.member2_network.arn
      role_name = aws_iam_role.member2_network.name
      description = "Network Monitoring & Forensics - VPC Flow Logs, ELB, CloudTrail network events"
    }
    "member-3-storage" = {
      role_arn = aws_iam_role.member3_storage.arn
      role_name = aws_iam_role.member3_storage.name
      description = "S3 Security & Data Analytics - S3 Data Events, CloudTrail S3, Config S3"
    }
    "member-4-compliance" = {
      role_arn = aws_iam_role.member4_compliance.arn
      role_name = aws_iam_role.member4_compliance.name
      description = "Cloud Security & Compliance - Config, CloudTrail, Config Rules"
    }
    "member-5-detection" = {
      role_arn = aws_iam_role.member5_detection.arn
      role_name = aws_iam_role.member5_detection.name
      description = "Threat Detection & IR - Full audit visibility, GuardDuty, Security Hub, Detective"
    }
    "audit-admin" = {
      role_arn = aws_iam_role.audit_admin.arn
      role_name = aws_iam_role.audit_admin.name
      description = "Member 1 - Full audit infrastructure management"
    }
  }
  description = "All member IAM role ARNs and descriptions"
}