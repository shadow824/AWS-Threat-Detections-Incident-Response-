# ===================================================================
# Outputs - Consolidated Handoff Package for All Members
# ===================================================================
# This file aggregates all outputs from individual components into
# a single handoff package. Each member consumes their relevant section.

# ===================================================================
# SHARED INFRASTRUCTURE (All Members)
# ===================================================================

output "shared_infrastructure" {
  description = "Core infrastructure all members need"
  value = {
    audit_bucket = {
      name = aws_s3_bucket.audit_logs.id
      arn  = aws_s3_bucket.audit_logs.arn
    }
    kms_key = {
      id  = aws_kms_key.audit_logs.key_id
      arn = aws_kms_key.audit_logs.arn
    }
    athena = {
      database    = aws_athena_database.audit.name
      workgroup   = aws_athena_workgroup.audit.name
      results_loc = "s3://${aws_s3_bucket.audit_logs.bucket}/athena/results/"
    }
    region = var.region
    account_id = var.account_id
  }
}

output "shared_athena_tables" {
  description = "All Athena table names created by this module"
  value = {
    cloudtrail_management = "cloudtrail_management"
    cloudtrail_s3_data    = "cloudtrail_s3_data"
    vpc_flowlogs          = "vpc_flowlogs"
    elb_accesslogs        = "elb_accesslogs"
    config_snapshots      = "config_snapshots"
    config_resources      = "config_resources"
    guardduty_findings    = "guardduty_findings"
  }
}

output "shared_athena_views" {
  description = "All shared Athena views for cross-member queries"
  value = [
    "shared.resource_timeline",
    "shared.iam_activity",
    "shared.s3_bucket_activity",
    "shared.sg_activity",
    "shared.failed_api_calls",
    "shared.cross_account_activity",
    "shared.root_activity",
    # Member 2 specific
    "shared.suspicious_connections",
    "shared.top_rejected_talkers",
    "shared.port_scanning",
    "shared.data_exfil_candidates",
    "shared.elb_errors",
    "shared.suspicious_user_agents",
    "shared.sqli_attempts",
    "shared.path_traversal",
    "shared.top_attacking_ips",
    # Member 3 specific
    "shared.external_s3_access",
    # Member 4 specific
    "shared.unapproved_changes",
    "shared.sg_changes",
    "shared.iam_changes",
    "shared.s3_bucket_changes",
    "shared.resource_drift",
    # Member 5 specific
    "shared.high_severity_findings",
    "shared.compromised_ec2",
    "shared.exposed_access_keys",
    "shared.recon_activity",
    "shared.crypto_mining",
    "shared.guardduty_enriched",
    "shared.mitre_attack_mapping"
  ]
}

# ===================================================================
# MEMBER 2 - NETWORK MONITORING & FORENSICS
# ===================================================================

output "member2_network_handoff" {
  description = "Complete handoff package for Member 2 (Network)"
  value = {
    # S3 Locations
    s3_prefixes = {
      vpc_flowlogs   = "vpc/flowlogs/"
      elb_accesslogs = "elb/accesslogs/"
      cloudtrail_net = "cloudtrail/management/"
    }
    # Athena
    athena = {
      database    = aws_athena_database.audit.name
      workgroup   = aws_athena_workgroup.audit.name
      tables = {
        vpc_flowlogs   = "vpc_flowlogs"
        elb_accesslogs = "elb_accesslogs"
        cloudtrail_mgmt = "cloudtrail_management"
      }
      views = [
        "shared.suspicious_connections",
        "shared.top_rejected_talkers",
        "shared.port_scanning",
        "shared.data_exfil_candidates",
        "shared.elb_errors",
        "shared.suspicious_user_agents",
        "shared.sqli_attempts",
        "shared.path_traversal",
        "shared.top_attacking_ips",
        "shared.sg_activity",
        "shared.resource_timeline"
      ]
    }
    # IAM
    iam_role = {
      arn  = aws_iam_role.member2_network.arn
      name = aws_iam_role.member2_network.name
    }
    # CloudWatch Metric Filters (for alerting)
    metric_filters = [
      "root-account-usage",
      "iam-policy-changes",
      "security-group-changes",
      "kms-key-changes",
      "cloudtrail-changes",
      "config-changes",
      "console-login-failure"
    ]
    # VPC Flow Log IDs (for management)
    flow_log_ids = { for k, v in aws_flow_log.vpc : k => v.id }
  }
}

# ===================================================================
# MEMBER 3 - S3 SECURITY & DATA ANALYTICS
# ===================================================================

output "member3_storage_handoff" {
  description = "Complete handoff package for Member 3 (Storage)"
  value = {
    s3_prefixes = {
      s3_data_events = "cloudtrail/data/s3/"
      cloudtrail_mgmt = "cloudtrail/management/"
      config_s3 = "config/snapshots/"
    }
    athena = {
      database  = aws_athena_database.audit.name
      workgroup = aws_athena_workgroup.audit.name
      tables = {
        s3_data_events = "cloudtrail_s3_data"
        cloudtrail_mgmt = "cloudtrail_management"
        config_resources = "config_resources"
      }
      views = [
        "shared.external_s3_access",
        "shared.s3_bucket_activity",
        "shared.s3_bucket_changes",
        "shared.resource_timeline",
        "shared.iam_activity"
      ]
    }
    iam_role = {
      arn  = aws_iam_role.member3_storage.arn
      name = aws_iam_role.member3_storage.name
    }
    # KMS key for encrypting findings
    kms_key_arn = aws_kms_key.audit_logs.arn
  }
}

# ===================================================================
# MEMBER 4 - CLOUD SECURITY & COMPLIANCE
# ===================================================================

output "member4_compliance_handoff" {
  description = "Complete handoff package for Member 4 (Compliance)"
  value = {
    s3_prefixes = {
      config_snapshots = "config/snapshots/"
      config_history   = "config/history/"
      cloudtrail_mgmt  = "cloudtrail/management/"
    }
    athena = {
      database  = aws_athena_database.audit.name
      workgroup = aws_athena_workgroup.audit.name
      tables = {
        config_snapshots = "config_snapshots"
        config_resources = "config_resources"
        cloudtrail_mgmt = "cloudtrail_management"
      }
      views = [
        "shared.unapproved_changes",
        "shared.sg_changes",
        "shared.iam_changes",
        "shared.s3_bucket_changes",
        "shared.resource_drift",
        "shared.resource_timeline",
        "shared.iam_activity",
        "shared.sg_activity"
      ]
    }
    iam_role = {
      arn  = aws_iam_role.member4_compliance.arn
      name = aws_iam_role.member4_compliance.name
    }
    # Config service ARNs
    config = {
      recorder_name = aws_config_configuration_recorder.main.name
      delivery_channel = aws_config_delivery_channel.main.name
      resource_types = var.config_resource_types
    }
  }
}

# ===================================================================
# MEMBER 5 - THREAT DETECTION & INCIDENT RESPONSE
# ===================================================================

output "member5_detection_handoff" {
  description = "Complete handoff package for Member 5 (Detection)"
  value = {
    s3_prefixes = {
      guardduty_findings = "guardduty/findings/"
      cloudtrail_all = "cloudtrail/"
      vpc_flowlogs = "vpc/flowlogs/"
      elb_logs = "elb/accesslogs/"
      config_snapshots = "config/snapshots/"
    }
    athena = {
      database  = aws_athena_database.audit.name
      workgroup = aws_athena_workgroup.audit.name
      tables = {
        guardduty = "guardduty_findings"
        cloudtrail_mgmt = "cloudtrail_management"
        cloudtrail_s3_data = "cloudtrail_s3_data"
        vpc_flowlogs = "vpc_flowlogs"
        elb_accesslogs = "elb_accesslogs"
        config_resources = "config_resources"
      }
      views = [
        "shared.high_severity_findings",
        "shared.compromised_ec2",
        "shared.exposed_access_keys",
        "shared.recon_activity",
        "shared.crypto_mining",
        "shared.guardduty_enriched",
        "shared.mitre_attack_mapping",
        "shared.resource_timeline",
        "shared.iam_activity",
        "shared.sg_activity",
        "shared.failed_api_calls",
        "shared.cross_account_activity",
        "shared.root_activity",
        "shared.suspicious_connections",
        "shared.port_scanning",
        "shared.elb_errors",
        "shared.sqli_attempts"
      ]
    }
    iam_role = {
      arn  = aws_iam_role.member5_detection.arn
      name = aws_iam_role.member5_detection.name
    }
    # GuardDuty
    guardduty = {
      detector_id = aws_guardduty_detector.main.id
      detector_arn = aws_guardduty_detector.main.arn
      publishing_dest = "s3://${aws_s3_bucket.audit_logs.bucket}/guardduty/findings/"
      threat_intel_path = "s3://${aws_s3_bucket.audit_logs.bucket}/guardduty/threat-intel/"
    }
    # CloudWatch Alarms (for SOAR triggers)
    cloudwatch_alarms = [
      "root-account-usage-alarm",
      "cloudtrail-stopped-alarm",
      "config-stopped-alarm"
    ]
  }
}

# ===================================================================
# MEMBER 1 - AUDIT ADMIN (Self)
# ===================================================================

output "member1_audit_admin_handoff" {
  description = "Member 1 (Self) - Audit infrastructure management"
  value = {
    iam_role = {
      arn  = aws_iam_role.audit_admin.arn
      name = aws_iam_role.audit_admin.name
    }
    managed_resources = {
      s3_bucket = aws_s3_bucket.audit_logs.id
      kms_key = aws_kms_key.audit_logs.key_id
      cloudtrail_management = aws_cloudtrail.management.name
      cloudtrail_s3_data = length(var.cloudtrail_data_event_buckets) > 0 ? aws_cloudtrail.s3_data[0].name : "disabled"
      config_recorder = aws_config_configuration_recorder.main.name
      guardduty_detector = aws_guardduty_detector.main.id
      athena_workgroup = aws_athena_workgroup.audit.name
    }
    member_roles = {
      "member-2" = aws_iam_role.member2_network.arn
      "member-3" = aws_iam_role.member3_storage.arn
      "member-4" = aws_iam_role.member4_compliance.arn
      "member-5" = aws_iam_role.member5_detection.arn
    }
  }
}

# ===================================================================
# ORGANIZATION MIGRATION INFO
# ===================================================================

output "org_migration" {
  description = "Information for migrating to Organization-level trails"
  value = {
    org_ready = var.org_ready
    current_state = "single-account"
    migration_steps = [
      "1. Join account to AWS Organization",
      "2. Enable CloudTrail Organization Trail in management account",
      "3. Set org_ready = true in variables",
      "4. Re-apply Terraform (creates org trail, keeps single-account as backup)",
      "5. Update member IAM roles for cross-account access if needed",
      "6. Update Athena table locations if org trail uses different bucket"
    ]
    notes = "Single-account trail continues working during/after migration. Org trail aggregates all member accounts."
  }
}

# ===================================================================
# COST ESTIMATION (Free Tier)
# ===================================================================

output "free_tier_cost_estimate" {
  description = "Estimated monthly costs on Free Tier (USD)"
  value = {
    notes = "Estimates for us-east-1, typical usage. Actual costs vary."
    items = {
      cloudtrail_management = "FREE (first trail, management events)"
      cloudtrail_data_events = length(var.cloudtrail_data_event_buckets) > 0 ? "~$0.10 per 100k events" : "DISABLED"
      cloudwatch_logs = "FREE (5 GB ingestion, 30-day retention)"
      s3_storage = "FREE (5 GB Standard) + lifecycle to IA/Glacier"
      s3_requests = "FREE (20k GET, 2k PUT per month)"
      vpc_flowlogs = "FREE (REJECT only, S3 destination)"
      elb_logs = "FREE (S3 destination, ~1 GB/month typical)"
      config_recorder = "FREE (first 10k config items/month)"
      guardduty = "FREE (30-day trial, then ~$4/GB)"
      athena = "~$5/TB scanned (use partition pruning!)"
      kms_key = "FREE (1 custom key) + $0.03/10k requests"
      total_estimate = "~$0-50/month depending on data event volume"
    }
  }
}