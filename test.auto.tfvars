account_id              = "247106421769"
region                  = "us-east-1"
environment             = "free-tier"
org_ready               = false
is_free_tier            = true

vpc_ids                 = []
flowlogs_traffic_type   = "REJECT"

cloudtrail_data_event_buckets = []

config_resource_types = [
  "AWS::EC2::Instance",
  "AWS::EC2::SecurityGroup",
  "AWS::IAM::Role",
  "AWS::IAM::User",
  "AWS::S3::Bucket",
  "AWS::Lambda::Function"
]

config_recording_frequency = "TwentyFour_Hours"
enable_guardduty = true
guardduty_publishing_frequency = "FIFTEEN_MINUTES"
guardduty_threat_intel_ips = []

retention_days_standard      = 30
retention_days_glacier       = 90
retention_days_deep_archive  = 365
retention_days_delete        = 2555
kms_key_deletion_window      = 30
athena_workgroup_name        = "audit-logs-workgroup"

member_iam_principals = {
  "member-2"     = "arn:aws:iam::247106421769:user/Ahmed_MOhammed"
  "member-3"     = "arn:aws:iam::247106421769:user/Abdulrahman_Kamal_Afia"
  "member-4"     = "arn:aws:iam::247106421769:user/Mostafa_Rayan"
  "member-5"     = "arn:aws:iam::247106421769:user/Ahmed_Galal"
  "audit-admin"  = "arn:aws:iam::247106421769:user/Sub-Admin"
}