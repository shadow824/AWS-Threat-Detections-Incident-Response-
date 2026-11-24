# ===================================================================
# GuardDuty - Threat Detection (Member 5)
# ===================================================================
# Security Design Decisions:
# - 30-day free trial, then paid per GB analyzed
# - S3 publishing = findings stored in audit bucket for Member 5 correlation
# - 15-min publishing frequency = near real-time for SOAR automation
# - Member 5 owns suppression rules, Member 1 provides detector + publishing
# - Malware protection = enable if EC2/EKS workloads exist (costs extra)
# ===================================================================

# -------------------------------------------------------------------
# GuardDuty Detector
# -------------------------------------------------------------------

resource "aws_guardduty_detector" "main" {
  enable                       = var.enable_guardduty
  finding_publishing_frequency = var.guardduty_publishing_frequency

  # Optional: Malware Protection for EC2/EBS (costs extra)
  # features {
  #   name  = "MALWARE_PROTECTION"
  #   status = "ENABLED"
  # }
  # features {
  #   name  = "RUNTIME_MONITORING"
  #   status = "ENABLED"
  # }

  tags = {
    Name        = "audit-guardduty-${var.environment}"
    Environment = var.environment
  }
}

# -------------------------------------------------------------------
# GuardDuty S3 Publishing Destination
# -------------------------------------------------------------------
# WHY S3: Member 5 correlates findings with CloudTrail/Config/VPC logs in Athena

resource "aws_guardduty_publishing_destination" "s3" {
  count = var.enable_guardduty ? 1 : 0

  detector_id    = aws_guardduty_detector.main.id
  destination_type = "S3"
  destination_arn  = "${aws_s3_bucket.audit_logs.arn}/guardduty/findings/"
  kms_key_arn      = aws_kms_key.audit_logs.arn
}

# -------------------------------------------------------------------
# GuardDuty IPSet (Threat Intel) - Member 5 manages
# -------------------------------------------------------------------
# WHY: Member 5 provides threat intel IPs, Member 1 creates the IPSet
# Member 5 updates via separate process (not in this module)

resource "aws_guardduty_ipset" "threat_intel" {
  count = var.enable_guardduty && length(var.guardduty_threat_intel_ips) > 0 ? 1 : 0

  detector_id = aws_guardduty_detector.main.id
  name        = "threat-intel-${var.environment}"
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.audit_logs.bucket}/guardduty/threat-intel/ipset.txt"
  activate    = true
}

variable "guardduty_threat_intel_ips" {
  description = "List of threat intel IPs/CIDRs for GuardDuty IPSet (Member 5 provides)"
  type        = list(string)
  default     = []
}

# -------------------------------------------------------------------
# GuardDuty ThreatList (Custom) - Member 5 manages
# -------------------------------------------------------------------

resource "aws_guardduty_threatintelset" "custom" {
  count = var.enable_guardduty && length(var.guardduty_threat_intel_ips) > 0 ? 1 : 0

  detector_id = aws_guardduty_detector.main.id
  name        = "custom-threat-intel-${var.environment}"
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.audit_logs.bucket}/guardduty/threat-intel/threatlist.txt"
  activate    = true
}

# -------------------------------------------------------------------
# Athena Table for GuardDuty Findings
# -------------------------------------------------------------------
# WHY: Member 5 queries findings, enriches with CloudTrail context

resource "aws_athena_named_query" "guardduty_findings_table" {
  database = aws_athena_database.audit.name
  name     = "create-guardduty-findings-table"
  query = <<-SQL
    CREATE EXTERNAL TABLE IF NOT EXISTS guardduty_findings (
      schema_version STRING,
      account_id STRING,
      region STRING,
      partition STRING,
      id STRING,
      arn STRING,
      type STRING,
      resource STRUCT<
        resource_type: STRING,
        instance_details: STRUCT<
          instance_id: STRING,
          instance_type: STRING,
          launch_time: STRING,
          platform: STRING,
          product_codes: ARRAY<STRING>,
          iam_instance_profile: STRUCT<arn: STRING, id: STRING>,
          network_interfaces: ARRAY<STRUCT<
            network_interface_id: STRING,
            private_ips: ARRAY<STRUCT<private_ip_address: STRING>>,
            public_ips: ARRAY<STRUCT<public_ip_address: STRING>>,
            security_groups: ARRAY<STRUCT<group_id: STRING, group_name: STRING>>,
            subnet_id: STRING,
            vpc_id: STRING
          >>
        >,
        access_key_details: STRUCT<
          access_key_id: STRING,
          principal_id: STRING,
          user_name: STRING,
          user_type: STRING
        >
      >,
      service STRUCT<
        action STRUCT<
          action_type: STRING,
          network_connection_action: STRUCT<
            blocked: BOOLEAN,
            connection_direction: STRING,
            local_port_details: STRUCT<port: INT, port_name: STRING>,
            protocol: STRING,
            local_ip_details: STRUCT<ip_address_v4: STRING>,
            remote_ip_details: STRUCT<
              ip_address_v4: STRING,
              organization: STRUCT<asn: STRING, asn_org: STRING, isp: STRING, org: STRING>,
              country: STRUCT<country_code: STRING, country_name: STRING>,
              city: STRUCT<city_name: STRING>,
              geo_location: STRUCT<lat: DOUBLE, lon: DOUBLE>
            >
          >,
          aws_api_call_action: STRUCT<
            api: STRING,
            caller_type: STRING,
            domain_details: STRUCT<domain: STRING>,
            remote_ip_details: STRUCT<
              ip_address_v4: STRING,
              organization: STRUCT<asn: STRING, asn_org: STRING, isp: STRING, org: STRING>,
              country: STRUCT<country_code: STRING, country_name: STRING>
            >
          >,
          dns_request_action: STRUCT<
            domain: STRING,
            protocol: STRING,
            block_status: STRING
          >
        >,
        evidence STRUCT<
          threat_intelligence_details: ARRAY<STRUCT<
            threat_list_name: STRING,
            threat_names: ARRAY<STRING>
          >>
        >,
        archived: BOOLEAN,
        count: INT,
        detector_id: STRING,
        event_first_seen: STRING,
        event_last_seen: STRING,
        resource_role: STRING,
        additional_info: STRUCT<value: STRING, type: STRING>,
        feature_name: STRING
      >,
      severity DOUBLE,
      confidence DOUBLE,
      title STRING,
      description STRING,
      created_at STRING,
      updated_at STRING
    )
    PARTITIONED BY (year STRING, month STRING, day STRING)
    ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.JsonSerDe'
    LOCATION 's3://${aws_s3_bucket.audit_logs.bucket}/guardduty/findings/'
    TBLPROPERTIES (
      'projection.enabled' = 'true',
      'projection.year.type' = 'integer',
      'projection.year.range' = '2020,2030',
      'projection.month.type' = 'integer',
      'projection.month.range' = '1,12',
      'projection.day.type' = 'integer',
      'projection.day.range' = '1,31',
      'storage.location.template' = 's3://${aws_s3_bucket.audit_logs.bucket}/guardduty/findings/AWSLogs/${var.account_id}/GuardDuty/${var.region}/$${year}/$${month}/$${day}/'
    );
  SQL
}

# -------------------------------------------------------------------
# Shared Views for Member 5 (Detection & Enrichment)
# -------------------------------------------------------------------

# High severity findings
resource "aws_athena_named_query" "view_high_severity_findings" {
  database = aws_athena_database.audit.name
  name     = "view-high-severity-findings"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.high_severity_findings AS
    SELECT
      id, arn, type, severity, confidence,
      title, description,
      service.action.action_type as action_type,
      service.action.network_connection_action.remote_ip_details.ip_address_v4 as remote_ip,
      service.action.network_connection_action.remote_ip_details.country.country_name as remote_country,
      service.action.aws_api_call_action.api as api_called,
      service.action.aws_api_call_action.remote_ip_details.ip_address_v4 as api_remote_ip,
      resource.resource_type,
      resource.instance_details.instance_id,
      resource.access_key_details.access_key_id,
      resource.access_key_details.user_name,
      created_at, updated_at
    FROM guardduty_findings
    WHERE severity >= 7.0
    ORDER BY severity DESC, created_at DESC;
  SQL
}

# Compromised EC2 instances (Member 5 scenario)
resource "aws_athena_named_query" "view_compromised_ec2" {
  database = aws_athena_database.audit.name
  name     = "view-compromised-ec2"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.compromised_ec2 AS
    SELECT
      id, arn, type, severity,
      resource.instance_details.instance_id,
      resource.instance_details.instance_type,
      resource.instance_details.launch_time,
      resource.instance_details.iam_instance_profile.arn as instance_profile_arn,
      service.action.network_connection_action.remote_ip_details.ip_address_v4 as c2_ip,
      service.action.network_connection_action.remote_ip_details.country.country_name as c2_country,
      service.action.network_connection_action.protocol,
      service.action.network_connection_action.local_port_details.port as local_port,
      service.action.network_connection_action.connection_direction,
      created_at, updated_at
    FROM guardduty_findings
    WHERE type LIKE '%EC2%' OR type LIKE '%Instance%'
      AND resource.resource_type = 'AWS::EC2::Instance'
    ORDER BY severity DESC, created_at DESC;
  SQL
}

# Exposed IAM Access Keys (Member 5 scenario)
resource "aws_athena_named_query" "view_exposed_access_keys" {
  database = aws_athena_database.audit.name
  name     = "view-exposed-access-keys"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.exposed_access_keys AS
    SELECT
      id, arn, type, severity,
      resource.access_key_details.access_key_id,
      resource.access_key_details.user_name,
      resource.access_key_details.user_type,
      resource.access_key_details.principal_id,
      service.action.aws_api_call_action.api as api_called,
      service.action.aws_api_call_action.remote_ip_details.ip_address_v4 as caller_ip,
      service.action.aws_api_call_action.remote_ip_details.country.country_name as caller_country,
      service.action.aws_api_call_action.caller_type,
      created_at, updated_at
    FROM guardduty_findings
    WHERE type LIKE '%Credential%' OR type LIKE '%AccessKey%'
      AND resource.access_key_details.access_key_id IS NOT NULL
    ORDER BY severity DESC, created_at DESC;
  SQL
}

# Recon/Scanning activity
resource "aws_athena_named_query" "view_recon_activity" {
  database = aws_athena_database.audit.name
  name     = "view-recon-activity"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.recon_activity AS
    SELECT
      id, arn, type, severity,
      service.action.network_connection_action.remote_ip_details.ip_address_v4 as scanner_ip,
      service.action.network_connection_action.remote_ip_details.country.country_name as scanner_country,
      service.action.network_connection_action.protocol,
      service.action.network_connection_action.local_port_details.port as target_port,
      service.action.network_connection_action.connection_direction,
      resource.resource_type,
      resource.instance_details.instance_id,
      created_at, updated_at
    FROM guardduty_findings
    WHERE type LIKE '%Recon%' OR type LIKE '%Scan%' OR type LIKE '%Probe%'
    ORDER BY created_at DESC;
  SQL
}

# Crypto mining
resource "aws_athena_named_query" "view_crypto_mining" {
  database = aws_athena_database.audit.name
  name     = "view-crypto-mining"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.crypto_mining AS
    SELECT
      id, arn, type, severity,
      resource.instance_details.instance_id,
      resource.instance_details.instance_type,
      service.action.network_connection_action.remote_ip_details.ip_address_v4 as pool_ip,
      service.action.network_connection_action.protocol,
      service.action.network_connection_action.local_port_details.port as pool_port,
      created_at, updated_at
    FROM guardduty_findings
    WHERE type LIKE '%CryptoCurrency%' OR type LIKE '%Bitcoin%'
    ORDER BY severity DESC, created_at DESC;
  SQL
}

# -------------------------------------------------------------------
# Enriched View: GuardDuty + CloudTrail Correlation (Member 5's crown jewel)
# -------------------------------------------------------------------
# WHY: Join GuardDuty findings with CloudTrail by AccessKeyId + time window
# Shows what the compromised key actually DID

resource "aws_athena_named_query" "view_guardduty_enriched" {
  database = aws_athena_database.audit.name
  name     = "view-guardduty-enriched"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.guardduty_enriched AS
    SELECT
      g.id as finding_id,
      g.type as finding_type,
      g.severity,
      g.title,
      g.description,
      g.resource.access_key_details.access_key_id,
      g.resource.access_key_details.user_name,
      g.resource.access_key_details.user_type,
      g.service.action.aws_api_call_action.api as gd_api,
      g.service.action.aws_api_call_action.remote_ip_details.ip_address_v4 as gd_caller_ip,
      g.created_at as finding_time,
      -- CloudTrail enrichment (what the key actually did around finding time)
      c.event_time as ct_event_time,
      c.event_name as ct_event_name,
      c.event_source as ct_event_source,
      c.source_ip_address as ct_source_ip,
      c.user_agent as ct_user_agent,
      c.request_parameters as ct_request_params,
      c.response_elements as ct_response_elements,
      c.error_code as ct_error_code
    FROM guardduty_findings g
    LEFT JOIN cloudtrail_management c
      ON g.resource.access_key_details.access_key_id = c.useridentity.accesskeyid
      AND c.event_time BETWEEN date_add('hour', -1, from_iso8601_timestamp(g.created_at))
                           AND date_add('hour', 1, from_iso8601_timestamp(g.created_at))
    WHERE g.resource.access_key_details.access_key_id IS NOT NULL
    ORDER BY g.severity DESC, g.created_at DESC;
  SQL
}

# MITRE ATT&CK Mapping (Member 5 builds this)
resource "aws_athena_named_query" "view_mitre_mapping" {
  database = aws_athena_database.audit.name
  name     = "view-mitre-mapping"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.mitre_attack_mapping AS
    SELECT
      g.id as finding_id,
      g.type as guardduty_type,
      CASE
        WHEN g.type LIKE '%Recon%' THEN 'TA0043: Reconnaissance'
        WHEN g.type LIKE '%InitialAccess%' THEN 'TA0001: Initial Access'
        WHEN g.type LIKE '%Execution%' THEN 'TA0002: Execution'
        WHEN g.type LIKE '%Persistence%' THEN 'TA0003: Persistence'
        WHEN g.type LIKE '%PrivilegeEscalation%' THEN 'TA0004: Privilege Escalation'
        WHEN g.type LIKE '%DefenseEvasion%' THEN 'TA0005: Defense Evasion'
        WHEN g.type LIKE '%CredentialAccess%' THEN 'TA0006: Credential Access'
        WHEN g.type LIKE '%Discovery%' THEN 'TA0007: Discovery'
        WHEN g.type LIKE '%LateralMovement%' THEN 'TA0008: Lateral Movement'
        WHEN g.type LIKE '%Collection%' THEN 'TA0009: Collection'
        WHEN g.type LIKE '%CommandAndControl%' THEN 'TA0011: Command and Control'
        WHEN g.type LIKE '%Exfiltration%' THEN 'TA0010: Exfiltration'
        WHEN g.type LIKE '%Impact%' THEN 'TA0040: Impact'
        ELSE 'UNMAPPED'
      END as mitre_tactic,
      g.severity,
      g.resource.instance_details.instance_id,
      g.resource.access_key_details.access_key_id,
      g.created_at
    FROM guardduty_findings g
    ORDER BY g.severity DESC, g.created_at DESC;
  SQL
}

# -------------------------------------------------------------------
# Outputs
# -------------------------------------------------------------------

output "detector_id" {
  value       = var.enable_guardduty ? aws_guardduty_detector.main.id : null
  description = "GuardDuty detector ID"
}

output "detector_arn" {
  value       = var.enable_guardduty ? aws_guardduty_detector.main.arn : null
  description = "GuardDuty detector ARN"
}

output "publishing_destination_arn" {
  value       = var.enable_guardduty ? aws_guardduty_publishing_destination.s3[0].destination_arn : null
  description = "GuardDuty S3 publishing destination ARN"
}

output "guardduty_athena_table" {
  value       = "guardduty_findings"
  description = "Athena table name for GuardDuty findings"
}

output "guardduty_shared_views" {
  value = [
    "shared.high_severity_findings",
    "shared.compromised_ec2",
    "shared.exposed_access_keys",
    "shared.recon_activity",
    "shared.crypto_mining",
    "shared.guardduty_enriched",
    "shared.mitre_attack_mapping"
  ]
  description = "Shared Athena views for Member 5 detection"
}

output "threat_intel_s3_path" {
  value       = "s3://${aws_s3_bucket.audit_logs.bucket}/guardduty/threat-intel/"
  description = "S3 path for Member 5 to upload threat intel files"
}