# ===================================================================
# VPC Flow Logs - Network Traffic Visibility (Member 2)
# ===================================================================
# Security Design Decisions:
# - REJECT traffic only on Free Tier = captures blocked connections (reconnaissance, attacks)
# - Parquet format = columnar, compressed, 10x faster/cheaper Athena queries
# - Partitioned by date + VPC = partition pruning reduces scan costs
# - S3 destination (not CloudWatch) = cheaper storage, Athena-native
# - 10-min aggregation = balance between granularity and cost
# - IAM role with least privilege = only PutObject to specific prefix
# ===================================================================

# -------------------------------------------------------------------
# IAM Role for VPC Flow Logs Service
# -------------------------------------------------------------------
# WHY dedicated role: least privilege - only write to specific S3 prefix

resource "aws_iam_role" "vpc_flowlogs" {
  name = "vpc-flowlogs-s3-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.${data.aws_region.current.name}.${data.aws_partition.current.partition}" }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = var.account_id
        }
        ArnLike = {
          "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${var.account_id}:vpc/*"
        }
      }
    }]
  })
}

resource "aws_iam_policy" "vpc_flowlogs" {
  name = "vpc-flowlogs-s3-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.audit_logs.arn}/vpc/flowlogs/*"
      Condition = {
        StringEquals = {
          "s3:x-amz-acl" = "bucket-owner-full-control"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "vpc_flowlogs" {
  role       = aws_iam_role.vpc_flowlogs.name
  policy_arn = aws_iam_policy.vpc_flowlogs.arn
}

# -------------------------------------------------------------------
# VPC Flow Logs (per VPC)
# -------------------------------------------------------------------
# WHY per VPC: different VPCs may have different traffic patterns
# Parquet format requires Hive-compatible partitioning

resource "aws_flow_log" "vpc" {
  for_each = { for vpc_id in var.vpc_ids : vpc_id => vpc_id }

  vpc_id              = each.key
  traffic_type        = var.flowlogs_traffic_type  # REJECT (free) or ALL (paid)
  log_destination_type = "s3"
  log_destination     = "${aws_s3_bucket.audit_logs.arn}/vpc/flowlogs/vpc-${each.key}/"
  log_format          = jsonencode({
    version = "1.0"
    fields  = [
      "version", "account-id", "interface-id", "srcaddr", "dstaddr",
      "srcport", "dstport", "protocol", "packets", "bytes",
      "start", "end", "action", "log-status"
    ]
  })
  max_aggregation_interval = 600  # 10 minutes (default)
  destination_options {
    file_format = "parquet"
    hive_compatible_partitions = true
    per_hour_partition = true
  }
}

# -------------------------------------------------------------------
# Athena Table for VPC Flow Logs (Partitioned by date + VPC)
# -------------------------------------------------------------------
# WHY this schema:
# - Parquet columnar format = only scanned columns read
# - Partition projection = automatic partition discovery, no MSCK REPAIR
# - vpc_id partition = query single VPC without scanning all

resource "aws_athena_named_query" "vpc_flowlogs_table" {
  database = aws_athena_database.audit.name
  name     = "create-vpc-flowlogs-table"
  query = <<-SQL
    CREATE EXTERNAL TABLE IF NOT EXISTS vpc_flowlogs (
      version INT,
      account_id STRING,
      interface_id STRING,
      srcaddr STRING,
      dstaddr STRING,
      srcport INT,
      dstport INT,
      protocol INT,
      packets BIGINT,
      bytes BIGINT,
      start_time BIGINT,
      end_time BIGINT,
      action STRING,
      log_status STRING
    )
    PARTITIONED BY (
      year STRING,
      month STRING,
      day STRING,
      hour STRING,
      vpc_id STRING
    )
    STORED AS PARQUET
    LOCATION 's3://${aws_s3_bucket.audit_logs.bucket}/vpc/flowlogs/'
    TBLPROPERTIES (
      'projection.enabled' = 'true',
      'projection.year.type' = 'integer',
      'projection.year.range' = '2020,2030',
      'projection.month.type' = 'integer',
      'projection.month.range' = '1,12',
      'projection.day.type' = 'integer',
      'projection.day.range' = '1,31',
      'projection.hour.type' = 'integer',
      'projection.hour.range' = '0,23',
      'projection.vpc_id.type' = 'injected',
      'storage.location.template' = 's3://${aws_s3_bucket.audit_logs.bucket}/vpc/flowlogs/vpc-$${vpc_id}/$${year}/$${month}/$${day}/$${hour}/'
    );
  SQL
}

# -------------------------------------------------------------------
# Shared Views for Member 2 (Network Analysis)
# -------------------------------------------------------------------

# Suspicious connections - REJECT to known bad IPs
resource "aws_athena_named_query" "view_suspicious_connections" {
  database = aws_athena_database.audit.name
  name     = "view-suspicious-connections"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.suspicious_connections AS
    SELECT
      srcaddr, dstaddr, srcport, dstport, protocol,
      action, packets, bytes,
      from_unixtime(start_time) as start_ts,
      from_unixtime(end_time) as end_ts,
      vpc_id,
      year, month, day, hour
    FROM vpc_flowlogs
    WHERE action = 'REJECT'
      AND dstaddr IN (
        -- Add threat intel IPs here, or join with threat intel table
        '0.0.0.0/0'  -- placeholder
      );
  SQL
}

# Top talkers (rejected traffic)
resource "aws_athena_named_query" "view_top_rejected_talkers" {
  database = aws_athena_database.audit.name
  name     = "view-top-rejected-talkers"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.top_rejected_talkers AS
    SELECT
      srcaddr,
      COUNT(*) as reject_count,
      SUM(packets) as total_packets,
      SUM(bytes) as total_bytes,
      COUNT(DISTINCT dstport) as unique_dst_ports,
      MIN(from_unixtime(start_time)) as first_seen,
      MAX(from_unixtime(end_time)) as last_seen
    FROM vpc_flowlogs
    WHERE action = 'REJECT'
    GROUP BY srcaddr
    ORDER BY reject_count DESC
    LIMIT 100;
  SQL
}

# Port scanning detection (many ports, few packets each)
resource "aws_athena_named_query" "view_port_scanning" {
  database = aws_athena_database.audit.name
  name     = "view-port-scanning"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.port_scanning AS
    SELECT
      srcaddr,
      COUNT(DISTINCT dstport) as ports_targeted,
      COUNT(*) as connection_attempts,
      MIN(from_unixtime(start_time)) as first_seen,
      MAX(from_unixtime(end_time)) as last_seen
    FROM vpc_flowlogs
    WHERE action = 'REJECT'
    GROUP BY srcaddr
    HAVING COUNT(DISTINCT dstport) > 20
       AND COUNT(*) > 50
    ORDER BY ports_targeted DESC;
  SQL
}

# Data exfiltration candidates (large outbound REJECT - unusual)
resource "aws_athena_named_query" "view_data_exfil_candidates" {
  database = aws_athena_database.audit.name
  name     = "view-data-exfil-candidates"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.data_exfil_candidates AS
    SELECT
      srcaddr, dstaddr,
      SUM(bytes) as total_bytes,
      COUNT(*) as flow_count,
      MIN(from_unixtime(start_time)) as first_seen,
      MAX(from_unixtime(end_time)) as last_seen
    FROM vpc_flowlogs
    WHERE action = 'REJECT'
      AND bytes > 10000000  -- > 10MB in single flow
    GROUP BY srcaddr, dstaddr
    ORDER BY total_bytes DESC
    LIMIT 50;
  SQL
}

# -------------------------------------------------------------------
# Outputs
# -------------------------------------------------------------------

output "flow_log_ids" {
  value       = { for k, v in aws_flow_log.vpc : k => v.id }
  description = "Map of VPC ID to Flow Log ID"
}

output "flow_logs_athena_table" {
  value       = "vpc_flowlogs"
  description = "Athena table name for VPC Flow Logs"
}

output "member2_shared_views" {
  value = [
    "shared.suspicious_connections",
    "shared.top_rejected_talkers",
    "shared.port_scanning",
    "shared.data_exfil_candidates"
  ]
  description = "Shared Athena views for Member 2 network analysis"
}

output "member2_iam_role_arn" {
  value       = aws_iam_role.vpc_flowlogs.arn
  description = "IAM role ARN for VPC Flow Logs service (Member 2)"
}