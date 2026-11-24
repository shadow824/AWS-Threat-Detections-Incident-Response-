# ===================================================================
# Athena - Query Engine for All Audit Logs
# ===================================================================
# Security Design Decisions:
# - Dedicated workgroup = query isolation, cost controls, result encryption
# - Result encryption with same KMS key = consistent encryption
# - Query result location = same audit bucket (centralized)
# - Cost controls: max query cost, bytes scanned limit
# - Engine version 3 = latest performance, Parquet optimization
# ===================================================================

# -------------------------------------------------------------------
# Athena Workgroup (Cost Controls + Isolation)
# -------------------------------------------------------------------
# WHY dedicated workgroup:
# - Separate query history from other workloads
# - Per-workgroup cost controls (bytes scanned limit)
# - Result encryption enforced
# - CloudWatch metrics per workgroup

resource "aws_athena_workgroup" "audit" {
  name = var.athena_workgroup_name
  description = "Audit logs query workgroup - ${var.environment}"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    requester_pays_enabled             = false

    # Result configuration
    result_configuration {
      output_location = "s3://${aws_s3_bucket.audit_logs.bucket}/athena/results/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.audit_logs.arn
      }
      expected_bucket_owner = var.account_id
    }

    # Cost controls (Free Tier friendly)
    bytes_scanned_cutoff_per_query = 10737418240  # 10 GB per query limit

    # Engine version
    engine_version {
      selected_engine_version = "Athena engine version 3"
      effective_engine_version = "Athena engine version 3"
    }
  }

  # Workgroup tags
  tags = {
    Name        = "audit-logs-workgroup"
    Environment = var.environment
  }
}

# -------------------------------------------------------------------
# Athena Database
# -------------------------------------------------------------------

resource "aws_athena_database" "audit" {
  name   = "audit_logs"
  bucket = aws_s3_bucket.audit_logs.bucket
}

# -------------------------------------------------------------------
# CloudTrail Management Events Table
# -------------------------------------------------------------------
# WHY: Uses CloudTrail SerDe for native log parsing
# Partition projection = automatic partition discovery (no MSCK REPAIR)

resource "aws_athena_named_query" "cloudtrail_management_table" {
  database = aws_athena_database.audit.name
  name     = "create-cloudtrail-management-table"
  workgroup = aws_athena_workgroup.audit.name
  query = <<-SQL
    CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_management (
      eventversion STRING,
      useridentity STRUCT<
        type: STRING,
        principalid: STRING,
        arn: STRING,
        accountid: STRING,
        invokedby: STRING,
        accesskeyid: STRING,
        userName: STRING,
        sessioncontext: STRUCT<
          attributes: STRUCT<mfaauthenticated: STRING, creationdate: STRING>,
          sessionissuer: STRUCT<type: STRING, principalid: STRING, arn: STRING, accountid: STRING, username: STRING>
        >
      >,
      eventtime STRING,
      eventsource STRING,
      eventname STRING,
      awsregion STRING,
      sourceipaddress STRING,
      useragent STRING,
      errorcode STRING,
      errormessage STRING,
      requestparameters STRING,
      responseelements STRING,
      additionaleventdata STRING,
      requestid STRING,
      eventid STRING,
      resources ARRAY<STRUCT<
        arn: STRING,
        accountid: STRING,
        type: STRING
      >>,
      eventtype STRING,
      apiversion STRING,
      readonly STRING,
      recipientaccountid STRING,
      serviceeventdetails STRING,
      sharedeventid STRING,
      vpcendpointid STRING
    )
    PARTITIONED BY (
      year STRING,
      month STRING,
      day STRING
    )
    ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
    STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
    LOCATION 's3://${aws_s3_bucket.audit_logs.bucket}/cloudtrail/management/AWSLogs/${var.account_id}/CloudTrail/${var.region}/'
    TBLPROPERTIES (
      'projection.enabled' = 'true',
      'projection.year.type' = 'integer',
      'projection.year.range' = '2020,2030',
      'projection.month.type' = 'integer',
      'projection.month.range' = '1,12',
      'projection.day.type' = 'integer',
      'projection.day.range' = '1,31',
      'storage.location.template' = 's3://${aws_s3_bucket.audit_logs.bucket}/cloudtrail/management/AWSLogs/${var.account_id}/CloudTrail/${var.region}/$${year}/$${month}/$${day}/'
    );
  SQL
}

# -------------------------------------------------------------------
# CloudTrail S3 Data Events Table
# -------------------------------------------------------------------

resource "aws_athena_named_query" "cloudtrail_s3_data_table" {
  database = aws_athena_database.audit.name
  name     = "create-cloudtrail-s3-data-table"
  workgroup = aws_athena_workgroup.audit.name
  query = <<-SQL
    CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_s3_data (
      eventversion STRING,
      useridentity STRUCT<
        type: STRING,
        principalid: STRING,
        arn: STRING,
        accountid: STRING,
        invokedby: STRING,
        accesskeyid: STRING,
        userName: STRING,
        sessioncontext: STRUCT<
          attributes: STRUCT<mfaauthenticated: STRING, creationdate: STRING>,
          sessionissuer: STRUCT<type: STRING, principalid: STRING, arn: STRING, accountid: STRING, username: STRING>
        >
      >,
      eventtime STRING,
      eventsource STRING,
      eventname STRING,
      awsregion STRING,
      sourceipaddress STRING,
      useragent STRING,
      errorcode STRING,
      errormessage STRING,
      requestparameters STRING,
      responseelements STRING,
      additionaleventdata STRING,
      requestid STRING,
      eventid STRING,
      resources ARRAY<STRUCT<
        arn: STRING,
        accountid: STRING,
        type: STRING
      >>,
      eventtype STRING,
      apiversion STRING,
      readonly STRING,
      recipientaccountid STRING,
      serviceeventdetails STRING,
      sharedeventid STRING,
      vpcendpointid STRING
    )
    PARTITIONED BY (
      year STRING,
      month STRING,
      day STRING
    )
    ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
    STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
    LOCATION 's3://${aws_s3_bucket.audit_logs.bucket}/cloudtrail/data/s3/AWSLogs/${var.account_id}/CloudTrail/${var.region}/'
    TBLPROPERTIES (
      'projection.enabled' = 'true',
      'projection.year.type' = 'integer',
      'projection.year.range' = '2020,2030',
      'projection.month.type' = 'integer',
      'projection.month.range' = '1,12',
      'projection.day.type' = 'integer',
      'projection.day.range' = '1,31',
      'storage.location.template' = 's3://${aws_s3_bucket.audit_logs.bucket}/cloudtrail/data/s3/AWSLogs/${var.account_id}/CloudTrail/${var.region}/$${year}/$${month}/$${day}/'
    );
  SQL
}

# -------------------------------------------------------------------
# Shared Views (Cross-cutting queries all members use)
# -------------------------------------------------------------------

# Resource timeline - universal "what happened to X when"
resource "aws_athena_named_query" "view_resource_timeline" {
  database = aws_athena_database.audit.name
  name     = "view-resource-timeline"
  workgroup = aws_athena_workgroup.audit.name
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.resource_timeline AS
    SELECT
      eventtime,
      eventname,
      eventsource,
      useridentity.arn as actor_arn,
      useridentity.type as actor_type,
      useridentity.accountid as actor_account,
      sourceipaddress,
      useragent,
      requestparameters,
      responseelements.errorcode as error_code,
      errorcode,
      awsregion
    FROM cloudtrail_management
    WHERE requestparameters.resourceName IS NOT NULL
       OR requestparameters.resourceArn IS NOT NULL
       OR requestparameters.instancesSet IS NOT NULL
       OR requestparameters.volumesSet IS NOT NULL
       OR requestparameters.networkInterfaces IS NOT NULL
    ORDER BY eventtime DESC;
  SQL
}

# All IAM activity (who did what to identities)
resource "aws_athena_named_query" "view_iam_activity" {
  database = aws_athena_database.audit.name
  name     = "view-iam-activity"
  workgroup = aws_athena_workgroup.audit.name
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.iam_activity AS
    SELECT
      eventtime,
      eventname,
      useridentity.arn as actor_arn,
      useridentity.type as actor_type,
      sourceipaddress,
      requestparameters,
      responseelements,
      errorcode
    FROM cloudtrail_management
    WHERE eventsource = 'iam.amazonaws.com'
       OR eventsource = 'sts.amazonaws.com'
    ORDER BY eventtime DESC;
  SQL
}

# All S3 bucket activity
resource "aws_athena_named_query" "view_s3_bucket_activity" {
  database = aws_athena_database.audit.name
  name     = "view-s3-bucket-activity"
  workgroup = aws_athena_workgroup.audit.name
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.s3_bucket_activity AS
    SELECT
      eventtime,
      eventname,
      useridentity.arn as actor_arn,
      sourceipaddress,
      requestparameters.bucketName as bucket_name,
      requestparameters.key as object_key,
      errorcode
    FROM cloudtrail_management
    WHERE eventsource = 's3.amazonaws.com'
      AND eventname IN ('CreateBucket', 'DeleteBucket', 'PutBucketPolicy', 'DeleteBucketPolicy',
                        'PutBucketAcl', 'PutBucketPublicAccessBlock', 'PutBucketVersioning',
                        'PutBucketEncryption', 'PutBucketLogging', 'PutBucketWebsite',
                        'PutBucketCors', 'PutBucketLifecycle', 'PutBucketReplication')
    ORDER BY eventtime DESC;
  SQL
}

# Security group changes
resource "aws_athena_named_query" "view_sg_activity" {
  database = aws_athena_database.audit.name
  name     = "view-sg-activity"
  workgroup = aws_athena_workgroup.audit.name
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.sg_activity AS
    SELECT
      eventtime,
      eventname,
      useridentity.arn as actor_arn,
      sourceipaddress,
      requestparameters.groupId as sg_id,
      requestparameters.groupName as sg_name,
      requestparameters.ipPermissions as ingress_rules,
      requestparameters.ipPermissionsEgress as egress_rules,
      errorcode
    FROM cloudtrail_management
    WHERE eventsource = 'ec2.amazonaws.com'
      AND eventname IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
                        'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
                        'CreateSecurityGroup', 'DeleteSecurityGroup')
    ORDER BY eventtime DESC;
  SQL
}

# Failed API calls (errors = potential attacks or misconfig)
resource "aws_athena_named_query" "view_failed_api_calls" {
  database = aws_athena_database.audit.name
  name     = "view-failed-api-calls"
  workgroup = aws_athena_workgroup.audit.name
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.failed_api_calls AS
    SELECT
      eventtime,
      eventname,
      eventsource,
      useridentity.arn as actor_arn,
      useridentity.type as actor_type,
      sourceipaddress,
      errorcode,
      errormessage,
      requestparameters
    FROM cloudtrail_management
    WHERE errorcode IS NOT NULL
    ORDER BY eventtime DESC;
  SQL
}

# Cross-account activity (external principals)
resource "aws_athena_named_query" "view_cross_account_activity" {
  database = aws_athena_database.audit.name
  name     = "view-cross-account-activity"
  workgroup = aws_athena_workgroup.audit.name
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.cross_account_activity AS
    SELECT
      eventtime,
      eventname,
      eventsource,
      useridentity.arn as actor_arn,
      useridentity.accountid as actor_account,
      useridentity.type as actor_type,
      sourceipaddress,
      requestparameters,
      errorcode
    FROM cloudtrail_management
    WHERE useridentity.accountid != '${var.account_id}'
      AND useridentity.type != 'AWSService'
    ORDER BY eventtime DESC;
  SQL
}

# Root account activity
resource "aws_athena_named_query" "view_root_activity" {
  database = aws_athena_database.audit.name
  name     = "view-root-activity"
  workgroup = aws_athena_workgroup.audit.name
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.root_activity AS
    SELECT
      eventtime,
      eventname,
      eventsource,
      sourceipaddress,
      useragent,
      requestparameters,
      errorcode
    FROM cloudtrail_management
    WHERE useridentity.type = 'Root'
    ORDER BY eventtime DESC;
  SQL
}

# -------------------------------------------------------------------
# Outputs
# -------------------------------------------------------------------

output "database_name" {
  value       = aws_athena_database.audit.name
  description = "Athena database name"
}

output "workgroup_name" {
  value       = aws_athena_workgroup.audit.name
  description = "Athena workgroup name"
}

output "athena_tables" {
  value = {
    cloudtrail_management = "cloudtrail_management"
    cloudtrail_s3_data    = "cloudtrail_s3_data"
    vpc_flowlogs          = "vpc_flowlogs"
    elb_accesslogs        = "elb_accesslogs"
    config_snapshots      = "config_snapshots"
    config_resources      = "config_resources"
    guardduty_findings    = "guardduty_findings"
  }
  description = "All Athena table names"
}

output "shared_views" {
  value = [
    "shared.resource_timeline",
    "shared.iam_activity",
    "shared.s3_bucket_activity",
    "shared.sg_activity",
    "shared.failed_api_calls",
    "shared.cross_account_activity",
    "shared.root_activity"
  ]
  description = "Shared Athena views for all members"
}

output "query_results_location" {
  value       = "s3://${aws_s3_bucket.audit_logs.bucket}/athena/results/"
  description = "Athena query results S3 location"
}