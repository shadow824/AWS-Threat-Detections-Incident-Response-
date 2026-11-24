# ===================================================================
# ELB/ALB Access Logs - HTTP/HTTPS Traffic Visibility (Member 2)
# ===================================================================
# Security Design Decisions:
# - S3 destination = same bucket, different prefix
# - Bucket policy allows ELB service to write (configured in s3_bucket.tf)
# - Interval: 5 or 60 minutes (60 min = fewer files, cheaper)
# - Member 2 uses this for: WAF bypass, SQLi, path traversal, bot detection
# ===================================================================

# -------------------------------------------------------------------
# This module configures the S3 bucket for ELB logs.
# Actual ALB/NLB resources are created elsewhere (Member 2's infra).
# Member 2 enables access_logs on their ALB pointing to this bucket/prefix.
# ===================================================================

# The bucket policy in s3_bucket.tf already allows:
#   Principal: elasticloadbalancing.<region>.<partition>
#   Action: s3:PutObject
#   Resource: arn:aws:s3:::audit-logs-.../elb/accesslogs/*

# Member 2's ALB configuration (reference - they apply this):
# resource "aws_lb" "example" {
#   # ... other config ...
#   access_logs {
#     bucket  = module.audit_logs.bucket_id
#     prefix  = "elb/accesslogs/"
#     enabled = true
#   }
# }

# -------------------------------------------------------------------
# Athena Table for ELB Access Logs
# -------------------------------------------------------------------
# WHY this schema:
# - Standard ELB log format (space-delimited)
# - Partitioned by date for cost control
# - RegexSerDe parses the log format

resource "aws_athena_named_query" "elb_accesslogs_table" {
  database = aws_athena_database.audit.name
  name     = "create-elb-accesslogs-table"
  query = <<-SQL
    CREATE EXTERNAL TABLE IF NOT EXISTS elb_accesslogs (
      type STRING,
      time STRING,
      elb STRING,
      client_ip STRING,
      client_port INT,
      target_ip STRING,
      target_port INT,
      request_processing_time DOUBLE,
      target_processing_time DOUBLE,
      response_processing_time DOUBLE,
      elb_status_code STRING,
      target_status_code STRING,
      received_bytes BIGINT,
      sent_bytes BIGINT,
      request_verb STRING,
      request_url STRING,
      request_proto STRING,
      user_agent STRING,
      ssl_cipher STRING,
      ssl_protocol STRING,
      target_group_arn STRING,
      trace_id STRING,
      domain_name STRING,
      chosen_cert_arn STRING,
      matched_rule_priority STRING,
      request_creation_time STRING,
      actions_executed STRING,
      redirect_url STRING,
      error_reason STRING,
      target_port_list STRING,
      target_status_code_list STRING,
      classification STRING,
      classification_reason STRING
    )
    PARTITIONED BY (year STRING, month STRING, day STRING)
    ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
    WITH SERDEPROPERTIES (
      'input.regex' = '^([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) ([^ ]*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^\"]*)\"$'
    )
    LOCATION 's3://${aws_s3_bucket.audit_logs.bucket}/elb/accesslogs/'
    TBLPROPERTIES (
      'projection.enabled' = 'true',
      'projection.year.type' = 'integer',
      'projection.year.range' = '2020,2030',
      'projection.month.type' = 'integer',
      'projection.month.range' = '1,12',
      'projection.day.type' = 'integer',
      'projection.day.range' = '1,31',
      'storage.location.template' = 's3://${aws_s3_bucket.audit_logs.bucket}/elb/accesslogs/AWSLogs/${var.account_id}/elasticloadbalancing/${var.region}/$${year}/$${month}/$${day}/'
    );
  SQL
}

# -------------------------------------------------------------------
# Shared Views for Member 2 (HTTP Analysis)
# -------------------------------------------------------------------

# HTTP 4xx/5xx errors
resource "aws_athena_named_query" "view_elb_errors" {
  database = aws_athena_database.audit.name
  name     = "view-elb-errors"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.elb_errors AS
    SELECT
      time, elb, client_ip, target_ip,
      request_verb, request_url,
      elb_status_code, target_status_code,
      error_reason, classification, classification_reason,
      user_agent, received_bytes, sent_bytes
    FROM elb_accesslogs
    WHERE CAST(elb_status_code AS INT) >= 400
       OR CAST(target_status_code AS INT) >= 400
    ORDER BY time DESC;
  SQL
}

# Suspicious User Agents (bots, scanners)
resource "aws_athena_named_query" "view_suspicious_ua" {
  database = aws_athena_database.audit.name
  name     = "view-suspicious-ua"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.suspicious_user_agents AS
    SELECT
      time, client_ip, elb, request_verb, request_url,
      user_agent, elb_status_code, target_status_code
    FROM elb_accesslogs
    WHERE LOWER(user_agent) RLIKE '(sqlmap|nmap|nikto|dirb|gobuster|w3af|acunetix|nessus|burp|zap|scanner|bot|crawler|spider|python-requests|go-http-client|curl|wget|httpclient|apache-httpclient|okhttp|axios|postman|insomnia|postmanruntime|httpx|nuclei|jaeles|dalfox|ffuf|feroxbuster|katana|subfinder|amass|assetfinder|findomain|chaos|httprobe|httpx|naabu|dnsx|tlsx|cdnx|subzy|gitdorks|githack|trufflehog|gitleaks|gitrob|gitgraber|gitminer|gitfinder|gitrecon|gitenum|gitscan|gitspy|gitwatch|gitmonitor|gitalert|gitnotify|gitwebhook|gitbot|gitcrawler|gitscanner|gitauditor|gitsecurity|gitvuln|gitexploit|gitattack|gitbreach|gitleak|gitsecret|gitcred|gittoken|gitkey|gitpass|gitauth|gitlogin|gitsession|gitcookie|githeader|gitparam|gitquery|gitbody|gitpayload|gitexploit|gitrce|gitsqli|gitxss|gitlfi|gitrfi|gitssti|gitxxe|gitdeserial|gitssrf|gitidor|gitauthbypass|gitprivilege|gitacl|gitrbac|gitpermission|gitaccess|gitauthz|gitauthn|gitidentity|gitaccount|gituser|gitadmin|gitroot|gitsudo|gitshell|gitcmd|gitexec|gitcode|gitscript|gitpayload|gitinject|gitoverflow|gitmem|githeap|gitstack|gitrop|gitjop|gitsys|gitexecve|gitsystem|gitpopen|gitsh|gitbash|gitzsh|gitfish|gitcsh|gittcsh|gitshell|gitterminal|gitconsole|gitcli|gitcommand|gitarg|gitenv|gitvar|gitconfig|gitconf|gitfile|gitdir|gitpath|giturl|gituri|gitendpoint|gitapi|gitservice|gitmicro|gitmesh|gitcloud|gitk8s|gitdocker|gitcontainer|gitpod|gitnode|gitsvc|gitdeploy|gitbuild|gitci|gitcd|gitpipeline|gitstage|gitprod|gitdev|gittest|gitstaging|gitqa|gituat|gitpreprod|gitdemo|gitsandbox|gitlab|gitci|gitrunner|gitjob|gitbuild|gitartifact|gitpackage|gitrelease|gitversion|gittag|gitbranch|gitcommit|githash|gitdiff|gitpatch|gitmerge|gitrebase|gitcherry|gitapply|gitstash|gitreset|gitcheckout|gitswitch|gitrestore|gitclean|gitfetch|gitpull|gitpush|gitremote|gitorigin|gitupstream|gitfork|gitclone|gitinit|gitadd|gitcommit|gitstatus|gitlog|gitshow|gitblame|gitdiff|gitgrep|gitsearch|gitfind|gitls|gittree|gitcat|gitshow|gitdump|gitexport|gitimport|gitbundle|gitarchive|gittar|gitzip|gitgz|gitbz2|gitxz|gitlz4|gitzstd|gitcompress|gitdecompress|gitencrypt|gitdecrypt|gitsign|gitverify|gittrust|gitkeys|gitgpg|gitpgp|gitssh|gitssl|gittls|gitcert|gitkey|gitca|gitcrl|gitocsp|gitpin|githsts|githpkp|gitexpectct|gitreferrer|gitcsp|gitfeature|gitpermissions|gitcrossorigin|gitcorp|gitcoop|gitcred|gitfetch|gitpush|gitpull|gitmerge|gitrebase|gitcherry|gitapply|gitstash|gitreset|gitcheckout|gitswitch|gitrestore|gitclean|gitfetch|gitpull|gitpush|gitremote|gitorigin|gitupstream|gitfork|gitclone|gitinit|gitadd|gitcommit|gitstatus|gitlog|gitshow|gitblame|gitdiff|gitgrep|gitsearch|gitfind|gitls|gittree|gitcat|gitshow|gitdump|gitexport|gitimport|gitbundle|gitarchive|gittar|gitzip|gitgz|gitbz2|gitxz|gitlz4|gitzstd|gitcompress|gitdecompress|gitencrypt|gitdecrypt|gitsign|gitverify|gittrust|gitkeys|gitgpg|gitpgp|gitssh|gitssl|gittls|gitcert|gitkey|gitca|gitcrl|gitocsp|gitpin|githsts|githpkp|gitexpectct|gitreferrer|gitcsp|gitfeature|gitpermissions|gitcrossorigin|gitcorp|gitcoop|gitcred)'
    ORDER BY time DESC
    LIMIT 1000;
  SQL
}

# SQL Injection attempts in URL
resource "aws_athena_named_query" "view_sqli_attempts" {
  database = aws_athena_database.audit.name
  name     = "view-sqli-attempts"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.sqli_attempts AS
    SELECT
      time, client_ip, elb, request_verb, request_url,
      user_agent, elb_status_code, target_status_code
    FROM elb_accesslogs
    WHERE LOWER(request_url) RLIKE '(union\\s+select|select\\s+.*\\s+from|insert\\s+into|update\\s+.*\\s+set|delete\\s+from|drop\\s+table|create\\s+table|alter\\s+table|exec\\s*\\(|execute\\s*\\(|xp_cmdshell|sp_executesql|benchmark\\(|sleep\\(|waitfor\\s+delay|pg_sleep|dbms_pipe|utl_http|utl_file|utl_tcp|utl_smtp|dbms_ldap|dbms_java|dbms_xmlquery|dbms_xmlgen|xmltype|extractvalue|updatexml|floor\\(|rand\\(|count\\(|group\\s+by|having\\s+|order\\s+by|limit\\s+|offset\\s+|information_schema|sysobjects|syscolumns|systables|sysusers|sysdatabases|master\\.\\.|msdb\\.\\.|tempdb\\.\\.|model\\.\\.|@@version|@@servername|@@database|user\\(|database\\(|schema\\(|connection_id\\(|last_insert_id\\(|row_count\\(|found_rows\\(|benchmark\\(|sleep\\(|waitfor|delay|pg_sleep|dbms_lock|dbms_pipe|dbms_alert|dbms_job|dbms_scheduler|dbms_aq|dbms_stream|dbms_cdc|dbms_logmnr|dbms_metadata|dbms_xmlschema|dbms_xmlsave|dbms_xmldom|dbms_xslprocessor|dbms_xdb|dbms_xdbz|dbms_xdbt|dbms_xdb_version|dbms_xdb_config|dbms_xdb_constants|dbms_xdb_admin|dbms_xdb_utils|dbms_xdb_t|dbms_xdb_p|dbms_xdb_i|dbms_xdb_r|dbms_xdb_u|dbms_xdb_v|dbms_xdb_w|dbms_xdb_x|dbms_xdb_y|dbms_xdb_z)'
    ORDER BY time DESC
    LIMIT 500;
  SQL
}

# Path traversal attempts
resource "aws_athena_named_query" "view_path_traversal" {
  database = aws_athena_database.audit.name
  name     = "view-path-traversal"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.path_traversal AS
    SELECT
      time, client_ip, elb, request_verb, request_url,
      user_agent, elb_status_code, target_status_code
    FROM elb_accesslogs
    WHERE request_url RLIKE '(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f|%252e%252e%255c|\\.\\.%2f|\\.\\.%5c|..%2f|..%5c|%2e%2e/|%2e%2e\\\\|%252e%252e/|%252e%252e\\\\)'
    ORDER BY time DESC
    LIMIT 500;
  SQL
}

# Top attacking IPs
resource "aws_athena_named_query" "view_top_attacking_ips" {
  database = aws_athena_database.audit.name
  name     = "view-top-attacking-ips"
  query = <<-SQL
    CREATE OR REPLACE VIEW shared.top_attacking_ips AS
    SELECT
      client_ip,
      COUNT(*) as total_requests,
      COUNT(DISTINCT request_url) as unique_urls,
      SUM(CASE WHEN CAST(elb_status_code AS INT) >= 400 THEN 1 ELSE 0 END) as error_count,
      SUM(CASE WHEN LOWER(request_url) RLIKE '(union|select|insert|update|delete|drop|create|alter|exec|sleep|benchmark)' THEN 1 ELSE 0 END) as sqli_attempts,
      SUM(CASE WHEN request_url RLIKE '(\\.\\./|\\.\\.\\\\|%2e%2e%2f)' THEN 1 ELSE 0 END) as traversal_attempts,
      MIN(time) as first_seen,
      MAX(time) as last_seen
    FROM elb_accesslogs
    GROUP BY client_ip
    HAVING error_count > 10 OR sqli_attempts > 0 OR traversal_attempts > 0
    ORDER BY (error_count + sqli_attempts * 10 + traversal_attempts * 10) DESC
    LIMIT 100;
  SQL
}

# -------------------------------------------------------------------
# Outputs
# -------------------------------------------------------------------

output "elb_accesslogs_prefix" {
  value       = "elb/accesslogs/"
  description = "S3 prefix for ELB access logs"
}

output "elb_athena_table" {
  value       = "elb_accesslogs"
  description = "Athena table name for ELB access logs"
}

output "elb_shared_views" {
  value = [
    "shared.elb_errors",
    "shared.suspicious_user_agents",
    "shared.sqli_attempts",
    "shared.path_traversal",
    "shared.top_attacking_ips"
  ]
  description = "Shared Athena views for Member 2 HTTP analysis"
}