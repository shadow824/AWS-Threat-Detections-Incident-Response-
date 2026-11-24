# 🛡️ AWS Threat Detection & Incident Response - Audit Logs Foundation

> **Terraform module for centralized audit logging infrastructure on AWS Free Tier**
>
> **Part of:** [AWS Threat Detection & Incident Response](https://github.com/shadow824/AWS-Threat-Detections-Incident-Response-) project
>
> **Team:** 5 members | **Provider:** AWS | **IaC:** Terraform | **Tier:** Free Tier optimized

[![Terraform](https://img.shields.io/badge/Terraform-1.5%2B-7B42BC?logo=terraform)](https://www.terraform.io/)
[![AWS Provider](https://img.shields.io/badge/AWS%20Provider-6.0%2B-FF9900?logo=amazon-aws)](https://registry.terraform.io/providers/hashicorp/aws/latest)
[![License](https://img.shields.io/badge/License-Internal%20Use-blue)](LICENSE)
[![Free Tier](https://img.shields.io/badge/Cost-Free%20Tier%20Optimized-brightgreen)](COST.md)

---

## 📖 Project Overview

This repository contains **Member 1's Audit Logs Foundation** - the centralized logging infrastructure for a 5-member AWS Threat Detection & Incident Response team.

### 👥 Team Structure

| Member | Role | Responsibility | Consumes |
|--------|------|----------------|----------|
| **Member 1** | **Logging & Audit** | Central audit infrastructure | — (Producer) |
| **Member 2** | **Network Monitoring & Forensics** | VPC Flow Logs, ELB, Network threats | VPC Flow Logs, ELB, CloudTrail |
| **Member 3** | **S3 Security & Data Analytics** | S3 object access, Data exfiltration | S3 Data Events, CloudTrail S3 |
| **Member 4** | **Cloud Security & Compliance** | Config drift, Compliance, Remediation | Config, CloudTrail |
| **Member 5** | **Threat Detection & IR** | GuardDuty, MITRE ATT&CK, SOAR | Everything (Correlation) |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CENTRAL AUDIT S3 BUCKET                              │
│  (SSE-KMS, Versioning, Lifecycle: Standard→IA→Glacier→Deep Archive→Delete)  │
│  ├── cloudtrail/management/     → All members (API activity)                │
│  ├── cloudtrail/data/s3/        → Member 3 (S3 object access)               │
│  ├── vpc/flowlogs/              → Member 2 (Network traffic)                │
│  ├── elb/accesslogs/            → Member 2 (HTTP/HTTPS traffic)             │
│  ├── config/snapshots/          → Member 4 (Resource config history)        │
│  ├── guardduty/findings/        → Member 5 (Threat findings)                │
│  └── athena/results/            → All members (Query results)               │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
            │   ATHENA    │ │ CLOUDWATCH  │ │ SECURITY    │
            │  WORKGROUP  │ │ LOG GROUPS  │ │    HUB      │
            │ (Queries)   │ │ (Real-time) │ │(Centralized)│
            └─────────────┘ └─────────────┘ └─────────────┘
                    │               │               │
         ┌──────────┴──────────┐    │               │
         ▼                     ▼    ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  Member 2       │ │  Member 3       │ │  Member 4       │
│  Network        │ │  Storage        │ │  Compliance     │
│  (VPC, ELB,     │ │  (S3 Data       │ │  (Config,       │
│   CloudTrail)   │ │   Events)       │ │   CloudTrail)   │
└─────────────────┘ └─────────────────┘ ┌─────────────────┘
         │                     │                     │
         └─────────────────────┼─────────────────────┘
                               ▼
                    ┌─────────────────┐
                    │  Member 5       │
                    │  Detection      │
                    │  (Everything +  │
                    │   GuardDuty +   │
                    │   Correlation)  │
                    └─────────────────┘
```

---

## 📦 What This Module Creates

| Component | Purpose | Free Tier Cost |
|-----------|---------|----------------|
| **S3 Bucket** | Central encrypted storage with lifecycle | 5 GB free |
| **KMS Key** | Dedicated encryption key with rotation | 1 key free |
| **CloudTrail (Management)** | All control-plane API calls | FREE (1st trail) |
| **CloudTrail (S3 Data Events)** | Object-level S3 API calls | ~$0.10/100k events |
| **VPC Flow Logs** | Network traffic (REJECT only) | FREE |
| **ELB Access Logs** | HTTP/HTTPS request logs | FREE (S3 storage) |
| **AWS Config** | Resource configuration history | 10k items free/month |
| **GuardDuty** | Threat detection | 30-day trial |
| **Athena** | Query engine with workgroup | $5/TB scanned |
| **IAM Roles** | Least-privilege per-member access | FREE |

---

## 🚀 Quick Start

### 1. Prerequisites
- Terraform >= 1.5.0
- AWS CLI configured with appropriate permissions
- AWS Account ID (12 digits)

### 2. Configure Variables

Create `terraform.tfvars` (or `test.auto.tfvars`):

```hcl
account_id              = "YOUR_12_DIGIT_ACCOUNT_ID"
region                  = "us-east-1"
environment             = "free-tier"
org_ready               = false
is_free_tier            = true

vpc_ids                 = ["vpc-YOUR_VPC_ID"]  # Empty [] if no VPCs yet
flowlogs_traffic_type   = "REJECT"

cloudtrail_data_event_buckets = []  # Add critical S3 buckets if needed

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
  "member-2"     = "arn:aws:iam::YOUR_ACCOUNT:user/TeamNetworkUser"
  "member-3"     = "arn:aws:iam::YOUR_ACCOUNT:user/TeamStorageUser"
  "member-4"     = "arn:aws:iam::YOUR_ACCOUNT:user/TeamComplianceUser"
  "member-5"     = "arn:aws:iam::YOUR_ACCOUNT:user/TeamDetectionUser"
  "audit-admin"  = "arn:aws:iam::YOUR_ACCOUNT:user/YourAdminUser"
}
```

### 3. Deploy

```bash
terraform init
terraform plan
terraform apply
```

### 4. Share Outputs with Team

```bash
# Member 2 (Network)
terraform output -json member2_network_handoff > member2_handoff.json

# Member 3 (Storage)
terraform output -json member3_storage_handoff > member3_handoff.json

# Member 4 (Compliance)
terraform output -json member4_compliance_handoff > member4_handoff.json

# Member 5 (Detection)
terraform output -json member5_detection_handoff > member5_handoff.json

# Member 1 (Self - Audit Admin)
terraform output -json member1_audit_admin_handoff > member1_handoff.json
```

---

## 🔑 Member Handoff Details

### Member 2 - Network Monitoring & Forensics
- **Tables:** `vpc_flowlogs`, `elb_accesslogs`, `cloudtrail_management`
- **Key Views:** `shared.suspicious_connections`, `shared.port_scanning`, `shared.sqli_attempts`
- **IAM Role:** `audit-read-network-{env}` (VPC/ELB/CloudTrail network events)

### Member 3 - S3 Security & Data Analytics
- **Tables:** `cloudtrail_s3_data`, `cloudtrail_management`, `config_resources`
- **Key Views:** `shared.external_s3_access`, `shared.s3_bucket_changes`
- **IAM Role:** `audit-read-storage-{env}` (S3 object-level access)

### Member 4 - Cloud Security & Compliance
- **Tables:** `config_snapshots`, `config_resources`, `cloudtrail_management`
- **Key Views:** `shared.unapproved_changes`, `shared.resource_drift`, `shared.sg_changes`
- **IAM Role:** `audit-read-compliance-{env}` (+ Config API)

### Member 5 - Threat Detection & Incident Response
- **Tables:** All 7 tables
- **Key Views:** `shared.guardduty_enriched`, `shared.compromised_ec2`, `shared.exposed_access_keys`, `shared.mitre_attack_mapping`
- **IAM Role:** `audit-read-detection-{env}` (Full access + GuardDuty/Security Hub/Detective APIs)

---

## 🔒 Security Design

| Principle | Implementation |
|-----------|----------------|
| **Least Privilege** | Dedicated role per member, S3 prefix restrictions, KMS conditions |
| **Encryption** | SSE-KMS with dedicated key, annual rotation, service-specific key policies |
| **Data Integrity** | CloudTrail log file validation (SHA-256), S3 versioning, MFA Delete ready |
| **Network Security** | Service principals with `aws:SourceAccount`, VPC-restricted roles, no public access |

---

## 💰 Free Tier Optimizations

| Setting | Value | Savings |
|---------|-------|---------|
| Flow Logs Traffic Type | `REJECT` only | Captures attacks/recon, free |
| CloudTrail Data Events | Opt-in only | Costs money, only critical buckets |
| Config Resource Types | 6 targeted types | Under 10k free items/month |
| Config Frequency | `TwentyFour_Hours` | Continuous costs more |
| GuardDuty | 30-day trial | Enable, evaluate, decide |
| Athena Workgroup | 10 GB/query limit | Prevents runaway queries |
| S3 Lifecycle | 30→90→365→2555 days | Minimizes Standard storage |

---

## 💰 Cost Estimation (us-east-1, typical)

| Component | Monthly Cost |
|-----------|-------------|
| CloudTrail Management | **FREE** |
| CloudTrail Data Events | ~$5-50 (if enabled) |
| CloudWatch Logs | **FREE** (5 GB) |
| S3 Storage | **FREE** (5 GB) + Glacier pennies |
| VPC Flow Logs (REJECT) | **FREE** |
| ELB Access Logs | **FREE** |
| AWS Config | **FREE** (10k items) |
| GuardDuty | **FREE** (30 days) then ~$4/GB |
| Athena Queries | ~$1-10 (partition pruning) |
| KMS Requests | ~$0.10 |
| **Total** | **$0-60/month** |

---

## 🔄 Organization Migration Path

```hcl
# When ready for multi-account:
org_ready = true
```

**Auto-migration on apply:**
1. Enable `is_organization_trail` on CloudTrail
2. Keep single-account trail as backup
4. Member roles work unchanged
5. Member 5 adds cross-account Athena queries

**Manual steps:**
1. Management account: Enable CloudTrail Organization Trail
2. Update member IAM roles for cross-account access if needed

---

## 📁 Repository Structure

```
├── versions.tf              # Terraform & provider versions (AWS 6.0+, Random 3.0+)
├── variables.tf             # All configurable variables with validation
├── main.tf                  # Orchestration (data sources, random)
├── backend.tf               # S3 backend + provider config (AWS 6.0+)
├── s3_bucket.tf             # S3 bucket, KMS, lifecycle, bucket policy
├── cloudtrail.tf            # CloudTrail (mgmt + data), CW metric filters, alarms
├── vpc_flowlogs.tf          # VPC Flow Logs (Parquet), Athena tables, views
├── elb_logs.tf              # ELB Access Logs, Athena tables, views
├── config_recorder.tf       # AWS Config recorder, Athena tables, views
├── guardduty.tf             # GuardDuty detector, publishing, Athena tables, views
├── athena.tf                # Athena workgroup, database, shared tables/views
├── iam_roles.tf             # Least-privilege roles per member (6 roles)
├── outputs.tf               # Consolidated handoff packages (35+ outputs)
├── variables.tf             # All configurable variables with validation
├── versions.tf              # Terraform & provider versions
├── Makefile                 # 20+ targets (init, plan, apply, test-athena, outputs)
├── scripts/
│   └── validate_athena.sh   # Post-deploy Athena validation script
├── test.auto.tfvars         # Example variables (replace with real values)
├── backend.tf               # S3 backend config (depi-team-5-tfstate)
└── README.md                # This file
```

---

## 🛠️ Makefile Targets

```bash
make init              # Initialize Terraform
make plan              # Show execution plan
make apply             # Apply the plan
make validate          # Validate syntax & formatting
make test-athena       # Test all Athena tables/views
make output-member2    # Show Member 2 handoff
make output-member3    # Show Member 3 handoff
make output-member4    # Show Member 4 handoff
make output-member5    # Show Member 5 handoff
make output-member1    # Show Member 1 (audit admin) handoff
make output-cost       # Show cost estimate
make help              # Show all targets
```

---

## ✅ Validation & Testing

```bash
# Validate Terraform syntax
terraform validate

# Plan with your account
terraform plan -var="account_id=YOUR_ACCOUNT_ID" -var="region=us-east-1"

# Test Athena tables (after apply)
aws athena start-query-execution \
  --query-string "SELECT * FROM cloudtrail_management LIMIT 10;" \
  --work-group audit-logs-workgroup \
  --result-configuration OutputLocation=s3://audit-logs-.../athena/results/

# Run validation script
./scripts/validate_athena.sh
```

---

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| Athena table shows no data | Wait 1-2 hours; check partition projection matches S3 path |
| CloudTrail not logging | `aws cloudtrail get-trail-status --name audit-management-trail` |
| VPC Flow Logs not appearing | Verify IAM role has `s3:PutObject` to correct prefix |
| GuardDuty findings not in S3 | Check publishing destination; verify KMS key policy |
| Member can't query Athena | Verify they assume correct role; check workgroup name |
| KMS AccessDenied | Verify bucket policy condition `kms:EncryptionContext:aws:s3:arn` |

---

## ✅ Security Checklist (Pre-Deploy)

- [ ] `account_id` is correct 12-digit AWS Account ID
- [ ] `vpc_ids` are valid and owned by this account (or `[]` if none yet)
- [ ] `cloudtrail_data_event_buckets` are critical buckets only (cost control)
- [ ] `member_iam_principals` are actual team user/role ARNs
- [ ] `config_resource_types` limited to stay under Free Tier (6 types)
- [ ] `org_ready = false` (Free Tier doesn't support Organization Trail)
- [ ] KMS key deletion window >= 7 days (compliance)
- [ ] S3 lifecycle delete >= 2555 days (7 years compliance)
- [ ] Athena workgroup bytes_scanned_cutoff_per_query set (cost control)

---

## 🤝 Contributing

1. Changes to module → update relevant `.tf` file + this README
2. Test in local environment before PR
3. Update handoff outputs if new tables/views added
4. Keep Free Tier optimizations in mind
5. Run `terraform validate` and `make validate` before commit

---

## 📄 License

Internal use only - Audit Logs Foundation for AWS Threat Detection & Incident Response Team

---

## 🔗 Related Repositories

- **Main Project:** [AWS-Threat-Detections-Incident-Response](https://github.com/shadow824/AWS-Threat-Detections-Incident-Response-)
- **Member 2 - Network:** (TBD)
- **Member 3 - Storage:** (TBD)
- **Member 4 - Compliance:** (TBD)
- **Member 5 - Detection:** (TBD)

---

*Built with ❤️ by the AWS Threat Detection & Incident Response Team*