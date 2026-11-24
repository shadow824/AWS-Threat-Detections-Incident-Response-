# ===================================================================
# Makefile - Audit Logs Module Operations
# ===================================================================
# Usage: make <target>
# Targets: init, plan, apply, validate, test-athena, outputs, clean

# Configuration - override via environment or command line
ACCOUNT_ID ?= 123456789012
REGION ?= us-east-1
ENVIRONMENT ?= free-tier
TERRAFORM_DIR = .

# Colors for output
GREEN = \033[0;32m
YELLOW = \033[1;33m
RED = \033[0;31m
NC = \033[0m # No Color

.PHONY: help init validate plan apply test-athena outputs clean docs

help: ## Show this help
	@echo "$(GREEN)Audit Logs Module - Available Targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

init: ## Initialize Terraform (download providers)
	@echo "$(GREEN)Initializing Terraform...$(NC)"
	cd $(TERRAFORM_DIR) && terraform init -upgrade

validate: ## Validate Terraform syntax and formatting
	@echo "$(GREEN)Validating Terraform...$(NC)"
	cd $(TERRAFORM_DIR) && terraform fmt -check -recursive
	cd $(TERRAFORM_DIR) && terraform validate

plan: ## Show execution plan
	@echo "$(GREEN)Planning Terraform...$(NC)"
	cd $(TERRAFORM_DIR) && terraform plan \
		-var="account_id=$(ACCOUNT_ID)" \
		-var="region=$(REGION)" \
		-var="environment=$(ENVIRONMENT)" \
		-out=tfplan

apply: ## Apply the plan
	@echo "$(GREEN)Applying Terraform...$(NC)"
	cd $(TERRAFORM_DIR) && terraform apply tfplan

apply-auto: ## Apply without saved plan (interactive)
	@echo "$(GREEN)Applying Terraform (auto-approve)...$(NC)"
	cd $(TERRAFORM_DIR) && terraform apply \
		-var="account_id=$(ACCOUNT_ID)" \
		-var="region=$(REGION)" \
		-var="environment=$(ENVIRONMENT)" \
		-auto-approve

destroy: ## Destroy all resources (DANGEROUS)
	@echo "$(RED)WARNING: This will destroy all audit log resources!$(NC)"
	@read -p "Type 'yes' to confirm: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		cd $(TERRAFORM_DIR) && terraform destroy \
			-var="account_id=$(ACCOUNT_ID)" \
			-var="region=$(REGION)" \
			-var="environment=$(ENVIRONMENT)"; \
	else \
		echo "Aborted."; \
	fi

test-athena: ## Test Athena tables after deployment
	@echo "$(GREEN)Testing Athena tables...$(NC)"
	@WORKGROUP=$$(cd $(TERRAFORM_DIR) && terraform output -raw workgroup_name 2>/dev/null || echo "audit-logs-workgroup"); \
	DATABASE=$$(cd $(TERRAFORM_DIR) && terraform output -raw database_name 2>/dev/null || echo "audit_logs"); \
	RESULTS=$$(cd $(TERRAFORM_DIR) && terraform output -raw query_results_location 2>/dev/null); \
	echo "Workgroup: $$WORKGROUP"; \
	echo "Database: $$DATABASE"; \
	echo "Results: $$RESULTS"; \
	for table in cloudtrail_management vpc_flowlogs elb_accesslogs config_resources guardduty_findings; do \
		echo "\n--- Testing $$table ---"; \
		aws athena start-query-execution \
			--query-string "SELECT * FROM $$table LIMIT 5;" \
			--work-group $$WORKGROUP \
			--result-configuration OutputLocation=$$RESULTS \
			--query 'QueryExecutionId' --output text; \
	done

test-athena-views: ## Test shared Athena views
	@echo "$(GREEN)Testing Athena shared views...$(NC)"
	@WORKGROUP=$$(cd $(TERRAFORM_DIR) && terraform output -raw workgroup_name 2>/dev/null || echo "audit-logs-workgroup"); \
	RESULTS=$$(cd $(TERRAFORM_DIR) && terraform output -raw query_results_location 2>/dev/null); \
	for view in resource_timeline iam_activity suspicious_connections high_severity_findings guardduty_enriched; do \
		echo "\n--- Testing shared.$$view ---"; \
		aws athena start-query-execution \
			--query-string "SELECT * FROM shared.$$view LIMIT 5;" \
			--work-group $$WORKGROUP \
			--result-configuration OutputLocation=$$RESULTS \
			--query 'QueryExecutionId' --output text; \
	done

outputs: ## Show all outputs as JSON
	@echo "$(GREEN)All module outputs:$(NC)"
	cd $(TERRAFORM_DIR) && terraform output -json

output-member2: ## Show Member 2 handoff
	cd $(TERRAFORM_DIR) && terraform output -json member2_network_handoff | jq .

output-member3: ## Show Member 3 handoff
	cd $(TERRAFORM_DIR) && terraform output -json member3_storage_handoff | jq .

output-member4: ## Show Member 4 handoff
	cd $(TERRAFORM_DIR) && terraform output -json member4_compliance_handoff | jq .

output-member5: ## Show Member 5 handoff
	cd $(TERRAFORM_DIR) && terraform output -json member5_detection_handoff | jq .

output-member1: ## Show Member 1 (self) handoff
	cd $(TERRAFORM_DIR) && terraform output -json member1_audit_admin_handoff | jq .

output-cost: ## Show cost estimate
	cd $(TERRAFORM_DIR) && terraform output -json free_tier_cost_estimate | jq .

output-org: ## Show org migration info
	cd $(TERRAFORM_DIR) && terraform output -json org_migration | jq .

docs: ## Generate documentation (requires terraform-docs)
	@echo "$(GREEN)Generating documentation...$(NC)"
	cd $(TERRAFORM_DIR) && terraform-docs markdown table --output-file README.md .

check-iam: ## Verify IAM roles and policies
	@echo "$(GREEN)Checking IAM roles...$(NC)"
	@for role in audit-read-network audit-read-storage audit-read-compliance audit-read-detection audit-admin; do \
		echo "\n--- $$role-$(ENVIRONMENT) ---"; \
		aws iam get-role --role-name $$role-$(ENVIRONMENT) 2>/dev/null | jq '.Role.Arn' || echo "Role not found"; \
	done

check-bucket: ## Verify S3 bucket configuration
	@echo "$(GREEN)Checking S3 bucket...$(NC)"
	@BUCKET=$$(cd $(TERRAFORM_DIR) && terraform output -raw bucket_id 2>/dev/null); \
	if [ -n "$$BUCKET" ]; then \
		echo "Bucket: $$BUCKET"; \
		aws s3api get-bucket-versioning --bucket $$BUCKET | jq .; \
		aws s3api get-bucket-encryption --bucket $$BUCKET | jq .; \
		aws s3api get-bucket-lifecycle-configuration --bucket $$BUCKET | jq .; \
		aws s3api get-bucket-policy --bucket $$BUCKET | jq .Policy | jq .; \
	else \
		echo "Bucket not deployed yet"; \
	fi

check-cloudtrail: ## Verify CloudTrail status
	@echo "$(GREEN)Checking CloudTrail...$(NC)"
	@TRAIL=$$(cd $(TERRAFORM_DIR) && terraform output -raw management_trail_name 2>/dev/null); \
	if [ -n "$$TRAIL" ]; then \
		aws cloudtrail get-trail-status --name $$TRAIL | jq .; \
	else \
		echo "CloudTrail not deployed yet"; \
	fi

check-config: ## Verify AWS Config status
	@echo "$(GREEN)Checking AWS Config...$(NC)"
	@RECORDER=$$(cd $(TERRAFORM_DIR) && terraform output -raw config_recorder_name 2>/dev/null); \
	if [ -n "$$RECORDER" ]; then \
		aws configservice describe-configuration-recorders --configuration-recorder-names $$RECORDER | jq .; \
		aws configservice describe-configuration-recorder-status --configuration-recorder-names $$RECORDER | jq .; \
	else \
		echo "Config not deployed yet"; \
	fi

check-guardduty: ## Verify GuardDuty status
	@echo "$(GREEN)Checking GuardDuty...$(NC)"
	@DETECTOR=$$(cd $(TERRAFORM_DIR) && terraform output -raw detector_id 2>/dev/null); \
	if [ -n "$$DETECTOR" ]; then \
		aws guardduty get-detector --detector-id $$DETECTOR | jq .; \
	else \
		echo "GuardDuty not deployed yet"; \
	fi

# Full deployment pipeline
deploy: init validate plan apply test-athena outputs ## Full deploy pipeline

# Quick commands
quick-plan: ## Quick plan with defaults
	$(MAKE) plan ACCOUNT_ID=$(ACCOUNT_ID) REGION=$(REGION) ENVIRONMENT=$(ENVIRONMENT)

quick-apply: ## Quick apply with defaults
	$(MAKE) apply-auto ACCOUNT_ID=$(ACCOUNT_ID) REGION=$(REGION) ENVIRONMENT=$(ENVIRONMENT)

# Cleanup
clean: ## Clean Terraform files
	@echo "$(GREEN)Cleaning Terraform files...$(NC)"
	cd $(TERRAFORM_DIR) && rm -rf .terraform .terraform.lock.hcl tfplan *.tfstate*

# Help for specific member
help-member2: ## Show Member 2 usage
	@echo "$(GREEN)Member 2 (Network) - Usage:$(NC)"
	@echo "  1. Get handoff: make output-member2"
	@echo "  2. Configure ALB access logs to bucket/prefix from handoff"
	@echo "  3. Query Athena: vpc_flowlogs, elb_accesslogs, cloudtrail_management"
	@echo "  4. Key views: suspicious_connections, port_scanning, sqli_attempts"

help-member3: ## Show Member 3 usage
	@echo "$(GREEN)Member 3 (Storage) - Usage:$(NC)"
	@echo "  1. Get handoff: make output-member3"
	@echo "  2. Identify critical S3 buckets for CloudTrail data events"
	@echo "  3. Query Athena: cloudtrail_s3_data, cloudtrail_management, config_resources"
	@echo "  4. Key views: external_s3_access, s3_bucket_changes"

help-member4: ## Show Member 4 usage
	@echo "$(GREEN)Member 4 (Compliance) - Usage:$(NC)"
	@echo "  1. Get handoff: make output-member4"
	@echo "  2. Create Config Rules for compliance checks"
	@echo "  3. Query Athena: config_resources, config_snapshots, cloudtrail_management"
	@echo "  4. Key views: unapproved_changes, sg_changes, resource_drift"

help-member5: ## Show Member 5 usage
	@echo "$(GREEN)Member 5 (Detection) - Usage:$(NC)"
	@echo "  1. Get handoff: make output-member5"
	@echo "  2. Configure GuardDuty threat intel (upload to S3 path)"
	@echo "  3. Query Athena: ALL tables + guardduty_findings"
	@echo "  4. Key views: guardduty_enriched, compromised_ec2, exposed_access_keys, mitre_attack_mapping"