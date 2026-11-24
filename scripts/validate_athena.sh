#!/bin/bash
# ===================================================================
# Validate Athena Tables and Views
# ===================================================================
# Run after terraform apply to verify all tables/views are queryable
# Usage: ./scripts/validate_athena.sh [account_id] [region] [environment]

set -euo pipefail

ACCOUNT_ID="${1:-123456789012}"
REGION="${2:-us-east-1}"
ENVIRONMENT="${3:-free-tier}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Athena Validation Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo "Account: $ACCOUNT_ID"
echo "Region: $REGION"
echo "Environment: $ENVIRONMENT"
echo ""

# Get Terraform outputs
WORKGROUP=$(terraform -chdir="$(dirname "$0")/.." output -raw workgroup_name 2>/dev/null || echo "audit-logs-workgroup")
DATABASE=$(terraform -chdir="$(dirname "$0")/.." output -raw database_name 2>/dev/null || echo "audit_logs")
RESULTS=$(terraform -chdir="$(dirname "$0")/.." output -raw query_results_location 2>/dev/null)

echo "Workgroup: $WORKGROUP"
echo "Database: $DATABASE"
echo "Results Location: $RESULTS"
echo ""

# Tables to test
TABLES=(
    "cloudtrail_management"
    "cloudtrail_s3_data"
    "vpc_flowlogs"
    "elb_accesslogs"
    "config_snapshots"
    "config_resources"
    "guardduty_findings"
)

# Views to test
VIEWS=(
    "shared.resource_timeline"
    "shared.iam_activity"
    "shared.s3_bucket_activity"
    "shared.sg_activity"
    "shared.failed_api_calls"
    "shared.cross_account_activity"
    "shared.root_activity"
    "shared.suspicious_connections"
    "shared.top_rejected_talkers"
    "shared.port_scanning"
    "shared.data_exfil_candidates"
    "shared.elb_errors"
    "shared.suspicious_user_agents"
    "shared.sqli_attempts"
    "shared.path_traversal"
    "shared.top_attacking_ips"
    "shared.external_s3_access"
    "shared.unapproved_changes"
    "shared.sg_changes"
    "shared.iam_changes"
    "shared.s3_bucket_changes"
    "shared.resource_drift"
    "shared.high_severity_findings"
    "shared.compromised_ec2"
    "shared.exposed_access_keys"
    "shared.recon_activity"
    "shared.crypto_mining"
    "shared.guardduty_enriched"
    "shared.mitre_attack_mapping"
)

run_query() {
    local query=$1
    local description=$2

    echo -n "Testing $description... "

    EXECUTION_ID=$(aws athena start-query-execution \
        --query-string "$query" \
        --work-group "$WORKGROUP" \
        --result-configuration "OutputLocation=$RESULTS" \
        --query 'QueryExecutionId' --output text 2>/dev/null)

    if [ -z "$EXECUTION_ID" ]; then
        echo -e "${RED}FAILED (could not start)${NC}"
        return 1
    fi

    # Wait for completion (max 30 seconds)
    for i in {1..30}; do
        STATUS=$(aws athena get-query-execution \
            --query-execution-id "$EXECUTION_ID" \
            --query 'QueryExecution.Status.State' --output text 2>/dev/null)

        case "$STATUS" in
            SUCCEEDED)
                echo -e "${GREEN}OK${NC}"
                return 0
                ;;
            FAILED|CANCELLED)
                ERROR=$(aws athena get-query-execution \
                    --query-execution-id "$EXECUTION_ID" \
                    --query 'QueryExecution.Status.StateChangeReason' --output text 2>/dev/null)
                echo -e "${RED}FAILED${NC} ($ERROR)"
                return 1
                ;;
            *)
                sleep 1
                ;;
        esac
    done

    echo -e "${YELLOW}TIMEOUT${NC}"
    return 1
}

echo -e "${YELLOW}--- Testing Tables ---${NC}"
for table in "${TABLES[@]}"; do
    run_query "SELECT * FROM $table LIMIT 1;" "Table: $table"
done

echo ""
echo -e "${YELLOW}--- Testing Views ---${NC}"
for view in "${VIEWS[@]}"; do
    run_query "SELECT * FROM $view LIMIT 1;" "View: $view"
done

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Validation Complete${NC}"
echo -e "${GREEN}========================================${NC}"