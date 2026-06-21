#!/bin/bash
# Cost monitoring script - run daily

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -z "$ACCOUNT_ID" ]; then
    echo "❌ AWS CLI not configured. Run 'aws configure' first."
    exit 1
fi

echo "=== AWS Free Tier Usage Check ==="
echo "Account: $ACCOUNT_ID"
echo "Date: $(date)"
echo ""

# Check EC2 instances
echo "--- EC2 Instances ---"
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,LaunchTime,Tags[?Key==`Name`].Value|[0]]' \
  --output table 2>/dev/null || echo "No running instances"

# Check Lambda invocations this month
echo ""
echo "--- Lambda Usage (This Month) ---"
START_TIME=$(date -d "$(date +%Y-%m-01)" +%Y-%m-%d)
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=ephemeral-event-generator \
  --start-time "${START_TIME}T00:00:00Z" \
  --end-time "$(date +%Y-%m-%d)T23:59:59Z" \
  --period 2592000 \
  --statistics Sum \
  --query 'Datapoints[0].Sum' \
  --output table 2>/dev/null || echo "No data"

# Check S3 bucket size
echo ""
echo "--- S3 Storage ---"
BUCKET=$(aws s3api list-buckets --query 'Buckets[?contains(Name, `ephemeral-ct-logs`)].Name' --output text 2>/dev/null)
if [ -n "$BUCKET" ] && [ "$BUCKET" != "None" ]; then
    aws s3api list-objects-v2 --bucket "$BUCKET" --query 'length(Contents)' --output table 2>/dev/null || echo "Bucket empty"
else
    echo "No CloudTrail bucket found"
fi

# Check estimated charges
echo ""
echo "--- Estimated Charges ---"
aws cloudwatch get-metric-statistics \
  --namespace AWS/Billing \
  --metric-name EstimatedCharges \
  --dimensions Name=Currency,Value=USD \
  --start-time "$(date -d '2 days ago' +%Y-%m-%d)T00:00:00Z" \
  --end-time "$(date +%Y-%m-%d)T23:59:59Z" \
  --period 86400 \
  --statistics Maximum \
  --query 'Datapoints[*].[Timestamp,Maximum]' \
  --output table 2>/dev/null || echo "No billing data yet"

echo ""
echo "=== Safety Checks ==="

# Alert if EC2 running too long
RUNNING=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=ephemeral-test-runner" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)

if [ "$RUNNING" != "None" ] && [ -n "$RUNNING" ]; then
    LAUNCH_TIME=$(aws ec2 describe-instances \
      --instance-ids "$RUNNING" \
      --query 'Reservations[0].Instances[0].LaunchTime' --output text)
    
    if command -v python3 &> /dev/null; then
        HOURS=$(python3 -c "from datetime import datetime; print(int((datetime.utcnow() - datetime.fromisoformat('$LAUNCH_TIME'.replace('Z', '+00:00'))).total_seconds() / 3600))")
    else
        HOURS=0
    fi
    
    if [ "$HOURS" -gt 8 ]; then
        echo "⚠️  WARNING: EC2 instance $RUNNING running for $HOURS hours!"
        echo "   Stop it now: aws ec2 stop-instances --instance-ids $RUNNING"
    else
        echo "✅ EC2 instance running for $HOURS hours (safe)"
    fi
else
    echo "✅ No running test instances"
fi

echo ""
echo "=== Quick Actions ==="
echo "Stop EC2:    aws ec2 stop-instances --instance-ids <id>"
echo "Destroy all: cd ~/ephemeral-security-test/free-tier && terraform destroy"


chmod +x scripts/check-costs.sh
