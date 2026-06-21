#!/bin/bash
set -e

echo "🚀 Ephemeral Security Test - Full Deployment"
echo "============================================"
echo ""

echo "Checking prerequisites..."

command -v aws &> /dev/null || { echo "❌ AWS CLI not installed"; exit 1; }
command -v terraform &> /dev/null || { echo "❌ Terraform not installed"; exit 1; }
command -v kubectl &> /dev/null || { echo "❌ kubectl not installed"; exit 1; }
command -v kind &> /dev/null || { echo "❌ kind not installed"; exit 1; }
command -v docker &> /dev/null || { echo "❌ Docker not installed"; exit 1; }

# Verify AWS credentials
aws sts get-caller-identity &> /dev/null || { echo "❌ AWS credentials not configured"; exit 1; }
echo "✅ All prerequisites met"
echo ""

# Deploy AWS resources
echo "📦 Deploying AWS resources..."
cd ~/ephemeral-security-test/free-tier
terraform init
terraform plan -out=tfplan
echo ""
read -p "Proceed with Terraform apply? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    terraform apply tfplan
else
    echo "Aborted"
    exit 1
fi

# Save outputs
terraform output > ~/ephemeral-security-test/outputs.txt
echo "✅ AWS resources deployed"
echo ""

# Deploy Kubernetes
echo "☸️  Setting up local Kubernetes cluster..."
kind get clusters | grep -q "ephemeral-test" && kind delete cluster --name ephemeral-test
kind create cluster --name ephemeral-test --config - <<'KINDEOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ephemeral-test
nodes:
  - role: control-plane
  - role: worker
    labels:
      workload-type: ephemeral
  - role: worker
    labels:
      workload-type: persistent
KINDEOF

echo "✅ Kubernetes cluster ready"
echo ""

# Apply manifests
echo "📋 Deploying Kubernetes workloads..."
kubectl apply -f ~/ephemeral-security-test/k8s-local/

echo ""
echo "⏳ Waiting for resources to be ready..."
sleep 5
kubectl get all -n ephemeral-test

echo ""
echo "🎉 DEPLOYMENT COMPLETE!"
echo ""
echo "Next steps:"
echo "1. Check AWS resources:  aws ec2 describe-instances"
echo "2. Check K8s resources:  kubectl get all -n ephemeral-test"
echo "3. Generate events:     aws lambda invoke --function-name ephemeral-event-generator --payload '{}' out.json"
echo "4. Monitor costs:       ~/ephemeral-security-test/scripts/check-costs.sh"
echo "5. View CloudTrail:     aws cloudtrail lookup-events --max-results 5"
echo ""
echo "⚠️  IMPORTANT: Your EC2 instance will auto-shutdown in 2 hours"
echo "    To destroy everything: cd ~/ephemeral-security-test/free-tier && terraform destroy"
