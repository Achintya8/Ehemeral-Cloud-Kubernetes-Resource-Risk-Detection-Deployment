#!/bin/bash
set -e

echo "🧹 Cleaning up all ephemeral test resources..."
echo ""

read -p "Are you sure? This will delete ALL resources. (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted"
    exit 1
fi

# Delete Kubernetes resources
echo "Deleting Kubernetes resources..."
kind delete cluster --name ephemeral-test 2>/dev/null || echo "No kind cluster found"
kubectl delete namespace ephemeral-test 2>/dev/null || true

# Destroy AWS resources
echo "Destroying AWS resources..."
cd ~/ephemeral-security-test/free-tier
terraform destroy -auto-approve 2>/dev/null || echo "No Terraform state found"

# Clean up local files
echo "Cleaning local files..."
rm -f ~/ephemeral-security-test/free-tier/lambda.zip
rm -f ~/ephemeral-security-test/free-tier/tfplan
rm -f ~/ephemeral-security-test/free-tier/auto-shutdown.sh
rm -f ~/ephemeral-security-test/outputs.txt

echo ""
echo "✅ Cleanup complete!"


chmod +x scripts/cleanup.sh
