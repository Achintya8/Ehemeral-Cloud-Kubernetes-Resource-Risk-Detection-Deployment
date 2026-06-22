# Testing and Deployment Guide: Terraform, Kind & Kubernetes

This guide walk you through deploying the **Kubernetes Local Testing Environment (Kind)** and the **AWS Cloud Simulation Sandbox (Terraform)**. These environments are used to test the ingestion pipeline, ML threat models, and automated response capabilities.

---

## 1. Kubernetes Local Setup (Kind)

**Kind (Kubernetes in Docker)** is used to run a multi-node Kubernetes cluster locally using Docker containers.

### Prerequisites
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
* [Kind CLI](https://kind.sigs.k8s.io/docs/user/quick-start/) installed.
* [kubectl CLI](https://kubernetes.io/docs/tasks/tools/) installed.

### Step 1: Create the Kind Cluster
Use the configuration file `ephemeral-security-test/kind-config.yaml` to spin up a cluster with 1 control plane node and 2 worker nodes (partitioned with labels):
```bash
kind create cluster --config ephemeral-security-test/kind-config.yaml
```

### Step 2: Verify the Cluster Nodes
Verify that the cluster nodes are up and check their associated workload-type labels:
```bash
kubectl get nodes --show-labels
```
You should see:
- `ephemeral-test-control-plane`
- `ephemeral-test-worker` (labeled with `workload-type=ephemeral`)
- `ephemeral-test-worker2` (labeled with `workload-type=persistent`)

---

## 2. Deploying Local Kubernetes Workloads

Once Kind is ready, deploy the testing manifests located in `ephemeral-security-test/k8s-local/` to simulate environments and security telemetry.

### Step 1: Create Namespace
Create the dedicated `ephemeral-test` namespace:
```bash
kubectl apply -f ephemeral-security-test/k8s-local/00-namespace.yaml
```

### Step 2: Deploy Simulation Workloads
Deploy the simulated CI/CD pipelines, batch workloads, and event generators:
1. **CI Pipeline Workloads**:
   ```bash
   kubectl apply -f ephemeral-security-test/k8s-local/01-ci-simulation.yaml
   ```
2. **Batch Job Workloads**:
   ```bash
   kubectl apply -f ephemeral-security-test/k8s-local/02-batch-jobs.yaml
   ```
3. **Telemetry Event Generator**:
   ```bash
   kubectl apply -f ephemeral-security-test/k8s-local/04-event-generator.yaml
   ```

### Step 3: Verify Deployments
Ensure that all pods are up and processing correctly:
```bash
kubectl get pods -n ephemeral-test
```

---

## 3. Cloud Infrastructure Setup (Terraform)

The Terraform configuration in `ephemeral-security-test/free-tier/` provisions AWS resources under the **AWS Free Tier** limits for cloud security events testing.

### Provisions
* **EC2 Test Runner Instance** (`t3.micro`): Auto-shutdown capability to prevent run-away costs.
* **AWS CloudTrail**: Configured to capture write-only management events.
* **S3 Log Bucket**: Configured with a 1-day retention/lifecycle expiration policy for cost control.
* **Lambda Event Generator**: Simulates AWS account compromises.

### Prerequisites
* [Terraform CLI](https://developer.hashicorp.com/terraform/downloads) (>= 1.5.0) installed.
* [AWS CLI](https://aws.amazon.com/cli/) installed.
* AWS credentials configured:
  ```bash
  aws configure
  ```

### Step 1: Initialize Terraform
Navigate to the Terraform folder and initialize the workspace:
```bash
cd ephemeral-security-test/free-tier
terraform init
```

### Step 2: Review and Plan Deployment
Verify the resources that will be provisioned:
```bash
terraform plan
```

### Step 3: Apply Configuration
Apply the plan to deploy the cloud security sandbox:
```bash
terraform apply -auto-approve
```

### Step 4: Capture Outputs
Upon completion, copy the outputs. Key parameters include:
* `ec2_public_ip`: SSH endpoint for the test runner.
* `lambda_function_name`: Name of the Lambda compromised-event generator.
* `s3_bucket_name`: Logs bucket.

---

## 4. Teardown and Cleanup

To clean up resources and prevent any cloud usage costs:

### AWS Cloud Cleanup
Destroy the Terraform-managed AWS infrastructure:
```bash
cd ephemeral-security-test/free-tier
terraform destroy -auto-approve
```

### Local Cluster Cleanup
Delete the local Kind cluster:
```bash
kind delete cluster --name ephemeral-test
```
