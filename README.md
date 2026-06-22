# k8strl: Ephemeral Cloud Kubernetes Resource Risk Detection Platform

An enterprise-grade, real-time security monitoring, ML anomaly detection, and automated zero-trust containment system for Kubernetes and cloud infrastructure.

---

## 🌟 Key Features

1. **Multi-Source Real-Time Telemetry Ingestion**:
   - Ingests and normalizes **Kubernetes Audit Logs**, **VPC Flow Logs**, and **AWS CloudTrail** telemetry.

2. **Machine Learning-Driven Anomaly Detection**:
   - Uses an **Isolation Forest** model to compute real-time Risk Scores (`0` to `100`).
   - Uses **NetworkX** graphs to correlate related security events (sharing namespaces, resource names, source IPs, or principal IDs) into unified campaign incidents.

3. **Automated Zero-Trust Containment**:
   - Automatically isolates compromised pods, cordons host nodes, and blocklists source IPs in real-time when **CRITICAL** risk levels are detected.

4. **Groq Llama-Powered AI Triage**:
   - Integrates with the **Groq API** (`llama-3.3-70b-versatile`) to generate threat narratives, attacker intent summaries, and recommendations.
   - Maps detected threats dynamically to **NIST SP 800-53** controls, **MITRE ATT&CK** techniques, and **CIS Benchmarks** with zero UI placeholders.

5. **Interactive Analyst Feedback Loop**:
   - In-modal **Approve Containment** and **Disapprove & Rollback** controls for auto-remediated incidents.
   - Feedbacks model corrections directly into the database as `scenario_4_false_positive` to improve future Isolation Forest training runs.

6. **Analyst History & Audit Logging**:
   - Tracks all automated responses, analyst approvals, and rollbacks in a persistent activity audit log displayed on the admin dashboard.

---

## 🚀 Quick Start Guide

### Prerequisites
* Python 3.10+
* Node.js 18+
* Groq API Key

### Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd ephemeral-risk
   ```
2. Copy the environment template and fill in your keys:
   ```bash
   cp backend/.env.example .env
   ```
   *Make sure to add your `GROQ_API_KEY` to the `.env` file.*
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the FastAPI server:
   ```bash
   python -m uvicorn backend.main:app --reload
   ```

### Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd ephemeral-risk/frontend
   ```
2. Install packages:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```

### Stress Testing & Data Ingestion
To simulate live traffic and verify the ingestion and machine learning pipeline, run the stress test script:
```bash
python ephemeral-risk/scripts/stress_test.py
```
*Note: The stress test is pre-configured with a realistic severity distribution (70% INFO, 10% MEDIUM, 20% HIGH/Burst events) and maps principals correctly to prevent false-positive anomaly spikes.*

---

## 📘 Detailed System Documentation

For in-depth information about the system architecture, telemetry normalization schema, ML correlation engine, containment automation flows, and API reference, please refer to the detailed [DOCUMENTATION.md](file:///c:/Users/ASUS/Ephemeral-Cloud-Kubernetes-Resource-Risk-Detection/DOCUMENTATION.md) file.

For detailed steps on deploying the Kubernetes local cluster (Kind), running local manifests, and setting up the AWS sandbox (Terraform), please refer to the [DEPLOYMENT_GUIDE.md](file:///c:/Users/ASUS/Ephemeral-Cloud-Kubernetes-Resource-Risk-Detection/DEPLOYMENT_GUIDE.md) file.

