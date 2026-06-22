import urllib.request
import urllib.parse
import json
import time

url = 'http://127.0.0.1:8000/api/ingest'
headers = {'Content-Type': 'application/json'}

# Send an attack payload: high weight, unknown IP, privileged pod
payload = {
    "source_ip": "5.6.7.8", # Malicious / unknown IP
    "user_agent": "sqlmap/1.7",
    "actor": "unauthenticated",
    "action": "pod.exec",
    "resource_id": "kube-system-pod",
    "namespace": "kube-system",
    "region": "eastus",
    "request_weight": 20,
    "burst_flag": 1,
    "success": False,
    "log_type": "k8s_audit"
}

data = json.dumps(payload).encode('utf-8')

for _ in range(5):
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req) as response:
            print(response.read().decode())
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(0.1)
