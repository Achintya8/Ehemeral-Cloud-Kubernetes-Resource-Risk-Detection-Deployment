import time
import random
import requests
import json
from datetime import datetime, timezone

INGEST_URL = "http://127.0.0.1:8000/api/ingest"
DURATION_MINUTES = 15

# Mock data pools
NAMESPACES = ["default", "kube-system", "ephemeral-test", "prod-frontend", "prod-backend", "data-lake"]
RESOURCES = ["nginx-pod", "redis-cache", "spark-worker", "api-gateway", "auth-service", "payment-processor"]
AWS_SERVICES = ["ec2.amazonaws.com", "s3.amazonaws.com", "iam.amazonaws.com", "lambda.amazonaws.com"]
AWS_EVENTS = ["RunInstances", "CreateBucket", "PutObject", "DeleteUser", "AttachRolePolicy", "Invoke"]
K8S_VERBS = ["create", "update", "delete", "patch", "scale"]

def generate_info_event():
    ns = random.choice(NAMESPACES)
    sa = f"system:serviceaccount:{ns}:default"
    return {
        "source": "kubernetes",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "get",
        "resource_type": "Pod",
        "resource_name": f"{random.choice(RESOURCES)}-{random.randint(1000, 9999)}",
        "namespace": ns,
        "username": sa,
        "actor": sa,
        "user": {"username": sa},
        "source_ip": f"10.244.{random.randint(0, 255)}.{random.randint(1, 254)}"
    }

def generate_medium_event():
    ns = random.choice(NAMESPACES)
    sa = f"system:serviceaccount:{ns}:default"
    return {
        "source": "kubernetes",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": random.choice(["create", "update", "patch"]),
        "resource_type": random.choice(["Pod", "Deployment", "Service"]),
        "resource_name": f"{random.choice(RESOURCES)}-{random.randint(1000, 9999)}",
        "namespace": ns,
        "username": sa,
        "actor": sa,
        "user": {"username": sa},
        "source_ip": f"10.244.{random.randint(0, 255)}.{random.randint(1, 254)}"
    }

def generate_high_event():
    sa = "system:serviceaccount:default:compromised"
    return {
        "source": "kubernetes",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "delete",
        "resource_type": "RoleBinding",
        "resource_name": f"admin-binding-{random.randint(1000, 9999)}",
        "namespace": "kube-system",
        "username": sa,
        "actor": sa,
        "user": {"username": sa},
        "source_ip": f"10.244.{random.randint(0, 255)}.{random.randint(1, 254)}"
    }

def generate_aws_event():
    role_name = f"admin-role-{random.randint(100, 999)}"
    return {
        "eventSource": random.choice(AWS_SERVICES),
        "eventName": random.choice(AWS_EVENTS),
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "sourceIPAddress": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": f"AROAEXAMPLE:{role_name}",
            "userName": role_name,
            "arn": f"arn:aws:sts::123456789012:assumed-role/admin-role/session-{random.randint(100, 999)}"
        },
        "requestParameters": {
            "target": f"resource-{random.randint(1000, 9999)}"
        }
    }

def generate_attack_burst():
    """Generates a suspicious sequence of events simulating a breakout."""
    ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
    pod = f"compromised-worker-{random.randint(1000, 9999)}"
    ns = "ephemeral-test"
    events = [
        {
            "source": "kubernetes", 
            "action": "exec", 
            "resource_type": "Pod", 
            "resource_name": pod, 
            "namespace": ns, 
            "username": "system:anonymous", 
            "actor": "system:anonymous",
            "user": {"username": "system:anonymous"}, 
            "source_ip": ip
        },
        {
            "source": "kubernetes", 
            "action": "list", 
            "resource_type": "Secret", 
            "resource_name": "aws-credentials", 
            "namespace": ns, 
            "username": f"system:serviceaccount:{ns}:default", 
            "actor": f"system:serviceaccount:{ns}:default",
            "user": {"username": f"system:serviceaccount:{ns}:default"}, 
            "source_ip": ip
        },
        {
            "eventSource": "iam.amazonaws.com", 
            "eventName": "ListRoles", 
            "sourceIPAddress": ip,
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROAEXAMPLE:compromised-role",
                "userName": "compromised-role"
            }
        },
        {
            "eventSource": "s3.amazonaws.com", 
            "eventName": "ListBuckets", 
            "sourceIPAddress": ip,
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROAEXAMPLE:compromised-role",
                "userName": "compromised-role"
            }
        }
    ]
    for e in events:
        e["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "eventTime" in e:
            e["eventTime"] = e["timestamp"]
    return events

print(f"Starting Ephemeral Risk Stress Test for {DURATION_MINUTES} minutes...")
print(f"Target: {INGEST_URL}")

start_time = time.time()
end_time = start_time + (DURATION_MINUTES * 60)
events_sent = 0

try:
    while time.time() < end_time:
        # 80% chance of normal background noise
        if random.random() < 0.8:
            rand_val = random.random()
            if rand_val < 0.7:
                event = generate_info_event()
            elif rand_val < 0.8:
                event = generate_medium_event()
            else:
                event = generate_high_event()
            
            payloads = [event]
            delay = random.uniform(0.1, 0.5) # Fast stream of normal events
        else:
            # 20% chance to drop a coordinated attack burst
            payloads = generate_attack_burst()
            delay = random.uniform(1.0, 3.0) # Pause after burst

        for payload in payloads:
            try:
                requests.post(INGEST_URL, json=payload, timeout=2)
                events_sent += 1
            except requests.exceptions.RequestException:
                pass # Ignore errors during stress test to keep pumping

        if events_sent % 100 == 0:
            elapsed = time.time() - start_time
            print(f"Sent {events_sent} events... (Elapsed: {elapsed:.1f}s)")
        
        time.sleep(delay)

except KeyboardInterrupt:
    print("\nStress test interrupted manually.")

elapsed = time.time() - start_time
print(f"\nStress test complete!")
print(f"Total events injected: {events_sent}")
print(f"Average throughput: {events_sent / elapsed:.2f} events/second")
