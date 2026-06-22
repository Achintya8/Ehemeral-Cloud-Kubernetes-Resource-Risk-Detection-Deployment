import sqlite3
import json

DB_PATH = "data/security_events.db"

def cleanup():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Identify all events that came from the stress test
    stress_test_resources = [
        "nginx-pod-%", "redis-cache-%", "spark-worker-%", 
        "api-gateway-%", "auth-service-%", "payment-processor-%", 
        "admin-binding-%", "compromised-worker-%"
    ]
    
    stress_test_aws_events = [
        "RunInstances", "CreateBucket", "PutObject", "DeleteUser", 
        "AttachRolePolicy", "Invoke", "ListRoles", "ListBuckets"
    ]
    
    print("Finding stress test events...")
    
    # Build query to delete events
    resource_conditions = " OR ".join([f"resource_id LIKE '{res}'" for res in stress_test_resources])
    action_conditions = " OR ".join([f"action = '{act}'" for act in stress_test_aws_events])
    
    # Delete Events
    cursor.execute(f"DELETE FROM events WHERE {resource_conditions} OR {action_conditions}")
    deleted_events = cursor.rowcount
    print(f"Deleted {deleted_events} fake events from the stream.")
    
    # 2. Delete Incidents that contain these fake resources in their report_text
    incident_conditions = " OR ".join([f"report_text LIKE '%{res.replace('%', '')}%'" for res in stress_test_resources])
    incident_conditions += " OR " + " OR ".join([f"report_text LIKE '%{act}%'" for act in stress_test_aws_events])
    
    cursor.execute(f"DELETE FROM incidents WHERE {incident_conditions}")
    deleted_incidents = cursor.rowcount
    print(f"Deleted {deleted_incidents} fake incidents.")
    
    # Also delete incidents that have no corresponding events anymore (orphans) or huge burst counts if needed.
    
    conn.commit()
    conn.close()
    print("Cleanup complete!")

if __name__ == "__main__":
    cleanup()
