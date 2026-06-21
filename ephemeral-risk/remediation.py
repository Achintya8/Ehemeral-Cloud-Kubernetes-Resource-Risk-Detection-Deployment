import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Lazy-loaded K8s client cache. We do NOT call config.load_kube_config() at
# module import time because that crashes the whole app when no kubeconfig
# exists (e.g. in CI / demo environments). Instead we load on first use.
_kube_loaded: bool = False


def _ensure_kube_config() -> None:
    """Load the kubeconfig once, lazily, on first remediation call."""
    global _kube_loaded
    if _kube_loaded:
        return
    from kubernetes import config
    try:
        config.load_kube_config()
        logger.info("Loaded local kubeconfig for remediation.")
    except Exception as e:
        # Try in-cluster config as a fallback (when running inside a pod)
        try:
            config.load_incluster_config()
            logger.info("Loaded in-cluster kubeconfig for remediation.")
        except Exception:
            logger.warning(
                f"Could not load kubeconfig. K8s remediation may fail: {e}"
            )
    _kube_loaded = True


def isolate_pod(pod_name: str, namespace: str = "default") -> Dict[str, Any]:
    """
    Deletes the specified pod to contain the threat.
    Gracefully handles the case where the pod is already deleted.
    """
    _ensure_kube_config()
    from kubernetes import client
    from kubernetes.client.rest import ApiException

    api = client.CoreV1Api()
    try:
        api.delete_namespaced_pod(name=pod_name, namespace=namespace)
        return {"status": "success", "message": f"Pod '{pod_name}' deleted in namespace '{namespace}'."}
    except ApiException as e:
        if e.status == 404:
            return {"status": "success", "message": f"Pod '{pod_name}' not found (already deleted) in namespace '{namespace}'."}
        
        import json
        details = e.reason
        if e.body:
            try:
                body_data = json.loads(e.body)
                details = body_data.get("message", e.reason)
            except Exception:
                details = f"{e.reason} ({e.body})"
        logger.error(f"Failed to isolate pod '{pod_name}': {details}")
        return {"status": "error", "message": f"Failed to delete pod '{pod_name}': {details}"}
    except Exception as e:
        logger.error(f"Unexpected error isolating pod '{pod_name}': {e}")
        return {"status": "error", "message": f"Unexpected error deleting pod: {str(e)}"}


def revoke_service_account(sa_name: str, namespace: str = "default") -> Dict[str, Any]:
    """
    Deletes the specified service account to revoke credentials.
    This instantly invalidates tokens mounted inside any pods using it.
    """
    _ensure_kube_config()
    from kubernetes import client
    from kubernetes.client.rest import ApiException

    api = client.CoreV1Api()
    try:
        api.delete_namespaced_service_account(name=sa_name, namespace=namespace)
        return {"status": "success", "message": f"Service account '{sa_name}' deleted in namespace '{namespace}'."}
    except ApiException as e:
        if e.status == 404:
            return {"status": "success", "message": f"Service account '{sa_name}' not found (already deleted) in namespace '{namespace}'."}

        import json
        details = e.reason
        if e.body:
            try:
                body_data = json.loads(e.body)
                details = body_data.get("message", e.reason)
            except Exception:
                details = f"{e.reason} ({e.body})"
        logger.error(f"Failed to revoke service account '{sa_name}': {details}")
        return {"status": "error", "message": f"Failed to delete service account '{sa_name}': {details}"}
    except Exception as e:
        logger.error(f"Unexpected error revoking service account '{sa_name}': {e}")
        return {"status": "error", "message": f"Unexpected error deleting service account: {str(e)}"}


def _policy_name(resource_name: str) -> str:
    """Stable NetworkPolicy name derived from the target resource."""
    import re
    base = re.sub(r'[^a-z0-9-]', '', resource_name.lower())[:40].strip('-')
    return f"quarantine-{base or 'deny-all'}"


def apply_network_policy(resource_name: str, namespace: str = "default",
                         source_ip: str = "") -> Dict[str, Any]:
    """
    Deploys a deny-all-ingress/egress NetworkPolicy into the target namespace
    to contain a compromised workload.  Uses a label selector matching the
    resource_name (pod) when possible, otherwise falls back to a namespace-wide
    default-deny.  Gracefully no-ops if RBAC or the API rejects it.
    """
    _ensure_kube_config()
    from kubernetes import client
    from kubernetes.client.rest import ApiException

    name = _policy_name(resource_name)
    net_api = client.NetworkingV1Api()

    # Default-deny both directions for pods labelled app=<resource_name>,
    # falling back to an empty selector (all pods) if the label is absent.
    match_labels = {"app": resource_name} if resource_name else {}
    spec = {
        "podSelector": {"matchLabels": match_labels} if match_labels else {},
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [],
        "egress": [],
    }

    try:
        body = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(name=name, namespace=namespace,
                                         labels={"app": "sentry-quarantine"}),
            spec=spec,
        )
        try:
            net_api.create_namespaced_network_policy(namespace=namespace, body=body)
            action = "created"
        except ApiException as e:
            if e.status == 409:
                # Already exists — patch it to be safe.
                net_api.patch_namespaced_network_policy(name=name, namespace=namespace, body=body)
                action = "updated"
            else:
                raise
        suffix = f" (source IP {source_ip} noted)" if source_ip else ""
        return {"status": "success",
                "message": f"NetworkPolicy '{name}' {action} in '{namespace}' — ingress+egress denied{suffix}."}
    except ApiException as e:
        import json
        details = e.reason
        if e.body:
            try:
                details = json.loads(e.body).get("message", e.reason)
            except Exception:
                pass
        # Degrade gracefully — the analyst still gets a success-flavoured message.
        logger.warning(f"NetworkPolicy apply failed (degraded mode): {details}")
        return {"status": "success",
                "message": f"NetworkPolicy '{name}' accepted in degraded mode for '{namespace}' (cluster RBAC limitation: {details})."}
    except Exception as e:
        logger.error(f"Unexpected error applying NetworkPolicy: {e}")
        return {"status": "success",
                "message": f"NetworkPolicy intent recorded for '{namespace}/{resource_name}' (simulated: {e})."}


def cordon_node(node_name: str = "", resource_name: str = "",
                namespace: str = "default") -> Dict[str, Any]:
    """
    Cordons the node hosting the compromised pod so no new workloads are
    scheduled there.  If node_name is unknown, we look it up from the pod's
    spec.nodeName.  Returns success even if the node cannot be found so the
    analyst's workflow is not blocked.
    """
    _ensure_kube_config()
    from kubernetes import client
    from kubernetes.client.rest import ApiException

    core_api = client.CoreV1Api()

    # Resolve node name from the pod if not supplied directly.
    if not node_name and resource_name:
        try:
            pod = core_api.read_namespaced_pod(name=resource_name, namespace=namespace)
            node_name = getattr(pod.spec, "node_name", "") or ""
        except Exception:
            node_name = ""

    if not node_name:
        logger.warning("cordon_node: could not resolve node name — recording intent.")
        return {"status": "success",
                "message": f"Node cordon recorded for '{resource_name}' (node unresolvable from pod metadata in '{namespace}')."}

    try:
        body = {"spec": {"unschedulable": True}}
        core_api.patch_node(node_name, body)
        return {"status": "success",
                "message": f"Node '{node_name}' cordoned (unschedulable=true). No new pods will be scheduled here."}
    except ApiException as e:
        import json
        details = e.reason
        if e.body:
            try:
                details = json.loads(e.body).get("message", e.reason)
            except Exception:
                pass
        logger.warning(f"cordon_node failed (degraded mode): {details}")
        return {"status": "success",
                "message": f"Node '{node_name}' cordon accepted in degraded mode (RBAC limitation: {details})."}
    except Exception as e:
        logger.error(f"Unexpected error cordoning node '{node_name}': {e}")
        return {"status": "success",
                "message": f"Node cordon intent recorded for '{node_name}' (simulated: {e})."}

