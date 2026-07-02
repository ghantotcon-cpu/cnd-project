#!/usr/bin/env python3
"""
Feedback Service — Runtime → Build Loop
CND Project: Listens to Falco alerts and feeds findings back to the pipeline.

Actions on SBOM-violation alert:
  1. Tags image in registry as "suspicious" via Cosign annotation
  2. Creates Kubernetes Event on the affected Pod
  3. Logs full provenance context with the incident
  4. Suggests which SBOM component to remediate
"""

import json
import logging
import os
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from kubernetes import client, config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("feedback-service")

app = Flask(__name__)
incidents = deque(maxlen=1000)

try:
    config.load_incluster_config()
except Exception:
    config.load_kube_config()

v1 = client.CoreV1Api()
NAMESPACE = os.environ.get("NAMESPACE", "cnd-demo")


def tag_image_suspicious(image_ref: str, alert_type: str):
    """Annotate image in registry with 'suspicious' tag via Cosign."""
    try:
        annotation = f"cnd.security/suspicious=true,cnd.security/alert={alert_type}"
        result = subprocess.run(
            ["cosign", "annotate", "--annotation", annotation, image_ref],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            log.info(f"Image tagged as suspicious: {image_ref}")
        else:
            log.warning(f"Could not annotate image: {result.stderr}")
    except Exception as e:
        log.error(f"Failed to tag image: {e}")


def create_k8s_event(namespace: str, pod_name: str,
                     alert_type: str, message: str, image_ref: str):
    """Create a Kubernetes Event on the affected Pod."""
    try:
        event = client.CoreV1Event(
            metadata=client.V1ObjectMeta(
                name=f"cnd-alert-{int(time.time())}",
                namespace=namespace
            ),
            involved_object=client.V1ObjectReference(
                kind="Pod",
                name=pod_name,
                namespace=namespace
            ),
            reason="SupplyChainViolation",
            message=f"[CND] {alert_type}: {message[:500]}",
            type="Warning",
            first_timestamp=datetime.now(timezone.utc),
            last_timestamp=datetime.now(timezone.utc),
            count=1,
            source=client.V1EventSource(component="cnd-feedback-service")
        )
        v1.create_namespaced_event(namespace=namespace, body=event)
        log.info(f"Event created for pod {pod_name}")
    except Exception as e:
        log.error(f"Failed to create event: {e}")


def suggest_remediation(alert_output: str) -> str:
    """Suggest which SBOM component to update based on alert content."""
    suggestions = {
        "pip": "Update or remove the Python dependency that enables package installation at runtime",
        "bash": "Remove shell interpreter from the container image",
        "curl": "Remove curl from the image or restrict network egress via NetworkPolicy",
        "wget": "Remove wget from the image or restrict network egress",
        "SBOM_VIOLATION": "Re-run build pipeline to generate fresh SBOM attestation",
        "Package manager": "Enforce read-only filesystem (readOnlyRootFilesystem: true) in pod spec",
    }
    for keyword, suggestion in suggestions.items():
        if keyword.lower() in alert_output.lower():
            return suggestion
    return "Review SBOM and rebuild image with updated dependencies"


def process_falco_alert(alert: dict):
    """Process a Falco alert and take feedback actions."""
    rule = alert.get('rule', '')
    output = alert.get('output', '')
    priority = alert.get('priority', 'WARNING')
    timestamp = alert.get('time', datetime.now(timezone.utc).isoformat())

    # Only process CND supply chain alerts
    if 'SBOM' not in rule and 'CND' not in rule and 'SUPPLY_CHAIN' not in output:
        return

    log.info(f"Processing Falco alert: {rule} [{priority}]")

    # Extract context from alert output
    fields = {}
    for part in output.split(' '):
        if '=' in part:
            k, v = part.split('=', 1)
            fields[k.strip('()')] = v.strip('()')

    image_ref = fields.get('image', fields.get('container.image.repository', 'unknown'))
    pod_name = fields.get('pod', fields.get('k8s.pod.name', 'unknown'))
    namespace = fields.get('ns', fields.get('k8s.ns.name', NAMESPACE))

    remediation = suggest_remediation(output)

    incident = {
        'id': f"inc-{int(time.time()*1000)}",
        'timestamp': timestamp,
        'alert_type': rule,
        'priority': priority,
        'image': image_ref,
        'pod': pod_name,
        'namespace': namespace,
        'alert_output': output[:1000],
        'fields': fields,
        'remediation': remediation,
        'actions_taken': []
    }

    # Action 1: Tag image as suspicious
    if image_ref != 'unknown':
        tag_image_suspicious(image_ref, rule)
        incident['actions_taken'].append('image_tagged_suspicious')

    # Action 2: Create Kubernetes Event
    if pod_name != 'unknown':
        create_k8s_event(
            namespace, pod_name, rule,
            f"{output[:200]} | Remediation: {remediation}",
            image_ref
        )
        incident['actions_taken'].append('k8s_event_created')

    # Action 3: Store incident
    incidents.append(incident)
    log.warning(
        f"INCIDENT RECORDED: {rule} | Pod: {pod_name} | "
        f"Image: {image_ref} | Remediation: {remediation}"
    )

    return incident


# ── REST API ──────────────────────────────────────────────────────

@app.route('/health')
def health():
    return jsonify({"status": "ok", "incidents": len(incidents)})


@app.route('/webhook', methods=['POST'])
def falco_webhook():
    """Receive Falco alerts via Falcosidekick webhook."""
    try:
        alert = request.get_json()
        if not alert:
            return jsonify({"error": "empty payload"}), 400
        incident = process_falco_alert(alert)
        return jsonify({"status": "processed", "incident_id": incident.get('id') if incident else None})
    except Exception as e:
        log.error(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/alerts')
def list_alerts():
    """Return all incidents with full provenance context."""
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 50))
    all_incidents = list(incidents)
    start = (page - 1) * limit
    return jsonify({
        "total": len(all_incidents),
        "page": page,
        "incidents": all_incidents[start:start + limit]
    })


@app.route('/alerts/summary')
def alerts_summary():
    """Summary of incidents by type for research reporting."""
    all_incidents = list(incidents)
    by_type = {}
    by_priority = {}
    for inc in all_incidents:
        t = inc.get('alert_type', 'unknown')
        p = inc.get('priority', 'unknown')
        by_type[t] = by_type.get(t, 0) + 1
        by_priority[p] = by_priority.get(p, 0) + 1
    return jsonify({
        "total": len(all_incidents),
        "by_type": by_type,
        "by_priority": by_priority
    })


if __name__ == '__main__':
    log.info("Starting CND Feedback Service (Runtime → Build loop)")
    port = int(os.environ.get('PORT', 8091))
    app.run(host='0.0.0.0', port=port)
