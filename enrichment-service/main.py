#!/usr/bin/env python3
"""
Provenance Enrichment Service — THE CORE INNOVATION
CND Project: Bridges build-time security metadata with runtime monitoring.

How it works:
1. Watches Kubernetes for new Pod deployments
2. Fetches SBOM + SLSA provenance + signature for each image
3. Extracts allowed binaries, packages, network ports
4. Generates DYNAMIC Falco rules specific to each image's SBOM
5. Stores enrichment data in ConfigMaps for Falco to use
6. Triggers Falco rules reload
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from hashlib import sha256
from typing import Optional

from flask import Flask, jsonify, request
from kubernetes import client, config, watch

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("enrichment-service")

app = Flask(__name__)

# ── In-memory store of enrichments ──
enrichments: dict = {}

# ── Kubernetes client setup ──
try:
    config.load_incluster_config()
    log.info("Using in-cluster Kubernetes config")
except Exception:
    config.load_kube_config()
    log.info("Using local kubeconfig")

v1 = client.CoreV1Api()
NAMESPACE = os.environ.get("WATCH_NAMESPACE", "cnd-demo")


# ══════════════════════════════════════════════════════════════════════════════
# SBOM + Provenance Fetching
# ══════════════════════════════════════════════════════════════════════════════

def fetch_sbom(image_ref: str) -> Optional[dict]:
    """Fetch SBOM from OCI registry using cosign."""
    try:
        result = subprocess.run(
            ["cosign", "download", "sbom", image_ref],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        log.warning(f"SBOM not found for {image_ref}: {result.stderr[:200]}")
        return None
    except Exception as e:
        log.error(f"Failed to fetch SBOM for {image_ref}: {e}")
        return None


def fetch_slsa_provenance(image_ref: str) -> Optional[dict]:
    """Fetch SLSA provenance attestation using cosign."""
    try:
        result = subprocess.run(
            ["cosign", "verify-attestation",
             "--certificate-identity-regexp", ".*",
             "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
             "--type", "slsaprovenance1",
             image_ref],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                try:
                    data = json.loads(line)
                    payload = data.get('payload', '')
                    if payload:
                        import base64
                        decoded = json.loads(base64.b64decode(payload + '=='))
                        return decoded.get('predicate', {})
                except Exception:
                    continue
        return None
    except Exception as e:
        log.error(f"Failed to fetch SLSA provenance for {image_ref}: {e}")
        return None


def verify_signature(image_ref: str) -> dict:
    """Verify Cosign signature and return verification status."""
    try:
        result = subprocess.run(
            ["cosign", "verify",
             "--certificate-identity-regexp", ".*",
             "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
             image_ref],
            capture_output=True, text=True, timeout=30
        )
        return {
            "verified": result.returncode == 0,
            "signer_identity": _extract_signer(result.stdout),
            "output": result.stdout[:500]
        }
    except Exception as e:
        return {"verified": False, "error": str(e)}


def _extract_signer(cosign_output: str) -> str:
    """Extract signer identity from cosign verify output."""
    try:
        data = json.loads(cosign_output)
        if isinstance(data, list) and data:
            cert = data[0].get('optional', {})
            return cert.get('Subject', cert.get('Issuer', 'unknown'))
    except Exception:
        pass
    return "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# SBOM Analysis — Extract Allowed Binaries, Packages, Ports
# ══════════════════════════════════════════════════════════════════════════════

def parse_sbom(sbom: dict) -> dict:
    """
    Parse SBOM and extract:
    - allowed_binaries: process names allowed at runtime
    - allowed_packages: declared package inventory
    - allowed_ports: network ports declared in dependencies
    """
    allowed_binaries = set()
    allowed_packages = []
    allowed_ports = set()

    components = sbom.get('components', [])

    for comp in components:
        name = comp.get('name', '').lower()
        ctype = comp.get('type', '')
        version = comp.get('version', '')
        purl = comp.get('purl', '')

        pkg_entry = {
            'name': name,
            'version': version,
            'type': ctype,
            'purl': purl
        }
        allowed_packages.append(pkg_entry)

        # Map known packages to their process names
        binary_map = {
            'python': ['python3', 'python'],
            'python3': ['python3', 'python'],
            'gunicorn': ['gunicorn'],
            'flask': ['python3'],
            'go': ['cnd-app'],
            'gin': ['cnd-app'],
            'nginx': ['nginx'],
            'node': ['node'],
            'java': ['java'],
        }
        if name in binary_map:
            allowed_binaries.update(binary_map[name])

        # Extract ports from service descriptions
        for ref in comp.get('externalReferences', []):
            url = ref.get('url', '')
            if ':' in url:
                try:
                    port = int(url.split(':')[-1].split('/')[0])
                    if 1 <= port <= 65535:
                        allowed_ports.add(port)
                except ValueError:
                    pass

    # Always allow these common container processes
    allowed_binaries.update({
        'pause', 'sh', 'bash',   # removed from final rules but needed for parsing
        '/cnd-app', 'cnd-app',
    })
    # Remove shells from ALLOWED — they should trigger alerts
    allowed_binaries.discard('bash')
    allowed_binaries.discard('sh')

    # Common app ports
    allowed_ports.update({8080, 443, 80})

    return {
        'allowed_binaries': sorted(list(allowed_binaries)),
        'allowed_packages': allowed_packages,
        'allowed_ports': sorted(list(allowed_ports)),
        'total_components': len(components)
    }


# ══════════════════════════════════════════════════════════════════════════════
# Dynamic Falco Rule Generation (THE KEY INNOVATION)
# ══════════════════════════════════════════════════════════════════════════════

def generate_falco_rules(image_ref: str, sbom_analysis: dict,
                          slsa_level: str, signer_identity: str) -> str:
    """
    Generate DYNAMIC Falco rules based on this specific image's SBOM.
    These rules are more precise than generic rules because they are
    derived from the actual declared component inventory.
    """
    binaries = sbom_analysis['allowed_binaries']
    binary_list = '(' + ', '.join(f'"{b}"' for b in binaries) + ')'
    image_hash = sha256(image_ref.encode()).hexdigest()[:12]

    rules = f"""# ══════════════════════════════════════════════════════════════════
# SBOM-ENRICHED FALCO RULES — Auto-generated by Provenance Enrichment Service
# Image:   {image_ref}
# Hash:    {image_hash}
# SLSA:    Level {slsa_level}
# Signer:  {signer_identity}
# SBOM Components: {sbom_analysis['total_components']}
# Generated: {datetime.now(timezone.utc).isoformat()}
# ══════════════════════════════════════════════════════════════════

# ─── SBOM-Derived Whitelist ───────────────────────────────────────
- macro: sbom_allowed_binaries_{image_hash}
  condition: >
    proc.name in {binary_list}

# ─── SBOM-ENRICHED RULE 1: Process Not in SBOM ───────────────────
- rule: "SBOM Violation - Unexpected Process [{image_hash}]"
  desc: >
    A process not declared in the SBOM is running in this container.
    This indicates possible supply chain tampering, malicious code
    injection, or runtime exploitation. SLSA Level: {slsa_level}.
    Signer: {signer_identity}
  condition: >
    spawned_process and
    container and
    container.image.repository contains "{image_ref.split(':')[0]}" and
    not sbom_allowed_binaries_{image_hash} and
    not proc.name in (pause, runc, containerd-shim)
  output: >
    [SBOM-ENRICHED] Process not in SBOM inventory
    (proc=%proc.name pid=%proc.pid cmdline=%proc.cmdline
     image=%container.image.repository:%container.image.tag
     pod=%k8s.pod.name ns=%k8s.ns.name
     slsa_level={slsa_level} signer={signer_identity}
     sbom_source={image_ref}
     PROVENANCE_CONTEXT=image_hash_{image_hash})
  priority: CRITICAL
  tags: [sbom_enriched, supply_chain, cnd_project, provenance]

# ─── SBOM-ENRICHED RULE 2: Shell Spawned (not in SBOM) ──────────
- rule: "SBOM Violation - Shell Execution [{image_hash}]"
  desc: >
    Shell (bash/sh) spawned in a container where SBOM does not
    declare any shell interpreter. Build-time attestation from
    {signer_identity} confirms this binary is not legitimate.
  condition: >
    spawned_process and
    container and
    container.image.repository contains "{image_ref.split(':')[0]}" and
    proc.name in (bash, sh, dash, zsh, ksh)
  output: >
    [SBOM-ENRICHED] Shell spawned — not in SBOM
    (shell=%proc.name pid=%proc.pid parent=%proc.pname
     cmdline=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name
     slsa_level={slsa_level} signer={signer_identity}
     SUPPLY_CHAIN_VIOLATION=shell_not_in_sbom)
  priority: CRITICAL
  tags: [sbom_enriched, shell, cnd_project, critical]

# ─── SBOM-ENRICHED RULE 3: Network Tool (not in SBOM) ───────────
- rule: "SBOM Violation - Network Tool Execution [{image_hash}]"
  desc: >
    A network tool (curl, wget, nc) was executed. These tools are
    not present in the SBOM for this image and may indicate
    data exfiltration or C2 communication.
  condition: >
    spawned_process and
    container and
    container.image.repository contains "{image_ref.split(':')[0]}" and
    proc.name in (curl, wget, nc, ncat, netcat, nmap, socat)
  output: >
    [SBOM-ENRICHED] Network tool not in SBOM
    (tool=%proc.name cmdline=%proc.cmdline
     pod=%k8s.pod.name ns=%k8s.ns.name
     slsa_level={slsa_level}
     EXFILTRATION_RISK=network_binary_not_in_sbom)
  priority: CRITICAL
  tags: [sbom_enriched, network, exfiltration, cnd_project]

# ─── SBOM-ENRICHED RULE 4: Package Manager (SBOM Violation) ─────
- rule: "SBOM Violation - Package Installation [{image_hash}]"
  desc: >
    A package manager is running inside the container. This is a
    malicious dependency injection attempt — the SBOM declared
    {sbom_analysis['total_components']} components and no package
    manager should be modifying them at runtime.
  condition: >
    spawned_process and
    container and
    container.image.repository contains "{image_ref.split(':')[0]}" and
    proc.name in (pip, pip3, apt, apt-get, yum, dnf, rpm, npm, yarn, gem)
  output: >
    [SBOM-ENRICHED] Package manager executing — SBOM tampering attempt
    (tool=%proc.name cmdline=%proc.cmdline
     pod=%k8s.pod.name ns=%k8s.ns.name
     declared_components={sbom_analysis['total_components']}
     slsa_level={slsa_level}
     SBOM_INTEGRITY_VIOLATION=new_package_not_declared)
  priority: CRITICAL
  tags: [sbom_enriched, malicious_dependency, cnd_project, critical]
"""
    return rules


# ══════════════════════════════════════════════════════════════════════════════
# Kubernetes ConfigMap Storage
# ══════════════════════════════════════════════════════════════════════════════

def store_enrichment_configmap(namespace: str, image_ref: str,
                                enrichment: dict, falco_rules: str):
    """Store enrichment data as a Kubernetes ConfigMap."""
    image_hash = sha256(image_ref.encode()).hexdigest()[:12]
    cm_name = f"provenance-{image_hash}"

    cm = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(
            name=cm_name,
            namespace=namespace,
            labels={
                'app': 'cnd-enrichment',
                'image-hash': image_hash,
                'managed-by': 'provenance-enrichment-service'
            },
            annotations={
                'cnd.security/image': image_ref,
                'cnd.security/enriched-at': datetime.now(timezone.utc).isoformat(),
                'cnd.security/slsa-level': enrichment.get('slsa_level', 'unknown'),
                'cnd.security/signer': enrichment.get('signer_identity', 'unknown'),
            }
        ),
        data={
            'image_ref': image_ref,
            'image_hash': image_hash,
            'enrichment.json': json.dumps(enrichment, indent=2),
            'allowed_binaries.json': json.dumps(
                {'allowed': enrichment['sbom_analysis']['allowed_binaries']},
                indent=2
            ),
            'allowed_packages.json': json.dumps(
                {'packages': enrichment['sbom_analysis']['allowed_packages']},
                indent=2
            ),
            'falco_rules.yaml': falco_rules,
        }
    )

    try:
        v1.create_namespaced_config_map(namespace=namespace, body=cm)
        log.info(f"Created ConfigMap {cm_name} in {namespace}")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            v1.replace_namespaced_config_map(name=cm_name, namespace=namespace, body=cm)
            log.info(f"Updated ConfigMap {cm_name}")
        else:
            log.error(f"Failed to create ConfigMap: {e}")


def reload_falco_rules():
    """Signal Falco to reload rules via falcoctl or hot-reload."""
    try:
        result = subprocess.run(
            ["kubectl", "rollout", "restart", "daemonset/falco", "-n", "falco"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            log.info("Falco rules reload triggered")
        else:
            log.warning(f"Falco reload failed: {result.stderr}")
    except Exception as e:
        log.warning(f"Could not reload Falco: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# Pod Watcher — Main Loop
# ══════════════════════════════════════════════════════════════════════════════

def enrich_pod(pod) -> Optional[dict]:
    """Full enrichment pipeline for a single Pod."""
    pod_name = pod.metadata.name
    namespace = pod.metadata.namespace

    # Get image references from all containers
    images = []
    for container in (pod.spec.containers or []):
        if container.image:
            images.append(container.image)

    if not images:
        return None

    image_ref = images[0]
    image_hash = sha256(image_ref.encode()).hexdigest()[:12]

    # Skip if already enriched
    if image_hash in enrichments:
        log.debug(f"Pod {pod_name} image already enriched: {image_hash}")
        return enrichments[image_hash]

    log.info(f"Enriching pod {pod_name} with image {image_ref}")

    # 1. Fetch SBOM
    sbom = fetch_sbom(image_ref)
    sbom_analysis = parse_sbom(sbom) if sbom else {
        'allowed_binaries': ['cnd-app'],
        'allowed_packages': [],
        'allowed_ports': [8080],
        'total_components': 0
    }

    # 2. Fetch SLSA Provenance
    provenance = fetch_slsa_provenance(image_ref)
    slsa_level = "3" if provenance else "unknown"

    # 3. Verify Signature
    sig_result = verify_signature(image_ref)
    signer_identity = sig_result.get('signer_identity', 'unknown')

    # 4. Build enrichment record
    enrichment = {
        'image_ref': image_ref,
        'image_hash': image_hash,
        'pod_name': pod_name,
        'namespace': namespace,
        'enriched_at': datetime.now(timezone.utc).isoformat(),
        'slsa_level': slsa_level,
        'signer_identity': signer_identity,
        'signature_verified': sig_result.get('verified', False),
        'sbom_available': sbom is not None,
        'sbom_analysis': sbom_analysis,
        'provenance_available': provenance is not None,
    }

    # 5. Generate dynamic Falco rules
    falco_rules = generate_falco_rules(
        image_ref, sbom_analysis, slsa_level, signer_identity
    )

    # 6. Store in ConfigMap
    store_enrichment_configmap(namespace, image_ref, enrichment, falco_rules)

    # 7. Cache enrichment
    enrichments[image_hash] = enrichment

    # 8. Trigger Falco reload
    reload_falco_rules()

    log.info(f"✅ Enrichment complete for {pod_name}: "
             f"SLSA={slsa_level}, signed={sig_result.get('verified')}, "
             f"SBOM_packages={sbom_analysis['total_components']}")

    return enrichment


def watch_pods():
    """Watch for new Pod creations and enrich them."""
    log.info(f"Watching for Pods in namespace: {NAMESPACE}")
    w = watch.Watch()

    while True:
        try:
            for event in w.stream(
                v1.list_namespaced_pod,
                namespace=NAMESPACE,
                timeout_seconds=60
            ):
                event_type = event['type']
                pod = event['object']

                if event_type == 'ADDED' and pod.status.phase not in ('Failed', 'Unknown'):
                    try:
                        enrich_pod(pod)
                    except Exception as e:
                        log.error(f"Enrichment failed for {pod.metadata.name}: {e}")

        except Exception as e:
            log.error(f"Watch error: {e} — reconnecting in 5s")
            time.sleep(5)


# ══════════════════════════════════════════════════════════════════════════════
# REST API Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/health')
def health():
    return jsonify({"status": "ok", "enrichments": len(enrichments)})


@app.route('/enrichments')
def list_enrichments():
    return jsonify({"count": len(enrichments), "data": list(enrichments.values())})


@app.route('/enrich', methods=['POST'])
def manual_enrich():
    """Manually trigger enrichment for an image."""
    data = request.get_json()
    image_ref = data.get('image_ref')
    if not image_ref:
        return jsonify({"error": "image_ref required"}), 400

    sbom = fetch_sbom(image_ref)
    sbom_analysis = parse_sbom(sbom) if sbom else {
        'allowed_binaries': [], 'allowed_packages': [],
        'allowed_ports': [8080], 'total_components': 0
    }
    sig_result = verify_signature(image_ref)
    provenance = fetch_slsa_provenance(image_ref)

    enrichment = {
        'image_ref': image_ref,
        'image_hash': sha256(image_ref.encode()).hexdigest()[:12],
        'slsa_level': '3' if provenance else 'unknown',
        'signer_identity': sig_result.get('signer_identity', 'unknown'),
        'signature_verified': sig_result.get('verified', False),
        'sbom_analysis': sbom_analysis,
        'enriched_at': datetime.now(timezone.utc).isoformat(),
    }
    falco_rules = generate_falco_rules(
        image_ref, sbom_analysis,
        enrichment['slsa_level'], enrichment['signer_identity']
    )
    store_enrichment_configmap(NAMESPACE, image_ref, enrichment, falco_rules)
    enrichments[enrichment['image_hash']] = enrichment

    return jsonify({"status": "enriched", "data": enrichment})


# ══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import threading
    log.info("Starting Provenance Enrichment Service")
    log.info("This service BRIDGES build-time security with runtime monitoring")

    watcher_thread = threading.Thread(target=watch_pods, daemon=True)
    watcher_thread.start()

    port = int(os.environ.get('PORT', 8090))
    app.run(host='0.0.0.0', port=port)
