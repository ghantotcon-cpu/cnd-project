#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# attack-scenarios.sh
# CND Project — Attack Simulation Script
# Simulates 4 attack scenarios to test the integrated security framework.
# All results are saved for use in Chapter 4 (Results & Discussion).
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}   $*"; }
attack()  { echo -e "${RED}[ATTACK]${NC} $*"; }
result()  { echo -e "${CYAN}[RESULT]${NC} $*"; }
section() { echo -e "\n${BLUE}══ $* ══${NC}"; }

RESULTS_DIR="evaluation/results"
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$RESULTS_DIR/attack-report-${TIMESTAMP}.json"

# Initialize JSON report
cat > "$REPORT" <<EOF
{
  "experiment": "CND Project Attack Simulation",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "scenarios": []
}
EOF

record_result() {
    local scenario="$1"
    local attack_type="$2"
    local detected="$3"
    local detection_layer="$4"
    local detection_time_ms="$5"
    local notes="$6"

    python3 - <<PYEOF
import json

with open("$REPORT", "r") as f:
    data = json.load(f)

data["scenarios"].append({
    "scenario": "$scenario",
    "attack_type": "$attack_type",
    "detected": $detected,
    "detection_layer": "$detection_layer",
    "detection_time_ms": $detection_time_ms,
    "notes": "$notes"
})

with open("$REPORT", "w") as f:
    json.dump(data, f, indent=2)
PYEOF
    echo "  → Recorded to report ✓"
}

# ─────────────────────────────────────────────
# SCENARIO 1: Image Tampering Attack
# Tests: Kyverno admission control + Cosign verification
# Expected: BLOCKED at admission (before running)
# ─────────────────────────────────────────────
scenario_1_image_tampering() {
    section "SCENARIO 1: Image Tampering (Unsigned Image)"
    attack "Attempting to deploy an UNSIGNED/tampered image..."

    START=$(date +%s%3N)

    # Create a pod with an unsigned image (simulating tampered artifact)
    cat <<EOF | kubectl apply -f - 2>&1 | tee /tmp/scenario1-output.txt
apiVersion: v1
kind: Pod
metadata:
  name: tampered-image-test
  namespace: cnd-demo
  labels:
    experiment: scenario-1-image-tampering
spec:
  containers:
    - name: tampered
      image: docker.io/library/alpine:latest   # Unsigned, non-trusted registry
      command: ["sleep", "3600"]
EOF

    END=$(date +%s%3N)
    DURATION=$(($END - $START))

    if grep -q "Error\|denied\|blocked\|failed" /tmp/scenario1-output.txt 2>/dev/null; then
        result "✅ DETECTED & BLOCKED — Kyverno rejected unsigned image in ${DURATION}ms"
        DETECTED="true"
        LAYER="admission_control"
    else
        result "❌ NOT DETECTED — Image deployed (framework failure)"
        DETECTED="false"
        LAYER="none"
        # Cleanup if deployed
        kubectl delete pod tampered-image-test -n cnd-demo --ignore-not-found=true
    fi

    record_result \
        "Scenario 1" \
        "image_tampering_unsigned" \
        "$DETECTED" \
        "$LAYER" \
        "$DURATION" \
        "Unsigned image from non-trusted registry blocked by Kyverno policy"

    cat /tmp/scenario1-output.txt
}

# ─────────────────────────────────────────────
# SCENARIO 2: Anomalous Runtime Behavior — Shell Execution
# Tests: Falco runtime monitoring (eBPF)
# Expected: DETECTED by Falco (CND-SC-002 alert)
# ─────────────────────────────────────────────
scenario_2_runtime_shell() {
    section "SCENARIO 2: Runtime Anomaly — Shell Execution"
    attack "Spawning a shell inside the verified container (simulating exploitation)..."

    POD=$(kubectl get pod -n cnd-demo -l app=cnd-demo-app -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [ -z "$POD" ]; then
        warn "No cnd-demo pod running. Deploying a test pod..."
        kubectl run cnd-test --image=python:3.12-slim -n cnd-demo \
            --restart=Never -- sleep 300
        kubectl wait --for=condition=Ready pod/cnd-test -n cnd-demo --timeout=60s
        POD="cnd-test"
    fi

    info "Target pod: $POD"

    START=$(date +%s%3N)

    # Execute shell commands inside container — Falco should detect this
    kubectl exec "$POD" -n cnd-demo -- /bin/sh -c "id; whoami; uname -a" 2>&1 \
        | tee /tmp/scenario2-shell-output.txt || true

    SHELL_TIME=$(date +%s%3N)
    SHELL_DURATION=$(($SHELL_TIME - $START))

    # Wait for Falco to detect and log
    sleep 5

    # Check Falco logs for detection
    FALCO_LOGS=$(kubectl logs -n falco -l app.kubernetes.io/name=falco \
        --since=30s 2>/dev/null || echo "")

    if echo "$FALCO_LOGS" | grep -q "CND-SC-002\|Shell spawned\|shell_spawned"; then
        END=$(date +%s%3N)
        DETECT_DURATION=$(($END - $START))
        result "✅ DETECTED — Falco alert CND-SC-002 triggered in ${DETECT_DURATION}ms"
        DETECTED="true"
        LAYER="runtime_falco_ebpf"
    else
        result "⚠️  Falco log not found in time window (may need more time)"
        DETECTED="false"
        LAYER="runtime_falco_ebpf"
        DETECT_DURATION=$SHELL_DURATION
    fi

    record_result \
        "Scenario 2" \
        "anomalous_runtime_shell_execution" \
        "$DETECTED" \
        "$LAYER" \
        "$DETECT_DURATION" \
        "Shell spawned inside verified container — Falco eBPF rule CND-SC-002"

    # Print relevant Falco alerts
    echo "$FALCO_LOGS" | grep -E "CND|shell|Shell" | head -20 || true
}

# ─────────────────────────────────────────────
# SCENARIO 3: Malicious Dependency Injection
# Tests: Falco runtime (package manager detection) + SBOM mismatch
# Expected: DETECTED by Falco (CND-SC-003)
# ─────────────────────────────────────────────
scenario_3_malicious_dependency() {
    section "SCENARIO 3: Malicious Dependency Injection (pip install)"
    attack "Attempting to install unauthorized package inside container (SBOM violation)..."

    POD=$(kubectl get pod -n cnd-demo -l app=cnd-demo-app -o jsonpath='{.items[0].metadata.name}' 2>/dev/null \
        || kubectl get pod cnd-test -n cnd-demo -o name 2>/dev/null | cut -d/ -f2 || echo "")

    if [ -z "$POD" ]; then
        warn "No pod available for scenario 3. Skipping."
        return
    fi

    START=$(date +%s%3N)

    # Attempt to install a package — violates SBOM-declared inventory
    kubectl exec "$POD" -n cnd-demo -- \
        sh -c "pip install requests --quiet 2>&1 | head -5" 2>&1 \
        | tee /tmp/scenario3-output.txt || true

    sleep 5

    FALCO_LOGS=$(kubectl logs -n falco -l app.kubernetes.io/name=falco \
        --since=30s 2>/dev/null || echo "")

    if echo "$FALCO_LOGS" | grep -q "CND-SC-003\|Package manager\|SBOM_VIOLATION"; then
        END=$(date +%s%3N)
        DETECT_DURATION=$(($END - $START))
        result "✅ DETECTED — Falco CND-SC-003 alert: package manager SBOM violation in ${DETECT_DURATION}ms"
        DETECTED="true"
        LAYER="runtime_falco_ebpf"
    else
        END=$(date +%s%3N)
        DETECT_DURATION=$(($END - $START))
        result "⚠️  Alert not found in log window (check full Falco logs)"
        DETECTED="false"
        LAYER="runtime_falco_ebpf"
    fi

    record_result \
        "Scenario 3" \
        "malicious_dependency_injection" \
        "$DETECTED" \
        "$LAYER" \
        "$DETECT_DURATION" \
        "pip install executed inside container — violates CycloneDX SBOM inventory"

    echo "$FALCO_LOGS" | grep -E "CND|pip|package" | head -10 || true
}

# ─────────────────────────────────────────────
# SCENARIO 4: Network Exfiltration Attempt
# Tests: Falco network monitoring (CND-SC-005, CND-SC-008)
# Expected: DETECTED by Falco
# ─────────────────────────────────────────────
scenario_4_network_exfiltration() {
    section "SCENARIO 4: Data Exfiltration via Network Tool"
    attack "Executing curl/wget inside container — simulating C2 / data exfiltration..."

    POD=$(kubectl get pod -n cnd-demo -l app=cnd-demo-app -o jsonpath='{.items[0].metadata.name}' 2>/dev/null \
        || kubectl get pod cnd-test -n cnd-demo -o name 2>/dev/null | cut -d/ -f2 || echo "")

    if [ -z "$POD" ]; then
        warn "No pod available for scenario 4. Skipping."
        return
    fi

    START=$(date +%s%3N)

    # Attempt network exfiltration simulation
    kubectl exec "$POD" -n cnd-demo -- \
        sh -c "curl -s --max-time 5 http://httpbin.org/get 2>&1 | head -3" 2>&1 \
        | tee /tmp/scenario4-output.txt || true

    sleep 5

    FALCO_LOGS=$(kubectl logs -n falco -l app.kubernetes.io/name=falco \
        --since=30s 2>/dev/null || echo "")

    if echo "$FALCO_LOGS" | grep -q "CND-SC-005\|CND-SC-008\|exfiltration\|Network tool"; then
        END=$(date +%s%3N)
        DETECT_DURATION=$(($END - $START))
        result "✅ DETECTED — Falco network exfiltration alert in ${DETECT_DURATION}ms"
        DETECTED="true"
        LAYER="runtime_falco_ebpf"
    else
        END=$(date +%s%3N)
        DETECT_DURATION=$(($END - $START))
        result "⚠️  Alert not found in log window"
        DETECTED="false"
        LAYER="runtime_falco_ebpf"
    fi

    record_result \
        "Scenario 4" \
        "network_exfiltration_curl" \
        "$DETECTED" \
        "$LAYER" \
        "$DETECT_DURATION" \
        "curl executed inside container — network tool not declared in SBOM (CND-SC-005)"
}

# ─────────────────────────────────────────────
# FINAL REPORT SUMMARY
# ─────────────────────────────────────────────
print_summary() {
    section "Attack Simulation Summary"

    python3 - <<PYEOF
import json

with open("$REPORT") as f:
    data = json.load(f)

scenarios = data["scenarios"]
total = len(scenarios)
detected = sum(1 for s in scenarios if s["detected"])

print(f"  Total scenarios tested:  {total}")
print(f"  Detected (True Positive): {detected}")
print(f"  Not Detected:            {total - detected}")
print(f"  Detection Rate:          {detected/total*100:.1f}%")
print()
print("  Results by scenario:")
for s in scenarios:
    status = "✅ DETECTED" if s["detected"] else "❌ MISSED"
    print(f"    {s['scenario']:12s} | {status:15s} | {s['attack_type']:40s} | {s['detection_time_ms']}ms | Layer: {s['detection_layer']}")

print()
print(f"  Full report: $REPORT")
PYEOF
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
main() {
    info "Starting CND Project Attack Simulation..."
    info "Results will be saved to: $RESULTS_DIR"

    scenario_1_image_tampering
    scenario_2_runtime_shell
    scenario_3_malicious_dependency
    scenario_4_network_exfiltration
    print_summary
}

main "$@"
