#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# simulate_attacks.sh — CND Project Attack Simulation (10 runs per scenario)
# Runs 3 scenarios × 10 iterations → detection_results.csv
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

TS()     { date '+%Y-%m-%d %H:%M:%S'; }
info()   { echo "[$(TS)] [INFO]   $*"; }
attack() { echo "[$(TS)] [ATTACK] $*"; }
result() { echo "[$(TS)] [RESULT] $*"; }

RESULTS_DIR="evaluation/results"
mkdir -p "$RESULTS_DIR"
CSV="$RESULTS_DIR/detection_results.csv"
RUNS="${ATTACK_RUNS:-10}"

IMAGE_REF="${IMAGE_REF:-localhost:5001/cnd-demo-app:latest}"
TAMPERED_IMAGE="${TAMPERED_IMAGE:-docker.io/library/alpine:latest}"
NAMESPACE="cnd-demo"

# Initialize CSV
echo "run,scenario,attack_type,detected,detection_time_ms,detection_layer,alert_rule,notes" > "$CSV"
info "Results CSV: $CSV"
info "Runs per scenario: $RUNS"

# ─────────────────────────────────────────────────────────────────────────────
wait_for_falco_alert() {
    # Wait up to $timeout seconds for a Falco alert matching $pattern
    local pattern="$1"
    local timeout="${2:-15}"
    local elapsed=0
    local start
    start=$(date +%s%3N)

    while [ $elapsed -lt $((timeout * 1000)) ]; do
        if kubectl logs -n falco -l app.kubernetes.io/name=falco \
            --since=30s 2>/dev/null | grep -q "$pattern"; then
            local end
            end=$(date +%s%3N)
            echo $((end - start))
            return 0
        fi
        sleep 0.5
        elapsed=$(( $(date +%s%3N) - start ))
    done
    echo "-1"
    return 1
}

record() {
    local run="$1" scenario="$2" attack_type="$3" detected="$4"
    local det_ms="$5" layer="$6" rule="$7" notes="$8"
    echo "${run},${scenario},${attack_type},${detected},${det_ms},${layer},${rule},\"${notes}\"" >> "$CSV"
}

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1: Image Tampering — Unsigned Image Deployment
# Expected: BLOCKED at admission by Kyverno
# ══════════════════════════════════════════════════════════════════════════════
run_scenario_1() {
    info "════ SCENARIO 1: Image Tampering (${RUNS} runs) ════"

    for run in $(seq 1 $RUNS); do
        attack "S1 Run ${run}/${RUNS}: Deploying unsigned/tampered image..."
        START=$(date +%s%3N)

        OUTPUT=$(kubectl apply -f - 2>&1 <<EOF || true
apiVersion: v1
kind: Pod
metadata:
  name: tampered-test-${run}-$(date +%s)
  namespace: ${NAMESPACE}
  labels:
    experiment: scenario-1
    run: "${run}"
spec:
  containers:
    - name: tampered
      image: ${TAMPERED_IMAGE}
      command: ["sleep", "10"]
  restartPolicy: Never
EOF
)
        END=$(date +%s%3N)
        DURATION=$((END - START))

        if echo "$OUTPUT" | grep -qiE "denied|blocked|Error|admission webhook"; then
            result "✅ S1 Run ${run}: BLOCKED in ${DURATION}ms"
            record "$run" "S1" "image_tampering_unsigned" "true" "$DURATION" \
                "admission_kyverno" "verify-cosign-signature" \
                "Unsigned image blocked by Kyverno policy"
        else
            result "❌ S1 Run ${run}: NOT BLOCKED (${DURATION}ms)"
            record "$run" "S1" "image_tampering_unsigned" "false" "$DURATION" \
                "none" "" "Image was not blocked — policy may be missing"
            # Cleanup if somehow deployed
            kubectl delete pod -n "$NAMESPACE" -l experiment=scenario-1,run="$run" \
                --ignore-not-found=true &>/dev/null || true
        fi
        sleep 2
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2: Runtime Anomaly — Shell Execution in Container
# Expected: DETECTED by Falco SBOM-enriched rule
# ══════════════════════════════════════════════════════════════════════════════
run_scenario_2() {
    info "════ SCENARIO 2: Runtime Shell Execution (${RUNS} runs) ════"

    # Get or create a target pod
    POD=$(kubectl get pod -n "$NAMESPACE" -l app=cnd-demo-app \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [ -z "$POD" ]; then
        info "Deploying test pod for scenario 2..."
        kubectl run cnd-attack-target \
            --image=python:3.12-slim \
            --namespace="$NAMESPACE" \
            --restart=Never \
            --labels="experiment=attack-target" \
            -- sleep 600 2>/dev/null || true
        kubectl wait --for=condition=Ready pod/cnd-attack-target \
            -n "$NAMESPACE" --timeout=60s 2>/dev/null || true
        POD="cnd-attack-target"
    fi

    for run in $(seq 1 $RUNS); do
        attack "S2 Run ${run}/${RUNS}: Spawning shell inside container $POD..."

        START=$(date +%s%3N)
        kubectl exec "$POD" -n "$NAMESPACE" -- \
            /bin/sh -c "id; whoami; echo 'ATTACK_MARKER_S2'" &>/dev/null 2>&1 || true

        # Wait for Falco detection
        DET_MS=$(wait_for_falco_alert "shell\|Shell\|CND-SC-002\|SBOM.*shell" 15 || echo "-1")
        END=$(date +%s%3N)

        if [ "$DET_MS" != "-1" ]; then
            result "✅ S2 Run ${run}: Shell detected in ${DET_MS}ms"
            record "$run" "S2" "runtime_shell_execution" "true" "$DET_MS" \
                "runtime_falco_ebpf" "SBOM Violation - Shell Execution" \
                "Shell spawned in SBOM-verified container"
        else
            TOTAL=$((END - START))
            result "⚠️  S2 Run ${run}: Not detected in ${TOTAL}ms window"
            record "$run" "S2" "runtime_shell_execution" "false" "$TOTAL" \
                "none" "" "Alert not found in 15s window"
        fi
        sleep 3
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3: Malicious Dependency — Package Installation at Runtime
# Expected: DETECTED by Falco SBOM-enriched rule (pip not in SBOM)
# ══════════════════════════════════════════════════════════════════════════════
run_scenario_3() {
    info "════ SCENARIO 3: Malicious Dependency Injection (${RUNS} runs) ════"

    POD=$(kubectl get pod -n "$NAMESPACE" -l experiment=attack-target \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "cnd-attack-target")

    for run in $(seq 1 $RUNS); do
        attack "S3 Run ${run}/${RUNS}: Running pip install inside container (SBOM violation)..."

        START=$(date +%s%3N)
        kubectl exec "$POD" -n "$NAMESPACE" -- \
            sh -c "pip install requests --quiet 2>&1 | head -3" &>/dev/null 2>&1 || true

        DET_MS=$(wait_for_falco_alert "pip\|Package manager\|CND-SC-003\|SBOM.*package\|malicious_dependency" 15 || echo "-1")
        END=$(date +%s%3N)

        if [ "$DET_MS" != "-1" ]; then
            result "✅ S3 Run ${run}: Malicious dependency detected in ${DET_MS}ms"
            record "$run" "S3" "malicious_dependency_injection" "true" "$DET_MS" \
                "runtime_falco_ebpf" "SBOM Violation - Package Installation" \
                "pip install not in SBOM — malicious dependency injection detected"
        else
            TOTAL=$((END - START))
            result "⚠️  S3 Run ${run}: Not detected in ${TOTAL}ms window"
            record "$run" "S3" "malicious_dependency_injection" "false" "$TOTAL" \
                "none" "" "Alert not found in 15s window"
        fi
        sleep 3
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# FALSE POSITIVE TEST: Clean deployments (should NOT trigger alerts)
# Used to calculate FPR = false alerts / 10 clean runs
# ══════════════════════════════════════════════════════════════════════════════
run_false_positive_test() {
    info "════ FALSE POSITIVE TEST: 10 clean deployments ════"
    FP_CSV="$RESULTS_DIR/false_positive_results.csv"
    echo "run,alerts_triggered,false_positive" > "$FP_CSV"

    for run in $(seq 1 10); do
        info "FP Run ${run}/10: Normal operation (no attacks)..."
        BEFORE_COUNT=$(kubectl logs -n falco -l app.kubernetes.io/name=falco \
            --since=5s 2>/dev/null | grep -c "CND\|SBOM" || echo "0")
        sleep 10
        AFTER_COUNT=$(kubectl logs -n falco -l app.kubernetes.io/name=falco \
            --since=10s 2>/dev/null | grep -c "CND\|SBOM" || echo "0")
        NEW_ALERTS=$((AFTER_COUNT - BEFORE_COUNT))
        FP=$([ "$NEW_ALERTS" -gt 0 ] && echo "true" || echo "false")
        echo "${run},${NEW_ALERTS},${FP}" >> "$FP_CSV"
        info "FP Run ${run}: new alerts=$NEW_ALERTS, false_positive=$FP"
        sleep 2
    done
    info "False positive results saved to $FP_CSV"
}

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
print_summary() {
    python3 - <<PYEOF
import csv, statistics

rows = []
with open("$CSV") as f:
    for r in csv.DictReader(f):
        rows.append(r)

scenarios = {}
for r in rows:
    s = r['scenario']
    if s not in scenarios:
        scenarios[s] = {'detected': 0, 'total': 0, 'times': []}
    scenarios[s]['total'] += 1
    if r['detected'] == 'true':
        scenarios[s]['detected'] += 1
        t = int(r['detection_time_ms'])
        if t > 0:
            scenarios[s]['times'].append(t)

print()
print("╔════════════════════════════════════════════════════════════════╗")
print("║   Attack Simulation Results                                    ║")
print("╠══════════╦═══════╦═══════╦═══════════╦════════════════════════╣")
print("║ Scenario ║ Total ║  TPR  ║ Avg Det.  ║ Min / Max (ms)         ║")
print("╠══════════╬═══════╬═══════╬═══════════╬════════════════════════╣")
for s, d in scenarios.items():
    tpr = d['detected'] / d['total'] * 100
    avg = statistics.mean(d['times']) if d['times'] else 0
    mn  = min(d['times']) if d['times'] else 0
    mx  = max(d['times']) if d['times'] else 0
    print(f"║  {s:7s} ║  {d['total']:4d} ║ {tpr:5.1f}% ║ {avg:7.0f}ms ║ {mn:5d} / {mx:5d}ms         ║")
print("╚══════════╩═══════╩═══════╩═══════════╩════════════════════════╝")
print(f"\n  Full results: $CSV")
PYEOF
}

# ── MAIN ──
main() {
    info "Starting CND Attack Simulation (${RUNS} runs per scenario)"
    run_scenario_1
    run_scenario_2
    run_scenario_3
    run_false_positive_test
    print_summary
}

main "$@"
