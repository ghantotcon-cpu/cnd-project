#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# collect-metrics.sh
# CND Project — Research Metrics Collection Script
# Collects performance overhead data for Chapter 4 (Results & Discussion)
#
# Metrics collected:
#   1. Admission latency (with and without Kyverno)
#   2. Falco CPU/memory overhead
#   3. Cluster resource utilization
#   4. Signature verification time
#   5. SBOM verification time
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
metric()  { echo -e "${CYAN}[METRIC]${NC} $*"; }

RESULTS_DIR="evaluation/results"
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
METRICS_FILE="$RESULTS_DIR/performance-metrics-${TIMESTAMP}.json"

IMAGE_REF="${1:-ghcr.io/ghantotcon-cpu/cnd-project/cnd-demo-app:latest}"

info "Starting metrics collection..."
info "Image: $IMAGE_REF"
info "Output: $METRICS_FILE"

# Initialize JSON output
cat > "$METRICS_FILE" <<EOF
{
  "experiment": "CND Project Performance Overhead Assessment",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "image": "${IMAGE_REF}",
  "metrics": {}
}
EOF

update_metrics() {
    local key="$1"
    local value="$2"
    python3 -c "
import json
with open('$METRICS_FILE', 'r') as f:
    data = json.load(f)
data['metrics']['$key'] = $value
with open('$METRICS_FILE', 'w') as f:
    json.dump(data, f, indent=2)
"
}

# ─────────────────────────────────────────────
# METRIC 1: Cosign Signature Verification Time
# ─────────────────────────────────────────────
measure_cosign_verification() {
    info "Measuring Cosign signature verification time..."

    local samples=5
    local total=0

    for i in $(seq 1 $samples); do
        START=$(date +%s%3N)
        cosign verify \
            --certificate-identity-regexp "https://github.com/ghantotcon-cpu/*" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "$IMAGE_REF" &>/dev/null || true
        END=$(date +%s%3N)
        DURATION=$(($END - $START))
        total=$(($total + $DURATION))
        metric "  Sample $i: ${DURATION}ms"
    done

    AVG=$(($total / $samples))
    metric "Cosign verification average: ${AVG}ms (${samples} samples)"
    update_metrics "cosign_verification_avg_ms" "$AVG"
    update_metrics "cosign_verification_samples" "$samples"
}

# ─────────────────────────────────────────────
# METRIC 2: SBOM Verification Time (Cosign attest verify)
# ─────────────────────────────────────────────
measure_sbom_verification() {
    info "Measuring SBOM attestation verification time..."

    local samples=5
    local total=0

    for i in $(seq 1 $samples); do
        START=$(date +%s%3N)
        cosign verify-attestation \
            --certificate-identity-regexp "https://github.com/ghantotcon-cpu/*" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            --type cyclonedx \
            "$IMAGE_REF" &>/dev/null || true
        END=$(date +%s%3N)
        DURATION=$(($END - $START))
        total=$(($total + $DURATION))
        metric "  Sample $i: ${DURATION}ms"
    done

    AVG=$(($total / $samples))
    metric "SBOM verification average: ${AVG}ms (${samples} samples)"
    update_metrics "sbom_verification_avg_ms" "$AVG"
}

# ─────────────────────────────────────────────
# METRIC 3: Kubernetes Admission Latency
# Measures time for pod admission with Kyverno policy enforcement
# ─────────────────────────────────────────────
measure_admission_latency() {
    info "Measuring Kubernetes admission latency (with Kyverno)..."

    local samples=5
    local total=0

    for i in $(seq 1 $samples); do
        # Create a test pod and measure time until admission decision
        START=$(date +%s%3N)
        kubectl run admission-test-${i} \
            --image="$IMAGE_REF" \
            --namespace=cnd-demo \
            --restart=Never \
            --dry-run=server \
            --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000}}}' \
            &>/dev/null || true
        END=$(date +%s%3N)
        DURATION=$(($END - $START))
        total=$(($total + $DURATION))
        metric "  Sample $i: ${DURATION}ms"
    done

    AVG=$(($total / $samples))
    metric "Admission latency average: ${AVG}ms (${samples} samples)"
    update_metrics "admission_latency_avg_ms" "$AVG"
}

# ─────────────────────────────────────────────
# METRIC 4: Falco CPU & Memory Overhead
# ─────────────────────────────────────────────
measure_falco_overhead() {
    info "Measuring Falco CPU and memory overhead..."

    # Get Falco pod metrics
    FALCO_METRICS=$(kubectl top pods -n falco 2>/dev/null || echo "Metrics server not available")

    if echo "$FALCO_METRICS" | grep -q "falco"; then
        CPU=$(echo "$FALCO_METRICS" | grep falco | awk '{print $2}' | head -1)
        MEM=$(echo "$FALCO_METRICS" | grep falco | awk '{print $3}' | head -1)
        metric "Falco CPU: $CPU | Memory: $MEM"
        update_metrics "falco_cpu" "\"$CPU\""
        update_metrics "falco_memory" "\"$MEM\""
    else
        metric "kubectl top not available (metrics-server not installed)"
        # Fall back to reading from /proc inside the pod
        FALCO_POD=$(kubectl get pod -n falco -l app.kubernetes.io/name=falco \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

        if [ -n "$FALCO_POD" ]; then
            metric "Falco pod: $FALCO_POD"
            update_metrics "falco_pod" "\"$FALCO_POD\""
        fi
    fi
}

# ─────────────────────────────────────────────
# METRIC 5: Kyverno CPU & Memory Overhead
# ─────────────────────────────────────────────
measure_kyverno_overhead() {
    info "Measuring Kyverno (admission controller) overhead..."

    KYVERNO_METRICS=$(kubectl top pods -n kyverno 2>/dev/null || echo "Metrics server not available")

    if echo "$KYVERNO_METRICS" | grep -q "kyverno"; then
        CPU=$(echo "$KYVERNO_METRICS" | grep "kyverno-admission" | awk '{print $2}' | head -1)
        MEM=$(echo "$KYVERNO_METRICS" | grep "kyverno-admission" | awk '{print $3}' | head -1)
        metric "Kyverno admission controller CPU: $CPU | Memory: $MEM"
        update_metrics "kyverno_cpu" "\"$CPU\""
        update_metrics "kyverno_memory" "\"$MEM\""
    fi
}

# ─────────────────────────────────────────────
# METRIC 6: SBOM Component Count
# ─────────────────────────────────────────────
measure_sbom_stats() {
    info "Generating and analyzing SBOM..."

    START=$(date +%s%3N)
    syft "$IMAGE_REF" -o cyclonedx-json=sbom-analysis.json 2>/dev/null || true
    END=$(date +%s%3N)
    SBOM_GEN_TIME=$(($END - $START))

    if [ -f sbom-analysis.json ]; then
        python3 - <<PYEOF
import json

with open("sbom-analysis.json") as f:
    sbom = json.load(f)

components = sbom.get("components", [])
total = len(components)

by_type = {}
for c in components:
    t = c.get("type", "unknown")
    by_type[t] = by_type.get(t, 0) + 1

print(f"  SBOM total components: {total}")
for t, c in sorted(by_type.items()):
    print(f"    {t}: {c}")

# Update metrics file
import json as j2
with open("$METRICS_FILE") as f:
    data = j2.load(f)
data["metrics"]["sbom_total_components"] = total
data["metrics"]["sbom_components_by_type"] = by_type
data["metrics"]["sbom_generation_time_ms"] = $SBOM_GEN_TIME
with open("$METRICS_FILE", "w") as f:
    j2.dump(data, f, indent=2)
PYEOF
        rm -f sbom-analysis.json
    fi
}

# ─────────────────────────────────────────────
# FINAL REPORT
# ─────────────────────────────────────────────
print_report() {
    info "Generating final metrics report..."

    python3 - <<PYEOF
import json

with open("$METRICS_FILE") as f:
    data = json.load(f)

m = data["metrics"]
print()
print("╔════════════════════════════════════════════════════════════╗")
print("║   CND Project — Performance Overhead Report                ║")
print("╠════════════════════════════════════════════════════════════╣")
print(f"║  Timestamp: {data['timestamp']}")
print(f"║  Image: {data['image']}")
print("╠════════════════════════════════════════════════════════════╣")
print(f"║  Cosign signature verification:  {m.get('cosign_verification_avg_ms', 'N/A')}ms avg")
print(f"║  SBOM attestation verification:  {m.get('sbom_verification_avg_ms', 'N/A')}ms avg")
print(f"║  Admission latency (Kyverno):    {m.get('admission_latency_avg_ms', 'N/A')}ms avg")
print(f"║  SBOM generation time:           {m.get('sbom_generation_time_ms', 'N/A')}ms")
print(f"║  SBOM total components:          {m.get('sbom_total_components', 'N/A')}")
print(f"║  Falco CPU overhead:             {m.get('falco_cpu', 'N/A')}")
print(f"║  Falco memory overhead:          {m.get('falco_memory', 'N/A')}")
print(f"║  Kyverno CPU overhead:           {m.get('kyverno_cpu', 'N/A')}")
print("╚════════════════════════════════════════════════════════════╝")
print()
print(f"  Full metrics saved to: $METRICS_FILE")
PYEOF
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
main() {
    measure_cosign_verification
    measure_sbom_verification
    measure_admission_latency
    measure_falco_overhead
    measure_kyverno_overhead
    measure_sbom_stats
    print_report
}

main "$@"
