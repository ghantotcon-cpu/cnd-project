#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# collect_metrics.sh — 3-Mode Performance Comparison
# Mode A: No Security | Mode B: Build-time Only | Mode C: Full Framework
# Output: performance_results.csv, comparison_results.csv
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

TS()   { date '+%Y-%m-%d %H:%M:%S'; }
info() { echo "[$(TS)] [INFO]  $*"; }

RESULTS_DIR="evaluation/results"
mkdir -p "$RESULTS_DIR"
PERF_CSV="$RESULTS_DIR/performance_results.csv"
COMP_CSV="$RESULTS_DIR/comparison_results.csv"
SAMPLES="${METRIC_SAMPLES:-5}"
IMAGE_REF="${IMAGE_REF:-localhost:5001/cnd-demo-app:latest}"
PROM_URL="${PROMETHEUS_URL:-http://localhost:9090}"

echo "metric,mode,value_ms,unit,sample" > "$PERF_CSV"
echo "metric,mode_a,mode_b,mode_c,overhead_b_vs_a_pct,overhead_c_vs_a_pct" > "$COMP_CSV"

info "Performance Metrics Collection — ${SAMPLES} samples per measurement"
info "Image: $IMAGE_REF"

# ─────────────────────────────────────────────────────────────────────────────
prom_query() {
    local query="$1"
    curl -s "${PROM_URL}/api/v1/query?query=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))")" \
        2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
r=d.get('data',{}).get('result',[])
print(r[0]['value'][1] if r else '0')
" 2>/dev/null || echo "0"
}

append_perf() {
    local metric="$1" mode="$2" value="$3" unit="$4" sample="$5"
    echo "${metric},${mode},${value},${unit},${sample}" >> "$PERF_CSV"
}

# ══════════════════════════════════════════════════════════════════════════════
# METRIC 1: Build Pipeline Overhead
# ══════════════════════════════════════════════════════════════════════════════
measure_build_overhead() {
    info "── Measuring Build Time Overhead ──"

    for i in $(seq 1 $SAMPLES); do
        # Baseline: plain docker build
        START=$(date +%s%3N)
        docker build -q ./app -t baseline-test:${i} &>/dev/null || true
        END=$(date +%s%3N)
        BASE_MS=$((END - START))
        append_perf "docker_build_baseline" "mode_a" "$BASE_MS" "ms" "$i"

        # Mode B & C: full pipeline (signing + SBOM)
        START=$(date +%s%3N)
        bash scripts/build_pipeline.sh &>/dev/null || true
        END=$(date +%s%3N)
        FULL_MS=$((END - START))
        append_perf "build_pipeline_full" "mode_c" "$FULL_MS" "ms" "$i"

        OVERHEAD=$(python3 -c "print(f'{(($FULL_MS - $BASE_MS) / $BASE_MS * 100):.1f}')")
        info "  Build sample ${i}: baseline=${BASE_MS}ms full=${FULL_MS}ms overhead=${OVERHEAD}%"
        docker rmi baseline-test:${i} &>/dev/null || true
        sleep 2
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# METRIC 2: Cosign Signing Overhead
# ══════════════════════════════════════════════════════════════════════════════
measure_signing_overhead() {
    info "── Measuring Signing Overhead ──"

    for i in $(seq 1 $SAMPLES); do
        START=$(date +%s%3N)
        if [ -f cosign.key ]; then
            COSIGN_PASSWORD="" cosign sign --key cosign.key "${IMAGE_REF}" \
                --yes 2>/dev/null || true
        else
            cosign sign "${IMAGE_REF}" --yes 2>/dev/null || true
        fi
        END=$(date +%s%3N)
        SIGN_MS=$((END - START))
        append_perf "cosign_sign" "mode_c" "$SIGN_MS" "ms" "$i"
        info "  Signing sample ${i}: ${SIGN_MS}ms"
        sleep 1
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# METRIC 3: SBOM Generation Time
# ══════════════════════════════════════════════════════════════════════════════
measure_sbom_overhead() {
    info "── Measuring SBOM Generation Overhead ──"

    for i in $(seq 1 $SAMPLES); do
        START=$(date +%s%3N)
        syft "${IMAGE_REF}" -o cyclonedx-json=/tmp/sbom-measure-${i}.json &>/dev/null || true
        END=$(date +%s%3N)
        SBOM_MS=$((END - START))
        append_perf "sbom_generation" "mode_c" "$SBOM_MS" "ms" "$i"

        PKG_COUNT=$(python3 -c "
import json
try:
    with open('/tmp/sbom-measure-${i}.json') as f:
        d=json.load(f)
    print(len(d.get('components',[])))
except: print(0)
" 2>/dev/null || echo "0")
        info "  SBOM sample ${i}: ${SBOM_MS}ms, ${PKG_COUNT} components"
        rm -f "/tmp/sbom-measure-${i}.json"
        sleep 1
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# METRIC 4: Admission Latency (with/without Kyverno)
# ══════════════════════════════════════════════════════════════════════════════
measure_admission_latency() {
    info "── Measuring Admission Latency ──"

    for i in $(seq 1 $SAMPLES); do
        # Mode A: no Kyverno (use default namespace)
        START=$(date +%s%3N)
        kubectl run admission-baseline-${i} \
            --image=python:3.12-slim \
            --namespace=default \
            --restart=Never \
            --dry-run=server &>/dev/null 2>&1 || true
        END=$(date +%s%3N)
        BASE_ADM=$((END - START))
        append_perf "admission_latency" "mode_a" "$BASE_ADM" "ms" "$i"

        # Mode C: with Kyverno policies (cnd-demo namespace)
        START=$(date +%s%3N)
        kubectl run admission-kyverno-${i} \
            --image="${IMAGE_REF}" \
            --namespace=cnd-demo \
            --restart=Never \
            --dry-run=server \
            --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000}}}' \
            &>/dev/null 2>&1 || true
        END=$(date +%s%3N)
        KYVERNO_ADM=$((END - START))
        append_perf "admission_latency" "mode_c" "$KYVERNO_ADM" "ms" "$i"

        OVERHEAD=$((KYVERNO_ADM - BASE_ADM))
        info "  Admission sample ${i}: baseline=${BASE_ADM}ms kyverno=${KYVERNO_ADM}ms overhead=${OVERHEAD}ms"
        sleep 1
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# METRIC 5: Falco CPU + Memory (from Prometheus)
# ══════════════════════════════════════════════════════════════════════════════
measure_runtime_overhead() {
    info "── Measuring Runtime Monitoring Overhead (Falco + Tetragon) ──"

    # Without Falco: mode A
    BASELINE_CPU=$(prom_query 'avg(rate(node_cpu_seconds_total{mode="user"}[2m])) * 100')
    BASELINE_MEM=$(prom_query '(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100')
    append_perf "node_cpu_usage_pct" "mode_a" "$BASELINE_CPU" "percent" "1"
    append_perf "node_memory_usage_pct" "mode_a" "$BASELINE_MEM" "percent" "1"

    # Falco pod resources
    FALCO_CPU=$(kubectl top pods -n falco 2>/dev/null | grep falco | awk '{print $2}' | tr -d 'm' | head -1 || echo "0")
    FALCO_MEM=$(kubectl top pods -n falco 2>/dev/null | grep falco | awk '{print $3}' | tr -d 'Mi' | head -1 || echo "0")
    append_perf "falco_cpu_millicores" "mode_c" "$FALCO_CPU" "millicores" "1"
    append_perf "falco_memory_mib" "mode_c" "$FALCO_MEM" "MiB" "1"

    info "  Falco overhead: CPU=${FALCO_CPU}m, Memory=${FALCO_MEM}Mi"

    # Tetragon resources
    TETRAGON_CPU=$(kubectl top pods -n kube-system -l app.kubernetes.io/name=tetragon \
        2>/dev/null | awk 'NR>1{print $2}' | tr -d 'm' | head -1 || echo "0")
    TETRAGON_MEM=$(kubectl top pods -n kube-system -l app.kubernetes.io/name=tetragon \
        2>/dev/null | awk 'NR>1{print $3}' | tr -d 'Mi' | head -1 || echo "0")
    append_perf "tetragon_cpu_millicores" "mode_c" "$TETRAGON_CPU" "millicores" "1"
    append_perf "tetragon_memory_mib" "mode_c" "$TETRAGON_MEM" "MiB" "1"
    info "  Tetragon overhead: CPU=${TETRAGON_CPU}m, Memory=${TETRAGON_MEM}Mi"
}

# ══════════════════════════════════════════════════════════════════════════════
# GENERATE COMPARISON TABLE (Mode A vs B vs C)
# ══════════════════════════════════════════════════════════════════════════════
generate_comparison() {
    info "── Generating 3-Mode Comparison Table ──"

    python3 - <<'PYEOF'
import csv, statistics, json

rows = []
try:
    with open("evaluation/results/performance_results.csv") as f:
        for r in csv.DictReader(f):
            rows.append(r)
except FileNotFoundError:
    print("No metrics file found yet")
    exit()

# Group by metric and mode
by_metric_mode = {}
for r in rows:
    key = (r['metric'], r['mode'])
    if key not in by_metric_mode:
        by_metric_mode[key] = []
    try:
        by_metric_mode[key].append(float(r['value_ms']))
    except ValueError:
        pass

# Compute averages
avgs = {}
for (metric, mode), values in by_metric_mode.items():
    if values:
        avgs[(metric, mode)] = {
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'stdev': statistics.stdev(values) if len(values) > 1 else 0,
            'min': min(values),
            'max': max(values)
        }

# Write comparison CSV
metrics = set(m for (m, _) in avgs.keys())
with open("evaluation/results/comparison_results.csv", 'w') as f:
    f.write("metric,mode_a_mean,mode_b_mean,mode_c_mean,overhead_b_pct,overhead_c_pct\n")
    for metric in sorted(metrics):
        a = avgs.get((metric, 'mode_a'), {}).get('mean', 0)
        b = avgs.get((metric, 'mode_b'), {}).get('mean', 0)
        c = avgs.get((metric, 'mode_c'), {}).get('mean', 0)
        ob = ((b - a) / a * 100) if a > 0 else 0
        oc = ((c - a) / a * 100) if a > 0 else 0
        f.write(f"{metric},{a:.1f},{b:.1f},{c:.1f},{ob:.1f},{oc:.1f}\n")
        print(f"  {metric:40s} A={a:.0f} B={b:.0f} C={c:.0f} (C overhead: {oc:.1f}%)")

print(f"\nComparison table saved to: evaluation/results/comparison_results.csv")
PYEOF
}

# ── MAIN ──
main() {
    info "Starting 3-Mode Performance Metrics Collection"
    measure_build_overhead
    measure_signing_overhead
    measure_sbom_overhead
    measure_admission_latency
    measure_runtime_overhead
    generate_comparison
    info "All metrics saved to $RESULTS_DIR"
}

main "$@"
