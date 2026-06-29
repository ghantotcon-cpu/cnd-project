#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# test_admission.sh — Kyverno Admission Control Tests
# Tests 3 cases: unsigned blocked, no-SBOM blocked, verified accepted
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

TS()    { date '+%Y-%m-%d %H:%M:%S'; }
pass()  { echo "[$(TS)] PASS ✅ $*"; PASSED=$((PASSED+1)); }
fail()  { echo "[$(TS)] FAIL ❌ $*"; FAILED=$((FAILED+1)); }
info()  { echo "[$(TS)] INFO ▸  $*"; }

NAMESPACE="cnd-demo"
VERIFIED_IMAGE="${VERIFIED_IMAGE:-localhost:5001/cnd-demo-app:latest}"
PASSED=0; FAILED=0

cleanup() {
    kubectl delete pod -n "$NAMESPACE" \
        -l test-admission=true --ignore-not-found=true &>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Kyverno Admission Control Tests"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ── TEST 1: Unsigned image MUST be rejected ────────────────────────────────
info "TEST 1: Unsigned image from untrusted registry (must be REJECTED)"
START=$(date +%s%3N)

OUTPUT=$(kubectl apply -f - 2>&1 <<EOF || true
apiVersion: v1
kind: Pod
metadata:
  name: test-unsigned-$(date +%s)
  namespace: ${NAMESPACE}
  labels:
    test-admission: "true"
spec:
  containers:
    - name: test
      image: docker.io/library/nginx:latest
      resources:
        requests: {cpu: "10m", memory: "16Mi"}
        limits:   {cpu: "100m", memory: "64Mi"}
  restartPolicy: Never
EOF
)
END=$(date +%s%3N)

if echo "$OUTPUT" | grep -qiE "denied|blocked|Error.*admission|webhook.*denied"; then
    pass "TEST 1: Unsigned image REJECTED by Kyverno in $((END-START))ms"
    echo "       → Kyverno output: $(echo "$OUTPUT" | head -2)"
else
    fail "TEST 1: Unsigned image was NOT rejected (policy failure)"
    echo "       → kubectl output: $OUTPUT"
fi

sleep 3

# ── TEST 2: Signed image without SBOM MUST be rejected ────────────────────
info "TEST 2: Signed image without SBOM attestation (must be REJECTED)"
info "  (Simulated — using image with incomplete attestations)"
START=$(date +%s%3N)

OUTPUT=$(kubectl apply -f - 2>&1 <<EOF || true
apiVersion: v1
kind: Pod
metadata:
  name: test-no-sbom-$(date +%s)
  namespace: ${NAMESPACE}
  labels:
    test-admission: "true"
spec:
  containers:
    - name: test
      image: ghcr.io/sigstore/cosign:v2.0.0
      resources:
        requests: {cpu: "10m", memory: "16Mi"}
        limits:   {cpu: "100m", memory: "64Mi"}
  restartPolicy: Never
EOF
)
END=$(date +%s%3N)

if echo "$OUTPUT" | grep -qiE "denied|blocked|Error|sbom|attestation"; then
    pass "TEST 2: Image without SBOM REJECTED in $((END-START))ms"
else
    fail "TEST 2: Image without SBOM was NOT rejected"
    echo "       → kubectl output: $OUTPUT"
fi

sleep 3

# ── TEST 3: Fully verified image MUST be accepted ─────────────────────────
info "TEST 3: Fully verified image (signature + SBOM + SLSA) must be ACCEPTED"
START=$(date +%s%3N)

OUTPUT=$(kubectl apply -f - 2>&1 <<EOF || true
apiVersion: v1
kind: Pod
metadata:
  name: test-verified-$(date +%s)
  namespace: ${NAMESPACE}
  labels:
    test-admission: "true"
    app: verified-test
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: test
      image: ${VERIFIED_IMAGE}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      resources:
        requests: {cpu: "50m", memory: "64Mi"}
        limits:   {cpu: "200m", memory: "128Mi"}
  restartPolicy: Never
EOF
)
END=$(date +%s%3N)

if echo "$OUTPUT" | grep -qiE "created|configured|unchanged"; then
    pass "TEST 3: Verified image ACCEPTED in $((END-START))ms"
else
    fail "TEST 3: Verified image was unexpectedly REJECTED"
    echo "       → kubectl output: $OUTPUT"
fi

# ── SUMMARY ───────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Admission Control Test Results                               ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Passed: ${PASSED}/3 tests"
echo "║  Failed: ${FAILED}/3 tests"
if [ "$FAILED" -eq 0 ]; then
    echo "║  Status: ✅ All admission control tests PASSED"
else
    echo "║  Status: ❌ ${FAILED} test(s) FAILED — check Kyverno policies"
fi
echo "╚══════════════════════════════════════════════════════════════╝"
exit "$FAILED"
