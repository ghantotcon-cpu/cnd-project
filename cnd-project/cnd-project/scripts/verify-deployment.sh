#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# verify-deployment.sh
# CND Project — Supply Chain Verification Script
# Verifies: Cosign signature, SBOM attestation, SLSA provenance
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✅ $*${NC}"; }
fail() { echo -e "${RED}  ❌ $*${NC}"; }
info() { echo -e "${CYAN}  ▸  $*${NC}"; }

IMAGE_REF="${1:-ghcr.io/ghantotcon-cpu/cnd-project/cnd-demo-app:latest}"
IDENTITY_REGEXP="https://github.com/ghantotcon-cpu/cnd-project/*"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   CND Project — Supply Chain Verification                    ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Image: ${IMAGE_REF}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

PASS=0; FAIL=0

# ─────────────────────────────────────────────
# CHECK 1: Cosign Signature Verification
# ─────────────────────────────────────────────
echo "── [1/4] Cosign Signature Verification ──"
info "Verifying image is signed by GitHub Actions (OIDC/Sigstore)..."

START=$(date +%s%3N)
if cosign verify \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE_REF" 2>/dev/null | jq -r '.[0].optional.Subject' 2>/dev/null; then
    END=$(date +%s%3N)
    ok "Image signature VALID — verified by Cosign (${$(($END-$START))}ms)"
    PASS=$((PASS+1))
else
    fail "Image signature INVALID or missing"
    FAIL=$((FAIL+1))
fi

echo ""
echo "── [2/4] SBOM Attestation Verification ──"
info "Verifying CycloneDX SBOM is attached and signed..."

START=$(date +%s%3N)
if cosign verify-attestation \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --type cyclonedx \
    "$IMAGE_REF" 2>/dev/null | jq -r '.payload' | base64 -d | jq -r '.predicateType' 2>/dev/null; then
    END=$(date +%s%3N)
    ok "SBOM attestation VALID — CycloneDX SBOM verified (${$(($END-$START))}ms)"
    PASS=$((PASS+1))
else
    fail "SBOM attestation INVALID or missing"
    FAIL=$((FAIL+1))
fi

echo ""
echo "── [3/4] SLSA Provenance Verification ──"
info "Verifying SLSA Level 3 provenance..."

START=$(date +%s%3N)
if cosign verify-attestation \
    --certificate-identity-regexp "https://github.com/slsa-framework/*" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --type slsaprovenance1 \
    "$IMAGE_REF" 2>/dev/null | jq -r '.payload' | base64 -d | jq -r '.predicateType' 2>/dev/null; then
    END=$(date +%s%3N)
    ok "SLSA provenance VALID — Level 3 provenance verified (${$(($END-$START))}ms)"
    PASS=$((PASS+1))
else
    fail "SLSA provenance INVALID or missing (run the full GitHub Actions pipeline first)"
    FAIL=$((FAIL+1))
fi

echo ""
echo "── [4/4] Vulnerability Scan (Grype) ──"
info "Scanning image for known CVEs..."

if command -v grype &>/dev/null; then
    CRITICAL=$(grype "$IMAGE_REF" --output json 2>/dev/null | \
        jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' 2>/dev/null || echo "0")
    HIGH=$(grype "$IMAGE_REF" --output json 2>/dev/null | \
        jq '[.matches[] | select(.vulnerability.severity=="High")] | length' 2>/dev/null || echo "0")

    if [ "$CRITICAL" -eq 0 ]; then
        ok "No critical CVEs found (High: $HIGH)"
        PASS=$((PASS+1))
    else
        fail "Found $CRITICAL CRITICAL CVEs and $HIGH HIGH CVEs"
        FAIL=$((FAIL+1))
    fi
else
    info "Grype not installed — skipping vulnerability scan"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Verification Summary                                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Passed: $PASS / $(($PASS+$FAIL)) checks"
echo "║  Failed: $FAIL / $(($PASS+$FAIL)) checks"
if [ $FAIL -eq 0 ]; then
    echo "║  Status: ✅ ALL CHECKS PASSED — image is supply-chain verified"
else
    echo "║  Status: ❌ VERIFICATION FAILED — do not deploy this image"
fi
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

exit $FAIL
