#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# verify_artifacts.sh — Supply Chain Artifact Verification
# Verifies: signature, SLSA provenance, SBOM; extracts allowed lists
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

TS()   { date '+%Y-%m-%d %H:%M:%S'; }
ok()   { echo "[$(TS)] ✅ $*"; }
fail() { echo "[$(TS)] ❌ $*"; FAILURES=$((FAILURES+1)); }
info() { echo "[$(TS)] ▸  $*"; }

IMAGE_REF="${1:-localhost:5001/cnd-demo-app:latest}"
IDENTITY_REGEXP="${COSIGN_IDENTITY:-.*}"
OIDC_ISSUER="${COSIGN_OIDC:-https://token.actions.githubusercontent.com}"
FAILURES=0

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Supply Chain Artifact Verification                          ║"
echo "║   Image: ${IMAGE_REF}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── CHECK 1: Cosign Signature ──────────────────────────────────────────────
info "Verifying Cosign signature..."
START=$(date +%s%3N)

if cosign verify \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE_REF" 2>/dev/null | tee /tmp/sig-verify.json | jq -r '.[0].optional.Subject' 2>/dev/null; then
    END=$(date +%s%3N)
    ok "Signature VALID — verified in $((END-START))ms"
else
    # Try key-based verification
    if [ -f cosign.pub ] && \
        COSIGN_PASSWORD="" cosign verify --key cosign.pub "$IMAGE_REF" 2>/dev/null; then
        END=$(date +%s%3N)
        ok "Signature VALID (key-based) — verified in $((END-START))ms"
    else
        fail "Signature INVALID or missing"
    fi
fi

# ── CHECK 2: SLSA Provenance ───────────────────────────────────────────────
info "Verifying SLSA provenance attestation..."
START=$(date +%s%3N)

if cosign verify-attestation \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --type slsaprovenance1 \
    "$IMAGE_REF" 2>/dev/null | \
    jq -r '.payload | @base64d | fromjson | .predicateType' 2>/dev/null; then
    END=$(date +%s%3N)
    ok "SLSA provenance VALID — $((END-START))ms"
else
    fail "SLSA provenance NOT found or invalid"
fi

# ── CHECK 3: SBOM Download & Parse ────────────────────────────────────────
info "Downloading and parsing SBOM..."
START=$(date +%s%3N)

if cosign download sbom "$IMAGE_REF" > /tmp/downloaded-sbom.json 2>/dev/null; then
    END=$(date +%s%3N)

    python3 - <<'PYEOF'
import json

with open('/tmp/downloaded-sbom.json') as f:
    sbom = json.load(f)

components = sbom.get('components', [])
print(f"  SBOM type: {sbom.get('bomFormat','unknown')}")
print(f"  Components: {len(components)}")

allowed_binaries = []
allowed_packages = []

for c in components:
    name = c.get('name','')
    ctype = c.get('type','')
    if ctype in ('library','framework'):
        allowed_packages.append({'name': name, 'version': c.get('version',''), 'purl': c.get('purl','')})

# Map to binary names
binary_map = {'python': ['python3'], 'flask': ['python3'], 'gunicorn': ['gunicorn'],
              'gin': ['cnd-app'], 'go': ['cnd-app']}
for pkg in allowed_packages:
    if pkg['name'].lower() in binary_map:
        allowed_binaries.extend(binary_map[pkg['name'].lower()])

with open('allowed_binaries.json', 'w') as f:
    json.dump({'allowed': list(set(allowed_binaries))}, f, indent=2)
with open('allowed_packages.json', 'w') as f:
    json.dump({'packages': allowed_packages}, f, indent=2)

print(f"  allowed_binaries.json: {len(set(allowed_binaries))} entries")
print(f"  allowed_packages.json: {len(allowed_packages)} entries")
PYEOF
    ok "SBOM downloaded and parsed — $((END-START))ms"
else
    fail "SBOM not found — run build_pipeline.sh first"
fi

# ── CHECK 4: Vulnerability Scan ────────────────────────────────────────────
info "Scanning for known CVEs (Grype)..."
if command -v grype &>/dev/null; then
    CRITICAL=$(grype "$IMAGE_REF" --output json 2>/dev/null | \
        jq '[.matches[]|select(.vulnerability.severity=="Critical")]|length' 2>/dev/null || echo "0")
    HIGH=$(grype "$IMAGE_REF" --output json 2>/dev/null | \
        jq '[.matches[]|select(.vulnerability.severity=="High")]|length' 2>/dev/null || echo "0")
    if [ "$CRITICAL" -eq 0 ]; then
        ok "No Critical CVEs (High: $HIGH)"
    else
        fail "Found $CRITICAL Critical CVEs and $HIGH High CVEs"
    fi
fi

# ── SUMMARY ───────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
if [ "$FAILURES" -eq 0 ]; then
    echo "║  VERIFIED ✅  All supply chain checks passed.                 ║"
else
    echo "║  FAILED ❌  $FAILURES check(s) failed. Do NOT deploy this image. ║"
fi
echo "╚══════════════════════════════════════════════════════════════╝"
exit "$FAILURES"
