#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# validate_env.sh — CND Project Environment Validation
# Checks ALL required tools and cluster state. Exits 0 on success.
# Run BEFORE any other script.
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0

ok()   { echo -e "${GREEN}  ✅ $*${NC}"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}  ❌ $*${NC}"; FAIL=$((FAIL+1)); }
warn() { echo -e "${YELLOW}  ⚠️  $*${NC}"; WARN=$((WARN+1)); }

check_cmd() {
    local cmd="$1"; local min_ver="${2:-}"
    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$(${cmd} version 2>/dev/null | head -1 || ${cmd} --version 2>/dev/null | head -1 || echo "unknown")
        ok "$cmd found: $ver"
    else
        fail "$cmd NOT found — install it first"
    fi
}

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   CND Project — Environment Validation                       ║"
echo "║   Ubuntu 22.04 LTS required (kernel 5.15+ for eBPF)         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── OS Check ──
echo "── Operating System ──"
KERNEL=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL" | cut -d. -f2)
if [ "$KERNEL_MAJOR" -ge 5 ] && [ "$KERNEL_MINOR" -ge 15 ]; then
    ok "Kernel $KERNEL (≥5.15 required for eBPF)"
else
    fail "Kernel $KERNEL is too old — need ≥5.15 for Falco eBPF"
fi

OS_NAME=$(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
ok "OS: $OS_NAME"

# ── Container Runtime ──
echo ""
echo "── Container Runtime ──"
check_cmd docker
if docker info &>/dev/null; then
    ok "Docker daemon is running"
else
    fail "Docker daemon not running — run: sudo systemctl start docker"
fi

# ── Kubernetes Tools ──
echo ""
echo "── Kubernetes Tools ──"
check_cmd minikube
check_cmd kubectl
check_cmd helm

# Cluster check
if minikube status 2>/dev/null | grep -q "Running"; then
    ok "Minikube cluster is running"
    NODES=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
    ok "Cluster nodes: $NODES"
else
    warn "Minikube not running — start with: bash scripts/setup-cluster.sh"
fi

# ── Supply Chain Tools ──
echo ""
echo "── Supply Chain Security Tools ──"
check_cmd cosign
check_cmd syft
check_cmd grype

if command -v slsa-verifier &>/dev/null; then
    ok "slsa-verifier found"
else
    warn "slsa-verifier not found (optional for local build pipeline)"
fi

# ── Runtime Security Tools ──
echo ""
echo "── Runtime Security Tools ──"
if kubectl get pods -n falco --no-headers 2>/dev/null | grep -q Running; then
    ok "Falco is running in cluster"
else
    warn "Falco not deployed yet"
fi

if kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon --no-headers 2>/dev/null | grep -q Running; then
    ok "Tetragon is running"
else
    warn "Tetragon not deployed yet"
fi

# ── Admission Control ──
echo ""
echo "── Admission Control ──"
if kubectl get pods -n kyverno --no-headers 2>/dev/null | grep -q Running; then
    ok "Kyverno is running"
    POLICIES=$(kubectl get clusterpolicies --no-headers 2>/dev/null | wc -l)
    ok "ClusterPolicies active: $POLICIES"
else
    warn "Kyverno not deployed yet"
fi

# ── Monitoring ──
echo ""
echo "── Monitoring Stack ──"
if kubectl get pods -n monitoring --no-headers 2>/dev/null | grep -q prometheus; then
    ok "Prometheus is running"
else
    warn "Prometheus not deployed yet"
fi

if kubectl get pods -n monitoring --no-headers 2>/dev/null | grep -q grafana; then
    ok "Grafana is running"
else
    warn "Grafana not deployed yet"
fi

# ── Build Tools ──
echo ""
echo "── Build Tools ──"
check_cmd go
check_cmd git
check_cmd jq
check_cmd curl
check_cmd python3

# ── Registry ──
echo ""
echo "── Container Registry ──"
REGISTRY_ADDR="${LOCAL_REGISTRY:-localhost:5001}"
if curl -s "http://${REGISTRY_ADDR}/v2/" &>/dev/null; then
    ok "Local registry reachable at $REGISTRY_ADDR"
else
    warn "Local registry not reachable at $REGISTRY_ADDR — will use minikube registry"
fi

# ── Enrichment Service ──
echo ""
echo "── CND Enrichment Service ──"
if kubectl get pods -n cnd-demo -l app=enrichment-service --no-headers 2>/dev/null | grep -q Running; then
    ok "Provenance Enrichment Service is running"
else
    warn "Enrichment Service not deployed yet"
fi

# ── Summary ──
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Validation Summary                                          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  ✅ Passed:  $PASS checks"
echo "║  ❌ Failed:  $FAIL checks"
echo "║  ⚠️  Warnings: $WARN checks"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}Environment validation FAILED. Fix the errors above before proceeding.${NC}"
    exit 1
else
    echo -e "${GREEN}Environment validation PASSED. Ready to proceed.${NC}"
    exit 0
fi
