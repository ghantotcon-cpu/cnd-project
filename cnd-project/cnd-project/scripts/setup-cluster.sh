#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# setup-cluster.sh
# CND Project — Full Environment Setup Script
# Sets up Kind cluster + Kyverno + Falco + Cosign in Ubuntu/VMware environment
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

CLUSTER_NAME="cnd-cluster"
KYVERNO_VERSION="v1.12.6"
FALCO_VERSION="4.3.0"

# ─────────────────────────────────────────────
# 1. Prerequisites Check
# ─────────────────────────────────────────────
check_prerequisites() {
    info "Checking prerequisites..."
    local missing=()
    for tool in docker kubectl kind helm curl jq; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing tools: ${missing[*]}. Please install them first."
    fi
    info "All prerequisites found ✓"
}

# ─────────────────────────────────────────────
# 2. Install Cosign
# ─────────────────────────────────────────────
install_cosign() {
    if command -v cosign &>/dev/null; then
        info "Cosign already installed: $(cosign version 2>/dev/null | head -1)"
        return
    fi

    info "Installing Cosign..."
    COSIGN_VERSION="v2.2.4"
    curl -sSfL \
        "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
        -o /tmp/cosign
    chmod +x /tmp/cosign
    sudo mv /tmp/cosign /usr/local/bin/cosign
    info "Cosign installed: $(cosign version 2>/dev/null | head -1) ✓"
}

# ─────────────────────────────────────────────
# 3. Install Syft (SBOM Generator)
# ─────────────────────────────────────────────
install_syft() {
    if command -v syft &>/dev/null; then
        info "Syft already installed: $(syft version | head -1)"
        return
    fi

    info "Installing Syft (SBOM generator)..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
        sudo sh -s -- -b /usr/local/bin
    info "Syft installed: $(syft version | head -1) ✓"
}

# ─────────────────────────────────────────────
# 4. Install Grype (Vulnerability Scanner)
# ─────────────────────────────────────────────
install_grype() {
    if command -v grype &>/dev/null; then
        info "Grype already installed"
        return
    fi

    info "Installing Grype (vulnerability scanner)..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
        sudo sh -s -- -b /usr/local/bin
    info "Grype installed ✓"
}

# ─────────────────────────────────────────────
# 5. Create Kind Cluster
# ─────────────────────────────────────────────
create_cluster() {
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        warn "Cluster '${CLUSTER_NAME}' already exists. Skipping creation."
        return
    fi

    info "Creating Kind cluster: ${CLUSTER_NAME}..."
    cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: 30080
        protocol: TCP
  - role: worker
  - role: worker
EOF
    kubectl cluster-info --context "kind-${CLUSTER_NAME}"
    info "Kind cluster created ✓"
}

# ─────────────────────────────────────────────
# 6. Install Kyverno (Admission Controller)
# ─────────────────────────────────────────────
install_kyverno() {
    if kubectl get ns kyverno &>/dev/null; then
        warn "Kyverno namespace already exists. Skipping."
        return
    fi

    info "Installing Kyverno ${KYVERNO_VERSION}..."
    helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
    helm repo update

    # Record admission latency baseline before Kyverno
    BEFORE=$(date +%s%3N)
    helm install kyverno kyverno/kyverno \
        --namespace kyverno \
        --create-namespace \
        --version "${KYVERNO_VERSION}" \
        --set admissionController.replicas=1 \
        --set backgroundController.replicas=1 \
        --set cleanupController.replicas=1 \
        --set reportsController.replicas=1 \
        --wait --timeout=5m
    AFTER=$(date +%s%3N)

    info "Kyverno installed in $(($AFTER - $BEFORE))ms ✓"

    # Apply CND policies
    info "Applying supply chain verification policies..."
    kubectl apply -f kubernetes/kyverno/verify-images-policy.yaml
    info "Kyverno policies applied ✓"
}

# ─────────────────────────────────────────────
# 7. Install Falco (Runtime Security)
# ─────────────────────────────────────────────
install_falco() {
    if kubectl get ns falco &>/dev/null; then
        warn "Falco namespace already exists. Skipping."
        return
    fi

    info "Installing Falco ${FALCO_VERSION} (eBPF runtime monitoring)..."
    helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update
    helm repo update

    helm install falco falcosecurity/falco \
        --namespace falco \
        --create-namespace \
        --version "${FALCO_VERSION}" \
        -f kubernetes/falco/falco-values.yaml \
        --wait --timeout=5m

    # Apply custom CND rules
    kubectl create configmap cnd-falco-rules \
        --from-file=cnd-rules.yaml=kubernetes/falco/custom-rules.yaml \
        -n falco --dry-run=client -o yaml | kubectl apply -f -

    info "Falco installed with custom CND rules ✓"
}

# ─────────────────────────────────────────────
# 8. Deploy the Application
# ─────────────────────────────────────────────
deploy_application() {
    info "Deploying cnd-demo-app..."
    kubectl apply -f kubernetes/base/namespace.yaml
    kubectl apply -f kubernetes/base/deployment.yaml
    kubectl wait --for=condition=Available deployment/cnd-demo-app \
        -n cnd-demo --timeout=120s
    info "Application deployed ✓"
}

# ─────────────────────────────────────────────
# 9. Print Summary
# ─────────────────────────────────────────────
print_summary() {
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  CND Project — Environment Setup Complete"
    echo "═══════════════════════════════════════════════════"
    echo ""
    kubectl get pods -A | grep -E "kyverno|falco|cnd-demo"
    echo ""
    echo "  Cluster:   ${CLUSTER_NAME}"
    echo "  Kyverno:   $(kubectl get pods -n kyverno --no-headers 2>/dev/null | wc -l) pods"
    echo "  Falco:     $(kubectl get pods -n falco --no-headers 2>/dev/null | wc -l) pods"
    echo "  App:       $(kubectl get pods -n cnd-demo --no-headers 2>/dev/null | wc -l) pods"
    echo ""
    echo "  Next steps:"
    echo "    bash scripts/attack-scenarios.sh        # Run attack simulations"
    echo "    bash scripts/collect-metrics.sh         # Collect research metrics"
    echo "    bash scripts/verify-deployment.sh       # Verify signatures & SBOM"
    echo ""
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
main() {
    info "Starting CND Project environment setup..."
    check_prerequisites
    install_cosign
    install_syft
    install_grype
    create_cluster
    install_kyverno
    install_falco
    deploy_application
    print_summary
}

main "$@"
