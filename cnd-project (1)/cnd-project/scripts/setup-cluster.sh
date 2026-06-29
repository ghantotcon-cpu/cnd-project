#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# setup-cluster.sh — CND Project Full Environment Setup
# Ubuntu 22.04 LTS + Minikube (2 nodes, containerd, Calico CNI)
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
TS() { date '+%Y-%m-%d %H:%M:%S'; }
info()  { echo -e "[$(TS)] ${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "[$(TS)] ${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "[$(TS)] ${RED}[ERROR]${NC} $*"; exit 1; }

KYVERNO_VERSION="v1.12.6"
FALCO_VERSION="4.3.0"
TETRAGON_VERSION="1.1.0"

# ── 1. Install system tools ──
install_system_tools() {
    info "Installing system dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        curl wget git jq python3 python3-pip \
        apt-transport-https ca-certificates \
        gnupg lsb-release openssl

    # Go 1.21
    if ! command -v go &>/dev/null || [[ "$(go version)" != *"go1.21"* ]]; then
        info "Installing Go 1.21..."
        curl -sSL https://go.dev/dl/go1.21.13.linux-amd64.tar.gz -o /tmp/go.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
        export PATH=$PATH:/usr/local/go/bin
    fi
    info "Go: $(go version)"
}

# ── 2. Install Cosign ──
install_cosign() {
    if command -v cosign &>/dev/null; then
        info "Cosign already installed"; return
    fi
    info "Installing Cosign v2.2.4..."
    curl -sSfL https://github.com/sigstore/cosign/releases/download/v2.2.4/cosign-linux-amd64 \
        -o /tmp/cosign && chmod +x /tmp/cosign && sudo mv /tmp/cosign /usr/local/bin/cosign
    info "Cosign: $(cosign version 2>/dev/null | head -1)"
}

# ── 3. Install Syft + Grype ──
install_sbom_tools() {
    if ! command -v syft &>/dev/null; then
        info "Installing Syft..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
    fi
    if ! command -v grype &>/dev/null; then
        info "Installing Grype..."
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
    fi
    info "Syft: $(syft version | head -1)"
    info "Grype: $(grype version | head -1)"
}

# ── 4. Install kubectl + helm ──
install_k8s_tools() {
    if ! command -v kubectl &>/dev/null; then
        info "Installing kubectl..."
        curl -sSLO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        chmod +x kubectl && sudo mv kubectl /usr/local/bin/
    fi
    if ! command -v helm &>/dev/null; then
        info "Installing Helm..."
        curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    fi
    if ! command -v minikube &>/dev/null; then
        info "Installing Minikube..."
        curl -sSLO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
        chmod +x minikube-linux-amd64 && sudo mv minikube-linux-amd64 /usr/local/bin/minikube
    fi
}

# ── 5. Start Minikube (2 nodes, containerd, Calico) ──
start_minikube() {
    if minikube status 2>/dev/null | grep -q "Running"; then
        warn "Minikube already running. Skipping."; return
    fi
    info "Starting Minikube (2 nodes, 8GB RAM, containerd, Calico CNI)..."
    minikube start \
        --nodes=2 \
        --memory=8192 \
        --cpus=4 \
        --driver=docker \
        --container-runtime=containerd \
        --cni=calico \
        --kubernetes-version=v1.30.0 \
        --profile=cnd-cluster \
        --addons=metrics-server,registry

    kubectl cluster-info
    info "Cluster nodes:"
    kubectl get nodes -o wide
}

# ── 6. Install Kyverno ──
install_kyverno() {
    if kubectl get ns kyverno &>/dev/null; then
        warn "Kyverno already installed."; return
    fi
    info "Installing Kyverno ${KYVERNO_VERSION}..."
    helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
    helm install kyverno kyverno/kyverno \
        --namespace kyverno --create-namespace \
        --version "${KYVERNO_VERSION}" \
        --set admissionController.replicas=1 \
        --wait --timeout=5m
    kubectl apply -f kubernetes/kyverno/verify-images-policy.yaml
    info "Kyverno installed ✓"
}

# ── 7. Install Falco (eBPF) ──
install_falco() {
    if kubectl get ns falco &>/dev/null; then
        warn "Falco already installed."; return
    fi
    info "Installing Falco ${FALCO_VERSION} (modern eBPF)..."
    helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update
    helm install falco falcosecurity/falco \
        --namespace falco --create-namespace \
        --version "${FALCO_VERSION}" \
        -f kubernetes/falco/falco-values.yaml \
        --wait --timeout=5m

    kubectl create configmap cnd-falco-rules \
        --from-file=cnd-rules.yaml=kubernetes/falco/custom-rules.yaml \
        -n falco --dry-run=client -o yaml | kubectl apply -f -
    info "Falco installed ✓"
}

# ── 8. Install Tetragon ──
install_tetragon() {
    if kubectl get ns kube-system &>/dev/null && \
       kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon --no-headers 2>/dev/null | grep -q Running; then
        warn "Tetragon already running."; return
    fi
    info "Installing Tetragon ${TETRAGON_VERSION}..."
    helm repo add cilium https://helm.cilium.io --force-update
    helm install tetragon cilium/tetragon \
        --namespace kube-system \
        --version "${TETRAGON_VERSION}" \
        --wait --timeout=5m

    kubectl apply -f kubernetes/tetragon/tracing-policy.yaml
    info "Tetragon installed ✓"
}

# ── 9. Install Prometheus + Grafana ──
install_monitoring() {
    if kubectl get ns monitoring &>/dev/null; then
        warn "Monitoring stack already installed."; return
    fi
    info "Installing Prometheus + Grafana..."
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update
    helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
        --namespace monitoring --create-namespace \
        --set prometheus.prometheusSpec.retention=24h \
        --set grafana.adminPassword=cnd-research-2026 \
        --wait --timeout=10m
    info "Monitoring installed — Grafana password: cnd-research-2026 ✓"
}

# ── 10. Deploy Enrichment + Feedback Services ──
deploy_cnd_services() {
    info "Deploying Provenance Enrichment Service..."
    kubectl apply -f kubernetes/base/namespace.yaml
    kubectl apply -f enrichment-service/k8s/
    kubectl apply -f feedback-service/k8s/
    kubectl apply -f kubernetes/base/deployment.yaml
    info "CND services deployed ✓"
}

# ── Summary ──
print_summary() {
    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  CND Project — Environment Setup Complete"
    echo "══════════════════════════════════════════════════════════════"
    kubectl get pods -A | grep -E "kyverno|falco|tetragon|cnd|monitoring" | head -20
    echo ""
    echo "  Next steps:"
    echo "    bash scripts/validate_env.sh           # Validate environment"
    echo "    bash scripts/build_pipeline.sh         # Build + Sign + SBOM"
    echo "    bash scripts/simulate_attacks.sh       # Run attack simulations"
    echo "    bash scripts/collect_metrics.sh        # Collect research metrics"
    echo ""
    GRAFANA_PORT=$(kubectl get svc -n monitoring kube-prometheus-stack-grafana \
        -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "3000")
    echo "  Grafana: http://$(minikube ip):${GRAFANA_PORT} (admin / cnd-research-2026)"
}

main() {
    info "Starting CND Project full environment setup..."
    install_system_tools
    install_cosign
    install_sbom_tools
    install_k8s_tools
    start_minikube
    install_kyverno
    install_falco
    install_tetragon
    install_monitoring
    deploy_cnd_services
    print_summary
}

main "$@"
