# CND Project — Supply Chain Security Framework

**Strengthening Cloud Software Supply Chain Security through the Integration of SLSA, Sigstore, and SBOM with Continuous Runtime Verification**

> Bachelor's Graduation Project  
> Computer Network Engineering and Distributed Systems  
> Taiz University, Faculty of Engineering & IT  
> Supervised by: Dr. Raad Al Selwi

---

## Framework Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CI/CD PIPELINE (GitHub Actions)               │
│                                                                   │
│  Source Code → Build → Sign (Cosign) → SBOM (Syft) → SLSA     │
│                  ↓          ↓              ↓           ↓         │
│              Docker      Sigstore      CycloneDX    Provenance   │
│              Image       Rekor Log     SBOM JSON    Attestation  │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                    ┌───────────▼────────────┐
                    │   ADMISSION CONTROL     │
                    │   (Kyverno Policies)    │
                    │                         │
                    │  ✓ Signature check      │
                    │  ✓ SBOM attestation     │
                    │  ✓ SLSA provenance      │
                    └───────────┬────────────┘
                                │ (BLOCKED if unsigned)
                    ┌───────────▼────────────┐
                    │   KUBERNETES CLUSTER   │
                    │   (Kind / Production)  │
                    │                         │
                    │  ┌─────────────────┐   │
                    │  │  cnd-demo-app   │   │
                    │  │  (Flask/Python) │   │
                    │  └────────┬────────┘   │
                    │           │            │
                    │  ┌────────▼────────┐   │
                    │  │  Falco (eBPF)   │   │
                    │  │  Runtime Rules  │   │
                    │  │  CND-SC-001..8  │   │
                    │  └─────────────────┘   │
                    └────────────────────────┘
```

## Repository Structure

```
cnd-project/
├── app/                          # Demo microservice (Flask/Python)
│   ├── Dockerfile               # Non-root, read-only FS, HEALTHCHECK
│   ├── main.py                  # Flask application
│   └── requirements.txt
│
├── .github/workflows/
│   ├── build-sign-sbom.yml      # Main pipeline: Build → Sign → SBOM → SLSA
│   └── verify-and-deploy.yml    # Supply chain verification workflow
│
├── kubernetes/
│   ├── base/
│   │   ├── namespace.yaml       # cnd-demo namespace with security labels
│   │   └── deployment.yaml      # Hardened pod spec (non-root, read-only FS)
│   ├── kyverno/
│   │   └── verify-images-policy.yaml  # 3 policies: signature + SBOM + SLSA
│   ├── falco/
│   │   ├── custom-rules.yaml    # 8 custom Falco rules (CND-SC-001..008)
│   │   └── falco-values.yaml    # Helm values (eBPF driver)
│   └── monitoring/
│       └── falco-alerts-dashboard.yaml
│
├── scripts/
│   ├── setup-cluster.sh         # One-command environment setup
│   ├── attack-scenarios.sh      # 4 attack simulations for evaluation
│   ├── collect-metrics.sh       # Performance overhead measurement
│   └── verify-deployment.sh     # Manual supply chain verification
│
└── evaluation/
    └── metrics-template.md      # Chapter 4 data collection template
```

## Quick Start (Ubuntu VM)

### 1. Prerequisites

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### 2. Clone & Setup

```bash
git clone https://github.com/ghantotcon-cpu/cnd-project.git
cd cnd-project

# Run the full setup (cluster + Kyverno + Falco + app)
chmod +x scripts/*.sh
bash scripts/setup-cluster.sh
```

### 3. Verify Supply Chain

```bash
# Verify a built image (run after GitHub Actions pipeline)
bash scripts/verify-deployment.sh ghcr.io/ghantotcon-cpu/cnd-project/cnd-demo-app:latest
```

### 4. Run Attack Simulations (Chapter 4 Data)

```bash
bash scripts/attack-scenarios.sh
# Results saved to: evaluation/results/attack-report-<timestamp>.json
```

### 5. Collect Performance Metrics (Chapter 4 Data)

```bash
bash scripts/collect-metrics.sh
# Results saved to: evaluation/results/performance-metrics-<timestamp>.json
```

---

## Attack Scenarios Tested

| # | Scenario | Attack Type | Detection Layer | Expected Result |
|---|----------|-------------|-----------------|-----------------|
| S1 | Unsigned image deployment | Image tampering | Kyverno (admission) | **BLOCKED** before running |
| S2 | Shell spawned in container | Runtime anomaly | Falco CND-SC-002 | **DETECTED** in <5s |
| S3 | pip install in container | Malicious dependency | Falco CND-SC-003 | **DETECTED** in <5s |
| S4 | curl to external server | Network exfiltration | Falco CND-SC-005 | **DETECTED** in <5s |

---

## Research Questions Addressed

1. **RQ1** — Detection accuracy: Measured via `attack-scenarios.sh`
2. **RQ2** — CI/CD overhead: Measured via GitHub Actions pipeline metrics
3. **RQ3** — Runtime detection reduction: Measured via Falco alert analysis
4. **RQ4** — Attack type vs detection accuracy: Cross-scenario comparison
5. **RQ5** — Practical barriers: Documented in Chapter 5

---

## Tools & Versions

| Tool | Version | Purpose |
|------|---------|---------|
| Kubernetes (Kind) | 1.30 | Cluster orchestration |
| Kyverno | 1.12.6 | Admission control (supply chain policies) |
| Falco | 4.3.0 | Runtime anomaly detection (eBPF) |
| Cosign | 2.2.4 | Image signing (Sigstore keyless) |
| Syft | latest | SBOM generation (CycloneDX/SPDX) |
| Grype | latest | Vulnerability scanning |
| SLSA Generator | v2.0.0 | SLSA Level 3 provenance |
