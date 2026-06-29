# CND Project — Integrated Supply Chain Security Framework

**Strengthening Cloud Software Supply Chain Security through the Integration of SLSA, Sigstore, and SBOM with Continuous Runtime Verification**

> Bachelor's Graduation Project | Computer Network Engineering and Distributed Systems  
> Taiz University, Faculty of Engineering & IT | Supervised by: Dr. Raad Al Selwi

---

## Core Innovation: Provenance Enrichment Service

The key contribution of this project is the **bridge between build-time and runtime security**:

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1: BUILD TIME (GitHub Actions)                                │
│  Go App → Docker Build → Cosign Sign → Syft SBOM → SLSA Provenance │
└───────────────────┬─────────────────────────────────────────────────┘
                    │ signed image + SBOM + SLSA attestations
┌───────────────────▼─────────────────────────────────────────────────┐
│  PHASE 2: ADMISSION (Kyverno)                                        │
│  Verify signature ✓ | Verify SBOM ✓ | Verify SLSA ✓ → DEPLOY      │
└───────────────────┬─────────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────────┐
│  PHASE 3: PROVENANCE ENRICHMENT SERVICE ← CORE INNOVATION           │
│  • Watches new Pod deployments via Kubernetes Watch API              │
│  • Fetches SBOM → extracts allowed binaries/packages/ports          │
│  • Fetches SLSA provenance → extracts builder identity, SLSA level  │
│  • Generates DYNAMIC Falco rules from SBOM inventory                │
│  • Stores enrichment data in ConfigMap provenance-<hash>            │
│  • Triggers Falco rules reload                                       │
└───────────────────┬─────────────────────────────────────────────────┘
                    │ SBOM-enriched rules
┌───────────────────▼─────────────────────────────────────────────────┐
│  PHASE 3: RUNTIME (Falco eBPF + Tetragon)                           │
│  Rules derived from SBOM → detect SBOM violations at runtime        │
└───────────────────┬─────────────────────────────────────────────────┘
                    │ runtime alerts
┌───────────────────▼─────────────────────────────────────────────────┐
│  PHASE 4: FEEDBACK LOOP (Feedback Service)                           │
│  • Tags suspicious images in registry via Cosign annotation         │
│  • Creates Kubernetes Events with provenance context                 │
│  • Exposes /alerts API with full incident history                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
cnd-project/
├── app/                          # Go microservice (gin + logrus + uuid)
│   ├── main.go                  # /health, /version, /api/data endpoints
│   ├── go.mod / go.sum
│   └── Dockerfile               # Multi-stage, distroless runtime
│
├── enrichment-service/          # ★ CORE INNOVATION — Provenance Bridge
│   ├── main.py                  # Pod watcher + SBOM parser + Falco rule generator
│   ├── Dockerfile
│   ├── requirements.txt
│   └── k8s/deployment.yaml      # Deployment + RBAC + Service
│
├── feedback-service/            # Runtime → Build feedback loop
│   ├── main.py                  # Falco webhook receiver + remediation suggester
│   ├── Dockerfile
│   └── k8s/deployment.yaml
│
├── .github/workflows/
│   ├── build-sign-sbom.yml      # CI/CD: Build → Sign → SBOM → SLSA → Scan
│   └── verify-and-deploy.yml    # Supply chain verification gate
│
├── kubernetes/
│   ├── base/                    # Namespace + Deployment + ServiceAccount
│   ├── kyverno/                 # 3 ClusterPolicies (signature + SBOM + SLSA)
│   ├── falco/                   # SBOM-enriched custom rules + Helm values
│   ├── tetragon/                # TracingPolicy (eBPF LSM enforcement)
│   └── monitoring/              # Prometheus + Grafana
│
├── scripts/
│   ├── validate_env.sh          # Environment validation (run first!)
│   ├── setup-cluster.sh         # Full cluster setup (Minikube + all tools)
│   ├── build_pipeline.sh        # SLSA L3 build: build+sign+SBOM+provenance
│   ├── verify_artifacts.sh      # Verify: signature + SLSA + SBOM
│   ├── test_admission.sh        # 3 Kyverno admission tests (PASS/FAIL)
│   ├── simulate_attacks.sh      # 3 scenarios × 10 runs → detection_results.csv
│   ├── collect_metrics.sh       # 3-mode overhead comparison → CSV
│   └── watch-falco.sh           # Live Falco alert monitor
│
└── evaluation/
    ├── analyze_results.py       # Stats + charts + t-test + LaTeX table
    └── results/                 # CSV and JSON outputs
```

---

## Quick Start (Ubuntu 22.04 LTS — kernel ≥5.15 required for eBPF)

```bash
git clone https://github.com/ghantotcon-cpu/cnd-project.git
cd cnd-project
tar -xzf cnd-project.tar.gz && cd cnd-project

# Step 0: Validate environment
bash scripts/validate_env.sh

# Step 1: Full cluster setup (Minikube + Kyverno + Falco + Tetragon + Prometheus)
bash scripts/setup-cluster.sh

# Step 2: Build SLSA Level 3 pipeline
bash scripts/build_pipeline.sh
# → produces: sbom.cyclonedx.json, provenance.json, allowed_binaries.json

# Step 3: Verify all artifacts
bash scripts/verify_artifacts.sh localhost:5001/cnd-demo-app:latest

# Step 4: Test admission control
bash scripts/test_admission.sh

# Step 5: Run attack simulation (10 runs × 3 scenarios)
bash scripts/simulate_attacks.sh
# → produces: evaluation/results/detection_results.csv

# Step 6: Collect performance metrics (3-mode comparison)
bash scripts/collect_metrics.sh
# → produces: evaluation/results/performance_results.csv

# Step 7: Generate charts + LaTeX tables
pip3 install matplotlib scipy numpy
python3 evaluation/analyze_results.py
# → produces: evaluation/results/charts/*.png, table_detection.tex
```

---

## Evaluation Metrics (Chapter 4)

| Metric | Tool | Output |
|--------|------|--------|
| True Positive Rate (TPR) | simulate_attacks.sh | detection_results.csv |
| False Positive Rate (FPR) | simulate_attacks.sh | false_positive_results.csv |
| Detection Latency (ms) | simulate_attacks.sh | detection_results.csv |
| Build time overhead | collect_metrics.sh | performance_results.csv |
| Signing overhead | collect_metrics.sh | performance_results.csv |
| Admission latency | collect_metrics.sh | performance_results.csv |
| CPU/Memory (Falco+Tetragon) | collect_metrics.sh | performance_results.csv |
| Mode A vs B vs C comparison | collect_metrics.sh | comparison_results.csv |
| Statistical significance | analyze_results.py | analysis_summary.json |
| Charts | analyze_results.py | results/charts/*.png |
| LaTeX tables | analyze_results.py | table_detection.tex |

---

## Attack Scenarios

| # | Scenario | Method | Expected Detection |
|---|----------|--------|-------------------|
| S1 | Image tampering | Deploy unsigned image | Kyverno blocks at admission |
| S2 | Runtime shell | kubectl exec bash into container | Falco SBOM rule: shell not in SBOM |
| S3 | Malicious dependency | pip install inside container | Falco SBOM rule: package manager not in SBOM |

**False Positive Test**: 10 clean deployments — zero alerts expected

---

## Tool Versions

| Tool | Version | Role |
|------|---------|------|
| Minikube | latest | 2-node cluster (containerd + Calico) |
| Kyverno | 1.12.6 | Admission control (3 policies) |
| Falco | 4.3.0 | Runtime monitoring (eBPF, SBOM-enriched rules) |
| Tetragon | 1.1.0 | eBPF LSM enforcement + process tracing |
| Cosign | 2.2.4 | Keyless signing (Sigstore/Rekor) |
| Syft | latest | SBOM generation (CycloneDX + SPDX) |
| Grype | latest | CVE scanning |
| Prometheus + Grafana | latest | Performance metrics |
