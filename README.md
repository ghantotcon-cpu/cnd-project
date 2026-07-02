# CND Project — Cloud-Native Supply Chain Security Framework

**Strengthening Cloud Software Supply Chain Security through the Integration of SLSA, Sigstore, and SBOM with Continuous Runtime Verification**

> Bachelor's Graduation Project | Computer Network Engineering  
> Taiz University, Faculty of Engineering & IT | Supervised by: Dr. Raad Al Selwi

---

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1: BUILD TIME  (GitHub Actions — automated on every push)    │
│  Go App → Docker Build (hermetic) → SLSA L3 Provenance              │
│         → Syft SBOM (CycloneDX + SPDX) → Grype CVE scan            │
│         → Cosign keyless sign → Rekor transparency log              │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ signed image + SBOM attestation + SLSA provenance
┌───────────────────────────▼─────────────────────────────────────────┐
│  PHASE 2: ADMISSION  (Kyverno — Kubernetes admission webhook)        │
│  Verify Cosign signature ✓ | Verify SBOM attestation ✓              │
│  Verify SLSA provenance ✓  | Registry policy ✓  →  DEPLOY          │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│  PHASE 3: RUNTIME  (Falco 0.40.0 — eBPF modern_ebpf probe)         │
│  8 custom CND rules monitor syscalls in real-time                    │
│  Cross-reference with SBOM declared components                       │
│  Alert on: shell spawn · package manager · sensitive files           │
│            network tools · root execution · outbound connections     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
cnd-project/
├── .github/
│   └── workflows/
│       ├── supply-chain-pipeline.yml   # Main CI/CD: Build→Sign→SBOM→SLSA
│       └── attack-scenarios.yml        # Manual: 3 security evaluation scenarios
│
├── app/                                # Go microservice (gin + logrus + uuid)
│   ├── main.go                         # /health /version /api/data endpoints
│   ├── go.mod
│   └── Dockerfile                      # Multi-stage, distroless nonroot runtime
│
├── enrichment-service/                 # Provenance-to-Runtime bridge
│   ├── main.py                         # Pod watcher + SBOM parser + Falco rule generator
│   ├── Dockerfile
│   ├── requirements.txt
│   └── k8s/deployment.yaml
│
├── feedback-service/                   # Runtime→Build feedback loop
│   ├── main.py                         # Falco webhook receiver + remediation suggester
│   ├── Dockerfile
│   └── k8s/deployment.yaml
│
├── kubernetes/
│   ├── base/                           # Namespace + Deployment + ServiceAccount + Service
│   ├── kyverno/                        # 2 ClusterPolicies: signature + registry restriction
│   ├── falco/                          # 8 custom CND rules + Helm values (offline mode)
│   ├── tetragon/                       # eBPF LSM TracingPolicy
│   └── monitoring/                     # Falco alerts dashboard
│
├── scripts/
│   ├── validate_env.sh                 # Validate all tools before setup
│   ├── setup-cluster.sh                # Minikube + Kyverno + Falco + tools
│   ├── build_pipeline.sh               # Local SLSA build pipeline
│   ├── verify_artifacts.sh             # Verify signature + SBOM + SLSA
│   ├── test_admission.sh               # Kyverno admission tests (PASS/FAIL)
│   ├── simulate_attacks.sh             # 3 scenarios × N runs → CSV
│   ├── collect_metrics.sh              # Performance comparison → CSV
│   ├── watch-falco.sh                  # Live Falco alert monitor
│   └── attack-scenarios.sh             # Local attack simulation
│
└── evaluation/
    ├── analyze_results.py              # Stats + charts + LaTeX tables
    └── metrics-template.md             # Metrics documentation
```

---

## GitHub Actions Workflows

### Automatic: `supply-chain-pipeline.yml`
Triggered on every `push` to `main` or `pull_request`.

```
push to main
    ├──▶ [Job 1] Build → Docker image (distroless, hermetic)
    │         push to ghcr.io/ghantotcon-cpu/cnd-project/cnd-demo-app
    │
    ├──▶ [Job 2] SLSA L3 Provenance (slsa-github-generator v2.0.0)
    │
    ├──▶ [Job 3] SBOM (Syft → CycloneDX + SPDX) + Grype CVE scan
    │
    ├──▶ [Job 4] Cosign sign (keyless OIDC) + SBOM attestation → Rekor
    │
    └──▶ [Job 5] Pipeline summary report (GitHub Step Summary)
```

### Manual: `attack-scenarios.yml`
Run from: `GitHub → Actions → CND Attack Scenarios → Run workflow`

| Scenario | Input | What it tests |
|----------|-------|---------------|
| `trusted` | trusted | Cosign verify + SBOM attestation on valid image |
| `build-tampering` | build-tampering | Unsigned image rejected by Cosign + Kyverno |
| `runtime-attack` | runtime-attack | Falco eBPF alerts (CND-SC-002 through SC-005) |
| `all` | all | All three scenarios + comparison report |

---

## Local Setup (Ubuntu 22.04 LTS, kernel ≥ 5.15)

```bash
git clone https://github.com/ghantotcon-cpu/cnd-project.git
cd cnd-project

# Step 0: Validate environment
bash scripts/validate_env.sh

# Step 1: Full cluster setup (Minikube + Kyverno + Falco)
bash scripts/setup-cluster.sh

# Step 2: Build local pipeline
bash scripts/build_pipeline.sh

# Step 3: Verify artifacts
bash scripts/verify_artifacts.sh localhost:5001/cnd-demo-app:latest

# Step 4: Test admission control
bash scripts/test_admission.sh

# Step 5: Run attack simulation
bash scripts/simulate_attacks.sh

# Step 6: Collect performance metrics
bash scripts/collect_metrics.sh

# Step 7: Generate analysis charts + LaTeX
pip3 install matplotlib scipy numpy
python3 evaluation/analyze_results.py
```

---

## Falco Custom Rules (8 Rules — CND-SC-001 to CND-SC-008)

| Rule | Description | Priority |
|------|-------------|----------|
| CND-SC-001 | Unexpected process not in SBOM | WARNING |
| CND-SC-002 | Shell spawned in container | CRITICAL |
| CND-SC-003 | Package manager execution | CRITICAL |
| CND-SC-004 | Sensitive file read (/etc/shadow, /proc, /root) | ERROR |
| CND-SC-005 | Network tool / exfiltration (curl, wget, nc) | CRITICAL |
| CND-SC-006 | Container running as root | ERROR |
| CND-SC-007 | Write to read-only filesystem | ERROR |
| CND-SC-008 | Unexpected outbound connection | WARNING |

Deployed with: Falco 0.40.0, `modern_ebpf` probe, namespace `falco`, Minikube.

---

## Attack Scenarios (Chapter 4 Evaluation)

| # | Scenario | Detection Layer | Tool | Expected Result |
|---|----------|-----------------|------|-----------------|
| S1 | Trusted image | Build + Admission + Runtime | Cosign + Kyverno + Falco | ✅ All checks pass |
| S2 | Build tampering (no signature) | Admission | Kyverno | ❌ Pod BLOCKED |
| S3 | Runtime shell / package manager | Runtime | Falco eBPF | 🚨 CRITICAL alert |

---

## Tool Versions

| Tool | Version | Role |
|------|---------|------|
| Minikube | v1.32+ | Local Kubernetes cluster (docker driver) |
| Kyverno | 1.12.6 | Admission control (2 ClusterPolicies) |
| Falco | 0.40.0 | Runtime monitoring (modern_ebpf, 8 custom rules) |
| Cosign | 2.2.4+ | Keyless signing (Sigstore/Rekor) |
| Syft | latest | SBOM generation (CycloneDX + SPDX) |
| Grype | latest | CVE scanning |
| slsa-github-generator | v2.0.0 | SLSA Level 3 provenance |
| Rekor | rekor.sigstore.dev | Transparency log |

---

## No Secrets Required

GitHub Actions uses **keyless OIDC** via `GITHUB_TOKEN` (automatically provided).  
No manual secrets need to be configured.
