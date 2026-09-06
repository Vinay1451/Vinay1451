# Automation & DevOps Engineering Scripts

This directory houses production-ready, standard-library-only Python tools developed for cloud automation, infrastructure auditing, and profile orchestration.

---

## Toolset Overview

### 1. `profile_sync.py` — Profile Automation & Asset Orchestration Engine
Fetches live GitHub metrics, regenerates dynamic SVG cards/radars, verifies local asset references, and exports telemetry.
```bash
# Sync entire profile and regenerate all assets
python scripts/profile_sync.py --user Vinay1451

# Verify assets without regenerating
python scripts/profile_sync.py --user Vinay1451 --skip-generation
```

### 2. `cloud_infra_audit.py` — Infrastructure & Container Security Auditor
Scans Dockerfiles, Terraform scripts, and Kubernetes manifests for security anti-patterns, privilege escalation, unencrypted storage, and missing best practices.
```bash
# Scan repository for IaC and container security issues
python scripts/cloud_infra_audit.py --path ./

# Export detailed Markdown report
python scripts/cloud_infra_audit.py --path ./ --format markdown --output audit-report.md

# Enforce minimum security compliance score in CI/CD pipelines
python scripts/cloud_infra_audit.py --min-score 85
```

### 3. `cloud_cost_estimator.py` — Multi-Cloud Architecture Cost Estimator
Analyzes and compares monthly infrastructure run-rates across AWS, Google Cloud (GCP), and Microsoft Azure with optimization recommendations.
```bash
# Run multi-cloud cost model for specific workload parameters
python scripts/cloud_cost_estimator.py --vcpus 8 --ram 32 --storage-gb 500 --egress-gb 200

# Generate Markdown cost comparison table
python scripts/cloud_cost_estimator.py --format markdown
```

### 4. `radar.py` — Dynamic Radar Chart Generator
Renders high-resolution spider/radar charts as standalone dark/light SVGs from local JSON or live GitHub language statistics.
```bash
# Generate language radar directly from GitHub API
python scripts/radar.py --github Vinay1451 -o assets/radar-langs

# Generate competency radar from custom JSON
python scripts/radar.py --data assets/skills.json -o assets/radar
```

### 5. `cards.py` — Self-Hosted GitHub Statistics & Repo Cards
Generates zero-dependency SVG stat cards and pinned repository showcases that never suffer from third-party rate limits or server downtime.
```bash
python scripts/cards.py --user Vinay1451 --out assets
```

---

## Design Principles
- **Standard Library Only**: Zero external `pip` dependencies required for execution.
- **Cross-Platform**: Fully compatible with Linux, macOS, and Windows.
- **CI/CD Ready**: Supports structured CLI exits and JSON/Markdown outputs for automated workflows.
