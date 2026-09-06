#!/usr/bin/env python3
"""
cloud_infra_audit.py - Lightweight Infrastructure-as-Code & Container Security Auditor.

Standard library only. Designed for Cloud & DevOps Engineers to scan:
  1. Dockerfiles (least privilege, image tagging, layer caching, security hygiene)
  2. Terraform configurations (open security groups, unencrypted storage, missing tags)
  3. Kubernetes manifests (pod security standards, resource limits, probe configurations)

Usage:
  python scripts/cloud_infra_audit.py --path ./
  python scripts/cloud_infra_audit.py --path ./ --format markdown --output audit-report.md
  python scripts/cloud_infra_audit.py --min-score 85
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from enum import Enum
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    target_type: str  # "docker", "terraform", "k8s"
    file_path: str
    line_number: Optional[int]
    title: str
    description: str
    remediation: str


class DockerfileAuditor:
    """Audits Dockerfile configurations against container security best practices."""

    @staticmethod
    def audit(file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        lines = content.splitlines()
        has_user_directive = False
        has_healthcheck = False
        from_lines: List[tuple[int, str]] = []

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # FROM check
            if re.match(r"^FROM\s+", stripped, re.IGNORECASE):
                from_lines.append((idx, stripped))
                image_ref = stripped.split()[1] if len(stripped.split()) > 1 else ""
                if ":latest" in image_ref or ":" not in image_ref.split("/")[-1]:
                    findings.append(Finding(
                        rule_id="DOCKER-001",
                        severity=Severity.HIGH,
                        target_type="docker",
                        file_path=str(file_path),
                        line_number=idx,
                        title="Avoid ':latest' or Untagged Base Images",
                        description=f"Base image '{image_ref}' uses ':latest' or no tag, leading to unpredictable builds.",
                        remediation="Pin specific immutable image digests (SHA256) or explicit semantic version tags."
                    ))

            # USER check
            if re.match(r"^USER\s+", stripped, re.IGNORECASE):
                user_name = stripped.split()[1] if len(stripped.split()) > 1 else ""
                if user_name.lower() not in ("root", "0"):
                    has_user_directive = True

            # HEALTHCHECK check
            if re.match(r"^HEALTHCHECK\s+", stripped, re.IGNORECASE):
                has_healthcheck = True

            # Sensitive variables in ENV/ARG
            if re.match(r"^(ENV|ARG)\s+.*(secret|password|token|key|pwd|cred).*", stripped, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="DOCKER-002",
                    severity=Severity.CRITICAL,
                    target_type="docker",
                    file_path=str(file_path),
                    line_number=idx,
                    title="Potential Hardcoded Secret in ENV/ARG",
                    description="Detected sensitive key pattern in Docker build argument or environment variable.",
                    remediation="Use build secrets (--mount=type=secret) or runtime secrets management (Vault/Secret Manager)."
                ))

            # Insecure curl | sh pattern
            if re.search(r"curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh", stripped, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="DOCKER-003",
                    severity=Severity.HIGH,
                    target_type="docker",
                    file_path=str(file_path),
                    line_number=idx,
                    title="Unverified Pipe to Shell (curl | sh)",
                    description="Downloading and piping executable scripts directly into a shell without checksum validation.",
                    remediation="Download the script, verify cryptographic hash/checksum, then execute with restricted privileges."
                ))

            # Package manager cache not cleared
            if re.search(r"apt-get\s+install", stripped, re.IGNORECASE):
                if "rm -rf /var/lib/apt/lists/*" not in content:
                    findings.append(Finding(
                        rule_id="DOCKER-004",
                        severity=Severity.LOW,
                        target_type="docker",
                        file_path=str(file_path),
                        line_number=idx,
                        title="APT Cache Not Cleaned",
                        description="apt-get install without cleaning /var/lib/apt/lists increases overall image attack surface and size.",
                        remediation="Append '&& rm -rf /var/lib/apt/lists/*' in the same RUN layer."
                    ))

        if not has_user_directive and from_lines:
            findings.append(Finding(
                rule_id="DOCKER-005",
                severity=Severity.HIGH,
                target_type="docker",
                file_path=str(file_path),
                line_number=from_lines[-1][0],
                title="Container Runs as Root by Default",
                description="No non-root USER instruction found. Container processes will run with root permissions.",
                remediation="Define a non-privileged user (e.g. 'USER nonroot' or 'USER 1001') before the CMD/ENTRYPOINT."
            ))

        if not has_healthcheck and from_lines:
            findings.append(Finding(
                rule_id="DOCKER-006",
                severity=Severity.MEDIUM,
                target_type="docker",
                file_path=str(file_path),
                line_number=None,
                title="Missing Container HEALTHCHECK",
                description="No HEALTHCHECK instruction declared. Orchestrators may not detect application deadlock.",
                remediation="Add HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8080/health || exit 1."
            ))

        return findings


class TerraformAuditor:
    """Audits Terraform (.tf) files for multi-cloud security and infrastructure best practices."""

    @staticmethod
    def audit(file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Open Ingress 0.0.0.0/0
            if "cidr_blocks" in stripped and "0.0.0.0/0" in stripped:
                window = "\n".join(lines[max(0, idx - 8):min(len(lines), idx + 8)])
                if any(port in window for port in ["22", "3389", "5432", "3306", "27017"]):
                    findings.append(Finding(
                        rule_id="TF-001",
                        severity=Severity.CRITICAL,
                        target_type="terraform",
                        file_path=str(file_path),
                        line_number=idx,
                        title="Sensitive Ingress Port Open to 0.0.0.0/0",
                        description="Security group opens administrative or database ports (22, 3389, 5432, 3306) to the entire Internet.",
                        remediation="Restrict CIDR blocks to specific corporate VPNs, bastion subnets, or utilize AWS SSM / Azure Bastion / GCP IAP."
                    ))

            # Unencrypted storage (S3 / EBS / Azure Blob / GCS)
            if "encrypted" in stripped and "false" in stripped:
                findings.append(Finding(
                    rule_id="TF-002",
                    severity=Severity.HIGH,
                    target_type="terraform",
                    file_path=str(file_path),
                    line_number=idx,
                    title="Storage Volume or Bucket Encryption Explicitly Disabled",
                    description="Storage resource has server-side encryption disabled.",
                    remediation="Set encrypted = true using KMS / Cloud Key Management customer-managed or service-managed keys."
                ))

            # Plaintext credentials
            if re.search(r'(access_key|secret_key|password|token)\s*=\s*"[^"]+"', stripped, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="TF-003",
                    severity=Severity.CRITICAL,
                    target_type="terraform",
                    file_path=str(file_path),
                    line_number=idx,
                    title="Hardcoded Credential in Terraform Code",
                    description="Hardcoded credentials committed in Infrastructure-as-Code.",
                    remediation="Utilize environment variables (TF_VAR_*), IAM Instance Profiles, Workload Identity, or HashiCorp Vault."
                ))

        # Check for tagging standards
        if "resource " in content and "tags" not in content and "labels" not in content:
            findings.append(Finding(
                rule_id="TF-004",
                severity=Severity.LOW,
                target_type="terraform",
                file_path=str(file_path),
                line_number=1,
                title="Missing Standard Infrastructure Tags/Labels",
                description="Resources defined without standard tags (Environment, Owner, Project, CostCenter).",
                remediation="Enforce mandatory tagging blocks or use provider-level default_tags."
            ))

        return findings


class KubernetesAuditor:
    """Audits Kubernetes manifests for Pod Security Standards and reliability requirements."""

    @staticmethod
    def audit(file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        if not ("apiVersion" in content and "kind" in content):
            return findings

        lines = content.splitlines()

        # Check privileged containers
        for idx, line in enumerate(lines, start=1):
            if "privileged: true" in line:
                findings.append(Finding(
                    rule_id="K8S-001",
                    severity=Severity.CRITICAL,
                    target_type="k8s",
                    file_path=str(file_path),
                    line_number=idx,
                    title="Container Runs in Privileged Mode",
                    description="Privileged containers inherit all root capabilities of the host kernel, enabling container escape.",
                    remediation="Remove 'privileged: true' and grant only explicit, fine-grained Linux capabilities required via capAdd."
                ))

            if "runAsNonRoot: false" in line:
                findings.append(Finding(
                    rule_id="K8S-002",
                    severity=Severity.HIGH,
                    target_type="k8s",
                    file_path=str(file_path),
                    line_number=idx,
                    title="Explicit Execution as Root in Pod Security Context",
                    description="runAsNonRoot explicitly disabled for container workload.",
                    remediation="Set 'runAsNonRoot: true' and assign a specific non-root runAsUser UID."
                ))

        # Check resource limits
        if "kind: Deployment" in content or "kind: StatefulSet" in content or "kind: DaemonSet" in content:
            if "resources:" not in content or "limits:" not in content:
                findings.append(Finding(
                    rule_id="K8S-003",
                    severity=Severity.MEDIUM,
                    target_type="k8s",
                    file_path=str(file_path),
                    line_number=None,
                    title="Missing Container CPU/Memory Limits",
                    description="No resource limits defined. Rogue containers can starve cluster worker nodes (Noisy Neighbor).",
                    remediation="Define explicit 'resources.requests' and 'resources.limits' for both cpu and memory."
                ))

            if "livenessProbe" not in content or "readinessProbe" not in content:
                findings.append(Finding(
                    rule_id="K8S-004",
                    severity=Severity.LOW,
                    target_type="k8s",
                    file_path=str(file_path),
                    line_number=None,
                    title="Missing Liveness / Readiness Health Probes",
                    description="Workload does not define health probes, risking traffic routing to failing pods.",
                    remediation="Configure appropriate HTTP, TCP, or Exec livenessProbe and readinessProbe configurations."
                ))

        return findings


class SecurityAuditorEngine:
    """Core scanner engine coordinating multi-format checks and score computation."""

    PENALTY_WEIGHTS = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0,
    }

    def __init__(self, target_dir: Path) -> None:
        self.target_dir = target_dir
        self.scanned_files: List[str] = []
        self.findings: List[Finding] = []

    def run(self) -> None:
        for root, dirs, files in os.walk(self.target_dir):
            # Skip VCS and cache directories
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".terraform", "__pycache__", ".venv")]

            for file in files:
                p = Path(root) / file
                name_lower = file.lower()

                # Dockerfile checks
                if "dockerfile" in name_lower or p.suffix in (".dockerfile",):
                    self.scanned_files.append(str(p))
                    self.findings.extend(DockerfileAuditor.audit(p))

                # Terraform checks
                elif p.suffix == ".tf":
                    self.scanned_files.append(str(p))
                    self.findings.extend(TerraformAuditor.audit(p))

                # Kubernetes checks
                elif p.suffix in (".yaml", ".yml"):
                    if any(token in name_lower for token in ("k8s", "deploy", "pod", "ingress", "service", "cluster")):
                        self.scanned_files.append(str(p))
                        self.findings.extend(KubernetesAuditor.audit(p))

    def compute_score(self) -> int:
        if not self.scanned_files and not self.findings:
            return 100
        penalties = sum(self.PENALTY_WEIGHTS[f.severity] for f in self.findings)
        return max(0, 100 - penalties)

    def summary(self) -> Dict[str, Any]:
        sev_counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            sev_counts[f.severity.value] += 1

        score = self.compute_score()
        return {
            "score": score,
            "grade": "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "F",
            "files_scanned": len(self.scanned_files),
            "total_findings": len(self.findings),
            "severity_breakdown": sev_counts,
            "findings": [asdict(f) for f in self.findings]
        }


def format_console(summary: Dict[str, Any]) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append("  CLOUD & DEVOPS INFRASTRUCTURE SECURITY AUDIT")
    lines.append("=" * 72)
    lines.append(f"  Files Scanned  : {summary['files_scanned']}")
    lines.append(f"  Total Findings : {summary['total_findings']}")
    lines.append(f"  Security Score : {summary['score']}/100 (Grade: {summary['grade']})")
    lines.append("-" * 72)
    lines.append("  Severity Distribution:")
    for sev, count in summary["severity_breakdown"].items():
        lines.append(f"    - {sev:<10}: {count}")
    lines.append("=" * 72)

    if summary["findings"]:
        lines.append("\nDetailed Findings:")
        for idx, item in enumerate(summary["findings"], start=1):
            lines.append(f"\n[{idx}] [{item['severity']}] {item['title']} ({item['rule_id']})")
            lines.append(f"     Target : {item['file_path']}" + (f":{item['line_number']}" if item['line_number'] else ""))
            lines.append(f"     Details: {item['description']}")
            lines.append(f"     Action : {item['remediation']}")
    else:
        lines.append("\nNo security violations or misconfigurations detected. Clean audit!")

    return "\n".join(lines)


def format_markdown(summary: Dict[str, Any]) -> str:
    lines = [
        "# Cloud Infrastructure & Security Audit Report",
        "",
        f"**Security Score:** `{summary['score']}/100` (Grade `{summary['grade']}`)  ",
        f"**Files Evaluated:** `{summary['files_scanned']}` | **Total Issues:** `{summary['total_findings']}`",
        "",
        "## Severity Breakdown",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev, count in summary["severity_breakdown"].items():
        lines.append(f"| **{sev}** | {count} |")

    lines.extend([
        "",
        "## Findings & Actionable Remediations",
        "",
    ])

    if not summary["findings"]:
        lines.append("No security warnings identified. Configuration complies with Cloud & DevOps standards.")
    else:
        for f in summary["findings"]:
            target_str = f"`{f['file_path']}`" + (f":`{f['line_number']}`" if f.get("line_number") else "")
            lines.append(f"### [{f['severity']}] {f['title']} (`{f['rule_id']}`)")
            lines.append(f"- **Target File:** {target_str}")
            lines.append(f"- **Description:** {f['description']}")
            lines.append(f"- **Remediation:** {f['remediation']}")
            lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Cloud & DevOps Infrastructure Security Auditor")
    parser.add_argument("--path", default=".", help="Root directory path to scan (default: current directory)")
    parser.add_argument("--format", choices=["console", "json", "markdown"], default="console", help="Report output format")
    parser.add_argument("--output", help="Write report output to specified file path")
    parser.add_argument("--min-score", type=int, default=0, help="Exit with non-zero code if score falls below threshold")

    args = parser.parse_args()
    engine = SecurityAuditorEngine(Path(args.path).resolve())
    engine.run()
    summary = engine.summary()

    if args.format == "json":
        output_text = json.dumps(summary, indent=2)
    elif args.format == "markdown":
        output_text = format_markdown(summary)
    else:
        output_text = format_console(summary)

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Audit report saved to {args.output}")
    else:
        print(output_text)

    if summary["score"] < args.min_score:
        print(f"\nAudit failed: Score {summary['score']} is below required minimum {args.min_score}.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
