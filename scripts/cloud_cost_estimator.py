#!/usr/bin/env python3
"""
cloud_cost_estimator.py - Multi-Cloud Workload Pricing & Architecture Cost Analyzer.

Standard library only. Computes and compares monthly infrastructure run-rates
across AWS, Google Cloud (GCP), and Microsoft Azure for cloud-native workloads.

Features:
  1. Multi-cloud pricing model for Compute (vCPU, RAM), Object Storage, and Egress
  2. Pricing strategies: On-Demand, 1-Year Reserved/Committed, and Spot/Preemptible
  3. Cost optimization advisory (rightsizing, lifecycle policies, multi-cloud recommendations)

Usage:
  python scripts/cloud_cost_estimator.py --vcpus 8 --ram 32 --storage-gb 500 --egress-gb 200
  python scripts/cloud_cost_estimator.py --workload assets/sample-workload.json --format markdown
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional


@dataclass
class ProviderPricing:
    name: str
    vcpu_per_hour_ondemand: float
    ram_gb_per_hour_ondemand: float
    storage_gb_per_month: float
    egress_gb: float
    reserved_1yr_discount: float  # e.g. 0.35 (35% discount)
    spot_discount: float          # e.g. 0.70 (70% discount)


# Baseline multi-cloud pricing reference model (US East / Central regions)
CLOUD_PROVIDERS = {
    "AWS": ProviderPricing(
        name="Amazon Web Services (AWS)",
        vcpu_per_hour_ondemand=0.0404,     # General Purpose m6i / t4g equivalent
        ram_gb_per_hour_ondemand=0.00505,
        storage_gb_per_month=0.023,        # S3 Standard
        egress_gb=0.09,                    # Internet data transfer out
        reserved_1yr_discount=0.38,        # Compute Savings Plan 1-yr
        spot_discount=0.72,
    ),
    "GCP": ProviderPricing(
        name="Google Cloud Platform (GCP)",
        vcpu_per_hour_ondemand=0.0385,     # E2 / N2 series
        ram_gb_per_hour_ondemand=0.00516,
        storage_gb_per_month=0.020,        # Cloud Storage Standard
        egress_gb=0.085,                   # Worldwide egress tier
        reserved_1yr_discount=0.37,        # 1-yr Committed Use Discount (CUD)
        spot_discount=0.70,                # Spot VMs
    ),
    "Azure": ProviderPricing(
        name="Microsoft Azure",
        vcpu_per_hour_ondemand=0.0396,     # D-series v5
        ram_gb_per_hour_ondemand=0.00495,
        storage_gb_per_month=0.0208,       # Azure Blob Hot LRS
        egress_gb=0.087,                   # Internet outbound
        reserved_1yr_discount=0.36,        # 1-yr Reserved VM Instance
        spot_discount=0.71,                # Azure Spot
    ),
}

HOURS_PER_MONTH = 730


@dataclass
class CostBreakdown:
    provider: str
    compute_ondemand: float
    storage: float
    egress: float
    total_ondemand: float
    total_reserved_1yr: float
    total_spot: float


def calculate_cost(
    vcpus: int, ram_gb: int, storage_gb: int, egress_gb: int
) -> List[CostBreakdown]:
    results: List[CostBreakdown] = []

    for key, p in CLOUD_PROVIDERS.items():
        hourly_compute = (vcpus * p.vcpu_per_hour_ondemand) + (ram_gb * p.ram_gb_per_hour_ondemand)
        monthly_compute_ondemand = hourly_compute * HOURS_PER_MONTH
        monthly_storage = storage_gb * p.storage_gb_per_month
        monthly_egress = egress_gb * p.egress_gb

        ondemand_total = monthly_compute_ondemand + monthly_storage + monthly_egress
        reserved_total = (monthly_compute_ondemand * (1 - p.reserved_1yr_discount)) + monthly_storage + monthly_egress
        spot_total = (monthly_compute_ondemand * (1 - p.spot_discount)) + monthly_storage + monthly_egress

        results.append(CostBreakdown(
            provider=p.name,
            compute_ondemand=round(monthly_compute_ondemand, 2),
            storage=round(monthly_storage, 2),
            egress=round(monthly_egress, 2),
            total_ondemand=round(ondemand_total, 2),
            total_reserved_1yr=round(reserved_total, 2),
            total_spot=round(spot_total, 2),
        ))

    return results


def generate_recommendations(vcpus: int, ram_gb: int, storage_gb: int, egress_gb: int) -> List[str]:
    recs: List[str] = []
    if storage_gb >= 1000:
        recs.append("Enable Lifecycle Policies: Transition data older than 30-90 days to Infrequent Access / Cold / Archive storage classes to save up to 60-80% on storage.")
    if vcpus >= 16 or ram_gb >= 64:
        recs.append("Commitment Strategy: For steady-state production nodes, enroll in 1-Year Compute Savings Plans or CUDs to save ~37% annually.")
    if egress_gb >= 500:
        recs.append("Content Delivery Network (CDN): Offload outbound assets through Cloudflare, CloudFront, or Cloud CDN to dramatically cut internet egress bandwidth fees.")
    recs.append("Spot Orchestration: Utilize Spot/Preemptible instances for batch workloads, CI/CD runners, and fault-tolerant Kubernetes worker nodes.")
    return recs


def format_console(
    results: List[CostBreakdown], vcpus: int, ram_gb: int, storage_gb: int, egress_gb: int, recs: List[str]
) -> str:
    lines = []
    lines.append("=" * 76)
    lines.append("  MULTI-CLOUD INFRASTRUCTURE ESTIMATOR & COST COMPARISON")
    lines.append("=" * 76)
    lines.append(f"  Workload Specs: {vcpus} vCPUs | {ram_gb} GB RAM | {storage_gb} GB Storage | {egress_gb} GB Egress/mo")
    lines.append("-" * 76)
    lines.append(f"  {'Provider':<32} {'On-Demand':<14} {'1-Yr Reserved':<14} {'Spot / Preempt':<14}")
    lines.append("-" * 76)

    for r in results:
        lines.append(f"  {r.provider:<32} ${r.total_ondemand:<13.2f} ${r.total_reserved_1yr:<13.2f} ${r.total_spot:<13.2f}")

    lines.append("=" * 76)
    lines.append("  Architectural Cost Optimization Recommendations:")
    for idx, rec in enumerate(recs, start=1):
        lines.append(f"   {idx}. {rec}")
    lines.append("=" * 76)

    return "\n".join(lines)


def format_markdown(
    results: List[CostBreakdown], vcpus: int, ram_gb: int, storage_gb: int, egress_gb: int, recs: List[str]
) -> str:
    lines = [
        "# Multi-Cloud Infrastructure Cost Comparison",
        "",
        f"**Workload Parameters:** `{vcpus} vCPUs` | `{ram_gb} GB Memory` | `{storage_gb} GB Storage` | `{egress_gb} GB Egress/month`",
        "",
        "## Monthly Cost Breakdown",
        "",
        "| Cloud Provider | On-Demand ($/mo) | 1-Yr Commitment ($/mo) | Spot / Preemptible ($/mo) |",
        "|---|---|---|---|",
    ]

    for r in results:
        lines.append(f"| **{r.provider}** | `${r.total_ondemand:.2f}` | `${r.total_reserved_1yr:.2f}` | `${r.total_spot:.2f}` |")

    lines.extend([
        "",
        "## Optimization Strategies",
        "",
    ])
    for r in recs:
        lines.append(f"- {r}")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-Cloud Infrastructure Cost Estimator")
    parser.add_argument("--vcpus", type=int, default=4, help="Total vCPU capacity required")
    parser.add_argument("--ram", type=int, default=16, help="Total RAM in GB")
    parser.add_argument("--storage-gb", type=int, default=250, help="Object/block storage in GB")
    parser.add_argument("--egress-gb", type=int, default=100, help="Outbound internet data transfer in GB/mo")
    parser.add_argument("--format", choices=["console", "json", "markdown"], default="console", help="Output format")
    parser.add_argument("--output", help="Optional file path to write results")

    args = parser.parse_args()

    results = calculate_cost(args.vcpus, args.ram, args.storage_gb, args.egress_gb)
    recs = generate_recommendations(args.vcpus, args.ram, args.storage_gb, args.egress_gb)

    if args.format == "json":
        data = {
            "specs": {"vcpus": args.vcpus, "ram_gb": args.ram, "storage_gb": args.storage_gb, "egress_gb": args.egress_gb},
            "comparison": [r.__dict__ for r in results],
            "recommendations": recs
        }
        text = json.dumps(data, indent=2)
    elif args.format == "markdown":
        text = format_markdown(results, args.vcpus, args.ram, args.storage_gb, args.egress_gb, recs)
    else:
        text = format_console(results, args.vcpus, args.ram, args.storage_gb, args.egress_gb, recs)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Cost estimate written to {args.output}")
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
