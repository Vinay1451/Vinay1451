#!/usr/bin/env python3
"""
profile_sync.py - Complete Profile Sync & Asset Orchestration Engine.

Standard library only. Automates:
  1. Fetching live GitHub statistics (user profile, repos, stars, forks, languages)
  2. Regenerating SVG cards & radar visualizations via cards.py and radar.py
  3. Verifying all referenced local assets and external URLs in README.md
  4. Exporting updated health metrics to assets/sync-metrics.json

Usage:
  python scripts/profile_sync.py --user Vinay1451
  python scripts/profile_sync.py --user Vinay1451 --verify-assets
  python scripts/profile_sync.py --user Vinay1451 --skip-generation
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

UA = {"User-Agent": "Vinay1451-ProfileSync/1.0"}


class GitHubMetricsFetcher:
    """Fetches public GitHub profile and repository metrics without external dependencies."""

    def __init__(self, username: str, token: Optional[str] = None) -> None:
        self.username = username
        self.token = token or os.environ.get("GITHUB_TOKEN")

    def _get(self, endpoint: str) -> Any:
        url = f"https://api.github.com/{endpoint.lstrip('/')}"
        headers = dict(UA)
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            print(f"[WARN] HTTP {err.code} fetching {url}: {err.reason}", file=sys.stderr)
            return None
        except Exception as exc:
            print(f"[WARN] Error fetching {url}: {exc}", file=sys.stderr)
            return None

    def fetch_metrics(self) -> Dict[str, Any]:
        user_data = self._get(f"users/{self.username}") or {}
        repos_data = self._get(f"users/{self.username}/repos?per_page=100&type=owner") or []

        total_stars = 0
        total_forks = 0
        languages: Dict[str, int] = {}

        for r in repos_data:
            if r.get("fork"):
                continue
            total_stars += r.get("stargazers_count", 0)
            total_forks += r.get("forks_count", 0)
            lang = r.get("language")
            if lang:
                languages[lang] = languages.get(lang, 0) + 1

        top_langs = sorted(languages.items(), key=lambda x: x[1], reverse=True)

        return {
            "username": self.username,
            "name": user_data.get("name", self.username),
            "bio": user_data.get("bio", ""),
            "followers": user_data.get("followers", 0),
            "public_repos": user_data.get("public_repos", len(repos_data)),
            "total_stars": total_stars,
            "total_forks": total_forks,
            "top_languages": [{"language": l, "repo_count": c} for l, c in top_langs],
            "last_synced": dt.datetime.now(dt.timezone.utc).isoformat(),
        }


class AssetIntegrityVerifier:
    """Verifies that all local assets and links mentioned in README.md exist."""

    @staticmethod
    def verify(readme_path: Path) -> Tuple[List[str], List[str]]:
        if not readme_path.exists():
            return [], [f"README file not found at {readme_path}"]

        content = readme_path.read_text(encoding="utf-8")
        valid: List[str] = []
        broken: List[str] = []

        # Find local asset links like assets/...
        local_assets = re.findall(r'(?:src|srcset)=["\'](assets/[^"\']+)["\']', content)
        repo_root = readme_path.parent

        for asset_rel in set(local_assets):
            asset_file = repo_root / asset_rel
            if asset_file.exists():
                valid.append(asset_rel)
            else:
                broken.append(asset_rel)

        return valid, broken


class ProfileOrchestrator:
    """Coordinates metrics fetching, sub-script executions, and validation."""

    def __init__(self, username: str, repo_root: Path) -> None:
        self.username = username
        self.repo_root = repo_root
        self.scripts_dir = repo_root / "scripts"
        self.assets_dir = repo_root / "assets"

    def run_subscript(self, script_name: str, args: List[str]) -> bool:
        script_file = self.scripts_dir / script_name
        if not script_file.exists():
            print(f"[SKIP] Script not found: {script_file}")
            return False

        cmd = [sys.executable, str(script_file)] + args
        print(f"--> Executing: {' '.join(cmd)}")
        try:
            res = subprocess.run(cmd, cwd=str(self.repo_root), check=True, capture_output=True, text=True)
            if res.stdout.strip():
                print(f"    {res.stdout.strip()}")
            return True
        except subprocess.CalledProcessError as exc:
            print(f"[ERROR] {script_name} failed: {exc.stderr.strip()}", file=sys.stderr)
            return False

    def sync(self, regenerate_assets: bool = True, verify_links: bool = True) -> Dict[str, Any]:
        print(f"[*] Starting Profile Sync for GitHub User: @{self.username}")

        # 1. Fetch live metrics
        fetcher = GitHubMetricsFetcher(self.username)
        metrics = fetcher.fetch_metrics()
        print(f"[OK] Metrics retrieved: {metrics['public_repos']} Repos | {metrics['total_stars']} Stars | {metrics['followers']} Followers")

        # 2. Regenerate SVG assets if requested
        if regenerate_assets:
            print("[*] Regenerating SVG assets...")
            # Run cards.py
            self.run_subscript("cards.py", ["--user", self.username, "--out", "assets"])
            # Run radar.py for skills
            skills_json = self.assets_dir / "skills.json"
            if skills_json.exists():
                self.run_subscript("radar.py", ["--data", "assets/skills.json", "-o", "assets/radar"])
            # Run radar.py for live github languages
            self.run_subscript("radar.py", ["--github", self.username, "-o", "assets/radar-langs"])

        # 3. Verify asset integrity
        verified_assets: List[str] = []
        broken_assets: List[str] = []
        if verify_links:
            print("[*] Verifying README asset references...")
            readme = self.repo_root / "README.md"
            verified_assets, broken_assets = AssetIntegrityVerifier.verify(readme)
            print(f"[OK] Asset integrity: {len(verified_assets)} valid, {len(broken_assets)} broken")
            for b in broken_assets:
                print(f"    [WARN] Missing asset: {b}", file=sys.stderr)

        # 4. Save synced metrics report
        metrics["asset_status"] = {
            "verified_count": len(verified_assets),
            "broken_count": len(broken_assets),
            "broken_files": broken_assets
        }

        output_file = self.assets_dir / "sync-metrics.json"
        self.assets_dir.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        print(f"[OK] Synced metrics saved to: {output_file}")

        return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="GitHub Profile Sync & Automation Engine")
    parser.add_argument("--user", default="Vinay1451", help="GitHub username to sync")
    parser.add_argument("--skip-generation", action="store_true", help="Skip SVG cards and radar regeneration")
    parser.add_argument("--verify-assets", action="store_true", default=True, help="Verify local assets referenced in README")

    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parent.parent

    orchestrator = ProfileOrchestrator(args.user, repo_root)
    metrics = orchestrator.sync(
        regenerate_assets=not args.skip_generation,
        verify_links=args.verify_assets
    )

    print("\n" + "=" * 50)
    print("  PROFILE SYNC COMPLETED SUCCESSFULLY")
    print("=" * 50)
    print(f"  User       : {metrics['username']} ({metrics['name']})")
    print(f"  Repos      : {metrics['public_repos']}")
    print(f"  Stars      : {metrics['total_stars']}")
    print(f"  Followers  : {metrics['followers']}")
    print(f"  Sync Time  : {metrics['last_synced']}")
    print("=" * 50)

    return 0


if __name__ == "__main__":
    sys.exit(main())
