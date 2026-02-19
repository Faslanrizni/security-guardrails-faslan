#!/usr/bin/env python3
"""
Repo Freezer v1.0.0
Freezes a GitHub repository when a secret leak is detected by:
  - Enabling branch protection on default branch
  - Creating a blocking incident issue
  - Posting a security alert comment
  - Writing a JSON incident report

Requires: GITHUB_TOKEN with repo + admin:repo_hook scope
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
GITHUB_API = "https://api.github.com"
# ─────────────────────────────────────────────────────────────────────────────


class GitHubClient:
    """Thin wrapper around the GitHub REST API."""

    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def get(self, path: str) -> Dict:
        r = self.session.get(f"{GITHUB_API}{path}")
        r.raise_for_status()
        return r.json()

    def post(self, path: str, body: Dict) -> Dict:
        r = self.session.post(f"{GITHUB_API}{path}", json=body)
        r.raise_for_status()
        return r.json()

    def put(self, path: str, body: Dict) -> Dict:
        r = self.session.put(f"{GITHUB_API}{path}", json=body)
        r.raise_for_status()
        return r.json()

    def delete(self, path: str, body: Dict = None) -> None:
        r = self.session.delete(f"{GITHUB_API}{path}", json=body or {})
        r.raise_for_status()


class RepoFreezer:
    """
    Freezes / unfreezes a GitHub repository in response to a secret leak.

    Freeze actions:
      1. Enable branch protection with admin enforcement on default branch
      2. Create a HIGH-SEVERITY incident issue (pinned, labelled)
      3. Write a local JSON incident report

    Unfreeze actions:
      1. Remove branch protection
      2. Close the incident issue
      3. Update the incident report
    """

    INCIDENT_LABEL = "security-incident"
    INCIDENT_LABEL_COLOR = "d93f0b"

    def __init__(self, repo: str, token: Optional[str] = None):
        self.repo  = repo          # "owner/repo"
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self._client: Optional[GitHubClient] = None
        self._sim = False

        if not self.token:
            print("⚠  No GITHUB_TOKEN found — running in simulation mode.")
            self._sim = True
        elif not REQUESTS_AVAILABLE:
            print("⚠  'requests' package not installed — running in simulation mode.")
            print("   Install with: pip install requests")
            self._sim = True
        else:
            self._client = GitHubClient(self.token)

    # ── public API ────────────────────────────────────────────────────────────

    def freeze(
        self,
        secret_type: str = "unknown",
        description: str = "Secret detected in code",
        file_path: str = "",
        commit_sha: str = "",
        json_output: str = "",
    ) -> Dict[str, Any]:

        now = datetime.now(timezone.utc).isoformat()
        print(f"\n  FREEZING REPOSITORY: {self.repo}")
        print(f"    Secret type : {secret_type}")
        print(f"    Description : {description}")
        if file_path:
            print(f"    File        : {file_path}")
        if commit_sha:
            print(f"    Commit      : {commit_sha[:12]}")

        report = {
            "version":     VERSION,
            "action":      "freeze",
            "repo":        self.repo,
            "secret_type": secret_type,
            "description": description,
            "file":        file_path,
            "commit":      commit_sha,
            "timestamp":   now,
            "simulation":  self._sim,
            "steps":       [],
        }

        if self._sim:
            self._simulate_freeze(report)
        else:
            self._apply_freeze(report, description, secret_type, file_path, commit_sha, now)

        if json_output:
            Path(json_output).write_text(json.dumps(report, indent=2))
            print(f"\n  Incident report written to: {json_output}")

        return report

    def unfreeze(self, json_output: str = "") -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        print(f"\n  UNFREEZING REPOSITORY: {self.repo}")

        report = {
            "version":   VERSION,
            "action":    "unfreeze",
            "repo":      self.repo,
            "timestamp": now,
            "simulation": self._sim,
            "steps":     [],
        }

        if self._sim:
            self._simulate_unfreeze(report)
        else:
            self._apply_unfreeze(report)

        if json_output:
            Path(json_output).write_text(json.dumps(report, indent=2))
            print(f"\n  Report written to: {json_output}")

        return report

    # ── freeze implementation ─────────────────────────────────────────────────

    def _apply_freeze(self, report, description, secret_type, file_path, commit_sha, now):
        try:
            default_branch = self._get_default_branch()

            # Step 1 — branch protection
            self._enable_branch_protection(default_branch)
            report["steps"].append({"step": "branch_protection", "status": "enabled", "branch": default_branch})
            print(f"    Branch protection enabled on '{default_branch}'")

            # Step 2 — ensure label exists
            self._ensure_label()

            # Step 3 — create incident issue
            issue_url = self._create_incident_issue(
                secret_type, description, file_path, commit_sha, now
            )
            report["steps"].append({"step": "incident_issue", "status": "created", "url": issue_url})
            print(f"    Incident issue created: {issue_url}")

            report["frozen"] = True
            print(f"\n  Repository {self.repo} is now FROZEN.")
            print(f"    Action required: Rotate the exposed {secret_type} immediately.")

        except Exception as e:
            report["steps"].append({"step": "error", "message": str(e)})
            print(f"    Error during freeze: {e}")
            sys.exit(1)

    def _apply_unfreeze(self, report):
        try:
            default_branch = self._get_default_branch()

            # Remove branch protection
            self._client.delete(f"/repos/{self.repo}/branches/{default_branch}/protection")
            report["steps"].append({"step": "branch_protection", "status": "removed"})
            print(f"    Branch protection removed from '{default_branch}'")

            # Close open incident issues
            issues = self._client.get(
                f"/repos/{self.repo}/issues?labels={self.INCIDENT_LABEL}&state=open"
            )
            for issue in issues:
                self._client.post(
                    f"/repos/{self.repo}/issues/{issue['number']}",
                    {"state": "closed", "body": f"Resolved at {datetime.now(timezone.utc).isoformat()}"}
                )
            report["steps"].append({"step": "incident_issues_closed", "count": len(issues)})
            print(f"    Closed {len(issues)} incident issue(s)")

            report["frozen"] = False
            print(f"\n  Repository {self.repo} has been UNFROZEN.")

        except Exception as e:
            report["steps"].append({"step": "error", "message": str(e)})
            print(f"    Error during unfreeze: {e}")
            sys.exit(1)

    # ── simulation ────────────────────────────────────────────────────────────

    def _simulate_freeze(self, report):
        steps = [
            "Enable branch protection on default branch",
            "Create security-incident label",
            "Create incident issue with full context",
            "Write JSON incident report",
        ]
        print("\n  [SIMULATION] Would perform:")
        for i, step in enumerate(steps, 1):
            print(f"    {i}. {step}")
            report["steps"].append({"step": step, "status": "simulated"})
        report["frozen"] = True

    def _simulate_unfreeze(self, report):
        steps = [
            "Remove branch protection",
            "Close open incident issues",
        ]
        print("\n  [SIMULATION] Would perform:")
        for i, step in enumerate(steps, 1):
            print(f"    {i}. {step}")
            report["steps"].append({"step": step, "status": "simulated"})
        report["frozen"] = False

    # ── GitHub API helpers ────────────────────────────────────────────────────

    def _get_default_branch(self) -> str:
        repo_data = self._client.get(f"/repos/{self.repo}")
        return repo_data["default_branch"]

    def _enable_branch_protection(self, branch: str):
        self._client.put(
            f"/repos/{self.repo}/branches/{branch}/protection",
            {
                "required_status_checks": None,
                "enforce_admins": True,
                "required_pull_request_reviews": {
                    "required_approving_review_count": 2,
                    "dismiss_stale_reviews": True,
                },
                "restrictions": None,
                "allow_force_pushes": False,
                "allow_deletions": False,
            },
        )

    def _ensure_label(self):
        try:
            self._client.get(f"/repos/{self.repo}/labels/{self.INCIDENT_LABEL}")
        except Exception:
            try:
                self._client.post(
                    f"/repos/{self.repo}/labels",
                    {"name": self.INCIDENT_LABEL, "color": self.INCIDENT_LABEL_COLOR},
                )
            except Exception:
                pass

    def _create_incident_issue(
        self, secret_type, description, file_path, commit_sha, now
    ) -> str:
        body = f"""##  Security Incident — Secret Leak Detected

| Field | Value |
|---|---|
| **Secret type** | `{secret_type}` |
| **Detected at** | {now} |
| **File** | `{file_path or "unknown"}` |
| **Commit** | `{commit_sha[:12] if commit_sha else "unknown"}` |

### Description
{description}

### Required Actions
- [ ] Rotate the exposed `{secret_type}` **immediately**
- [ ] Audit access logs for the exposed credential
- [ ] Remove the secret from git history (`git filter-repo`)
- [ ] Verify no downstream systems used the leaked credential
- [ ] Unfreeze the repository once rotation is confirmed

### How to unfreeze
```bash
python tools/secrets/repo-freezer.py {self.repo} --unfreeze
```

---
*This issue was created automatically by the Security Guardrails pipeline.*
"""
        issue = self._client.post(
            f"/repos/{self.repo}/issues",
            {
                "title": f" SECURITY INCIDENT: {secret_type} leaked",
                "body": body,
                "labels": [self.INCIDENT_LABEL],
            },
        )
        return issue["html_url"]


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Freeze/unfreeze a GitHub repository on secret leak",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Freeze on secret detection
  python repo-freezer.py owner/repo --secret-type aws_access_key --file api/config.go

  # Unfreeze after rotation
  python repo-freezer.py owner/repo --unfreeze

  # Simulation (no token needed)
  python repo-freezer.py owner/repo --secret-type github_token
""",
    )
    parser.add_argument("repo",           help="Repository (owner/repo)")
    parser.add_argument("--secret-type",  default="unknown",                  help="Type of secret leaked")
    parser.add_argument("--description",  default="Secret detected in code",  help="Human-readable description")
    parser.add_argument("--file",         default="",                          help="File where secret was found")
    parser.add_argument("--commit",       default="",                          help="Commit SHA where secret was found")
    parser.add_argument("--unfreeze",     action="store_true",                 help="Unfreeze instead of freeze")
    parser.add_argument("--json-output",  default="",    metavar="FILE",       help="Write incident report to FILE")
    parser.add_argument("--version",      action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    freezer = RepoFreezer(args.repo)

    if args.unfreeze:
        freezer.unfreeze(json_output=args.json_output)
    else:
        freezer.freeze(
            secret_type=args.secret_type,
            description=args.description,
            file_path=args.file,
            commit_sha=args.commit,
            json_output=args.json_output,
        )


if __name__ == "__main__":
    main()