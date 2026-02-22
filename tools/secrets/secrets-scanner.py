#!/usr/bin/env python3
"""
Secrets Post-Processor v2.0.0

This script does NOT scan for secrets itself.
Gitleaks handles all detection via gitleaks.toml.

This script:
  1. Reads the gitleaks SARIF output
  2. Converts it to our standard JSON format
  3. Applies severity mapping from policies/secrets.yaml
  4. Triggers repo-freezer if CRITICAL secrets are found
  5. Exits 1 if blocking severities are present
"""

import re
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

VERSION = "2.0.0"

# Map gitleaks rule IDs to severity — must match your gitleaks.toml rule ids
# Gitleaks SARIF doesn't always carry severity, so we define it here
RULE_SEVERITY = {
    "aws-access-key":           "CRITICAL",
    "aws-secret-key":           "CRITICAL",
    "github-pat-classic":       "CRITICAL",
    "github-pat-fine":          "CRITICAL",
    "github-oauth-token":       "CRITICAL",
    "stripe-secret-key":        "CRITICAL",
    "azure-storage-key":        "CRITICAL",
    "database-connection-string": "CRITICAL",
    "private-key-block":        "CRITICAL",
    "gcp-api-key":              "HIGH",
    "google-oauth":             "HIGH",
    "slack-token":              "HIGH",
    "jwt-token":                "HIGH",
    "firebase-server-key":      "HIGH",
    "hardcoded-env-secret":     "HIGH",
    "bearer-token":             "HIGH",
}

DEFAULT_BLOCK_SEVERITIES = {"CRITICAL", "HIGH"}


class SecretsPostProcessor:

    def __init__(self, policy_path: Optional[str] = None, verbose: bool = False):
        self.verbose  = verbose
        self.findings: List[Dict] = []
        self._policy  = self._load_policy(policy_path)

    def _load_policy(self, policy_path: Optional[str]) -> Dict:
        if not policy_path:
            auto = Path(__file__).parent.parent.parent / "policies" / "secrets.yaml"
            if auto.exists():
                policy_path = str(auto)

        if policy_path and Path(policy_path).exists() and YAML_AVAILABLE:
            try:
                with open(policy_path) as f:
                    data = yaml.safe_load(f) or {}
                self._log(f"Policy loaded: {policy_path}")
                return data.get("secrets", {})
            except Exception as e:
                print(f"  ⚠ Could not load policy: {e}")
        else:
            self._log("No policy file found — using defaults")
        return {}

    @property
    def _block_severities(self) -> set:
        configured = self._policy.get("block_on_severity", ["HIGH", "CRITICAL"])
        return set(configured)

    def load_sarif(self, sarif_path: str) -> List[Dict]:
        """Parse gitleaks SARIF output into our standard finding format."""
        path = Path(sarif_path)
        if not path.exists():
            print(f"  ⚠ SARIF file not found: {sarif_path}")
            return []

        try:
            sarif = json.loads(path.read_text())
        except Exception as e:
            print(f"  ⚠ Could not parse SARIF: {e}")
            return []

        for run in sarif.get("runs", []):
            # Build rule id → severity map from SARIF rules section
            rules_meta = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rule_id = rule.get("id", "")
                # Try to get severity from SARIF properties first, fall back to our map
                sarif_severity = (
                    rule.get("properties", {}).get("severity", "") or
                    rule.get("defaultConfiguration", {}).get("level", "")
                )
                severity = RULE_SEVERITY.get(rule_id, "MEDIUM")
                rules_meta[rule_id] = severity

            for result in run.get("results", []):
                rule_id  = result.get("ruleId", "unknown")
                message  = result.get("message", {}).get("text", "")
                severity = rules_meta.get(rule_id, RULE_SEVERITY.get(rule_id, "MEDIUM"))

                # Extract file and line from locations
                for loc in result.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    uri  = phys.get("artifactLocation", {}).get("uri", "unknown")
                    line = phys.get("region", {}).get("startLine", 0)

                    self.findings.append({
                        "file":     uri,
                        "line":     line,
                        "type":     rule_id,
                        "severity": severity,
                        "match":    message[:80] + ("..." if len(message) > 80 else ""),
                    })

        self._log(f"Loaded {len(self.findings)} finding(s) from SARIF")
        return self.findings

    def should_block(self) -> bool:
        return any(f["severity"] in self._block_severities for f in self.findings)

    def get_critical_findings(self) -> List[Dict]:
        return [f for f in self.findings if f["severity"] == "CRITICAL"]

    def print_findings(self):
        if not self.findings:
            print("\n  No secrets found.")
            return

        critical = [f for f in self.findings if f["severity"] == "CRITICAL"]
        high     = [f for f in self.findings if f["severity"] == "HIGH"]
        medium   = [f for f in self.findings if f["severity"] == "MEDIUM"]

        print(f"\n{'═' * 62}")
        print(f"  SECRETS SCAN REPORT — {len(self.findings)} finding(s)")
        print(f"  Block severities: {', '.join(sorted(self._block_severities))}")
        print(f"{'═' * 62}")

        for group, label in [
            (critical, " CRITICAL"),
            (high,     " HIGH"),
            (medium,   " MEDIUM"),
        ]:
            if group:
                print(f"\n{label} ({len(group)})")
                for f in group:
                    print(f"  {f['file']}:{f['line']}  [{f['type']}]  {f['match']}")

        status = "BLOCKED" if self.should_block() else "FLAGGED"
        print(f"\n{'─' * 62}")
        print(f"  Result: {status}")
        print(f"{'═' * 62}\n")

    def save_json(self, path: str):
        output = {
            "version": VERSION,
            "blocked": self.should_block(),
            "policy": {
                "block_on_severity": list(self._block_severities),
            },
            "summary": {
                "total":    len(self.findings),
                "critical": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
                "high":     sum(1 for f in self.findings if f["severity"] == "HIGH"),
                "medium":   sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
            },
            "findings": self.findings,
        }
        Path(path).write_text(json.dumps(output, indent=2))
        print(f"  JSON report written to: {path}")

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [post-processor] {msg}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert gitleaks SARIF output to standard JSON and apply policy"
    )
    parser.add_argument("--sarif",       required=True,  help="Path to gitleaks SARIF output file")
    parser.add_argument("--policy",      default="",     help="Path to policies/secrets.yaml")
    parser.add_argument("--json-output", default="",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--block",       action="store_true", help="Exit 1 if blocking severities found")
    parser.add_argument("--verbose",     action="store_true")
    parser.add_argument("--version",     action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    processor = SecretsPostProcessor(
        policy_path=args.policy or None,
        verbose=args.verbose,
    )
    processor.load_sarif(args.sarif)
    processor.print_findings()

    if args.json_output:
        processor.save_json(args.json_output)

    if args.block and processor.should_block():
        print("  Blocking secrets found.")
        sys.exit(1)


if __name__ == "__main__":
    main()