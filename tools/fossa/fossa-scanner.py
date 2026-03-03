#!/usr/bin/env python3
"""
FOSSA Post-Processor v1.0.0

This script does NOT scan for license or vulnerability issues itself.
FOSSA CLI handles all detection via the FOSSA SaaS platform.

This script:
  1. Reads the `fossa test --json` output
  2. Converts it to our standard JSON format
  3. Applies severity mapping from policies/fossa.yaml
  4. Exits 1 if blocking severities are present

Supports FOSSA CLI v3 JSON output format.
"""

import re
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

VERSION = "1.0.0"

# CVSS score → severity band mapping
# Used when FOSSA returns a numeric CVSS score without a named severity
CVSS_SEVERITY_MAP = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.0, "LOW"),
]

# FOSSA license severity — mapped from blocked/requires_review lists in policy
# Fallback when no policy file is available
DEFAULT_BLOCKED_LICENSES = {
    "GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0", "BUSL-1.1", "Commons-Clause",
    "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
}

DEFAULT_REVIEW_LICENSES = {
    "LGPL-2.1", "LGPL-3.0", "CC-BY-SA-4.0", "EPL-2.0",
    "LGPL-2.1-only", "LGPL-3.0-only",
}

DEFAULT_BLOCK_SEVERITIES = {"CRITICAL", "HIGH"}


def cvss_to_severity(score: float) -> str:
    for threshold, label in CVSS_SEVERITY_MAP:
        if score >= threshold:
            return label
    return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Policy loader
# ─────────────────────────────────────────────────────────────────────────────

class Policy:
    def __init__(self, policy_path: Optional[str] = None, verbose: bool = False):
        self._verbose = verbose
        self._raw: Dict = {}

        if not policy_path:
            auto = Path(__file__).parent.parent.parent / "policies" / "fossa.yaml"
            if auto.exists():
                policy_path = str(auto)

        if policy_path and Path(policy_path).exists() and YAML_AVAILABLE:
            try:
                with open(policy_path) as f:
                    self._raw = yaml.safe_load(f) or {}
                self._log(f"Policy loaded: {policy_path}")
            except Exception as e:
                self._warn(f"Could not load policy: {e} — using defaults")
        else:
            self._warn("No policy file found — using defaults")

    @property
    def _fossa(self) -> Dict:
        return self._raw.get("fossa", {})

    @property
    def _licenses(self) -> Dict:
        return self._fossa.get("licenses", {})

    @property
    def _vulns(self) -> Dict:
        return self._fossa.get("vulnerabilities", {})

    @property
    def block_on_severity(self) -> set:
        configured = self._fossa.get("block_on_severity", ["HIGH", "CRITICAL"])
        return set(configured)

    @property
    def allowed_licenses(self) -> set:
        return set(self._licenses.get("allowed", []))

    @property
    def blocked_licenses(self) -> Dict[str, str]:
        """Returns {license_id: reason}"""
        raw = self._licenses.get("blocked", [])
        result = {}
        for entry in raw:
            if isinstance(entry, dict):
                result[entry.get("license", "")] = entry.get("reason", "Blocked by policy")
            elif isinstance(entry, str):
                result[entry] = "Blocked by policy"
        return result if result else {lic: "Blocked by policy" for lic in DEFAULT_BLOCKED_LICENSES}

    @property
    def review_licenses(self) -> Dict[str, str]:
        """Returns {license_id: reason}"""
        raw = self._licenses.get("requires_review", [])
        result = {}
        for entry in raw:
            if isinstance(entry, dict):
                result[entry.get("license", "")] = entry.get("reason", "Requires review")
            elif isinstance(entry, str):
                result[entry] = "Requires review"
        return result if result else {lic: "Requires review" for lic in DEFAULT_REVIEW_LICENSES}

    @property
    def block_on_requires_review(self) -> bool:
        return self._licenses.get("block_on_requires_review", False)

    @property
    def min_cvss_score(self) -> float:
        return float(self._vulns.get("min_cvss_score", 4.0))

    @property
    def fail_on_cvss_score(self) -> float:
        return float(self._vulns.get("fail_on_cvss_score", 7.0))

    @property
    def ignore_unfixable(self) -> bool:
        return bool(self._vulns.get("ignore_unfixable", False))

    def _log(self, msg: str):
        if self._verbose:
            print(f"  [policy] {msg}")

    def _warn(self, msg: str):
        print(f"  [policy] ⚠  {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# FOSSA output parser
# ─────────────────────────────────────────────────────────────────────────────

class FOSSAPostProcessor:

    def __init__(self, policy_path: Optional[str] = None, verbose: bool = False):
        self.verbose = verbose
        self.policy = Policy(policy_path, verbose=verbose)
        self.license_findings: List[Dict] = []
        self.vulnerability_findings: List[Dict] = []

    def load_fossa_output(self, fossa_output_path: str, test_exit_code: int = 0) -> bool:
        """
        Parse `fossa test --json` output.
        FOSSA CLI v3 outputs a JSON object with `issues` array when violations exist,
        or an empty response / exit 0 when clean.
        Returns True if any findings were loaded.
        """
        path = Path(fossa_output_path)

        if not path.exists() or path.stat().st_size == 0:
            self._log(f"FOSSA output file not found or empty: {fossa_output_path}")
            # If fossa test exited 1 but we have no JSON, record a generic finding
            if test_exit_code == 1:
                self._warn("FOSSA test reported violations but no JSON output — check FOSSA CLI logs")
            return False

        try:
            raw_text = path.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception as e:
            self._warn(f"Could not read FOSSA output: {e}")
            return False

        if not raw_text:
            self._log("FOSSA output file is empty — no issues found")
            return False

        # fossa test --json may produce NDJSON (one JSON object per line)
        # or a single JSON object. Handle both.
        data = self._parse_fossa_json(raw_text)
        if data is None:
            self._log("Could not parse FOSSA JSON output — treating as no findings")
            return False

        self._extract_findings(data)
        self._log(
            f"Loaded {len(self.license_findings)} license finding(s) and "
            f"{len(self.vulnerability_findings)} vulnerability finding(s)"
        )
        return bool(self.license_findings or self.vulnerability_findings)

    def _parse_fossa_json(self, raw_text: str) -> Optional[Any]:
        """Try to parse FOSSA JSON output in several formats."""
        # Try single JSON object first
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError:
            pass

        # Try NDJSON — take the last non-empty line that parses as JSON
        for line in reversed(raw_text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

        return None

    def _extract_findings(self, data: Any):
        """
        Extract license and vulnerability findings from FOSSA JSON.
        FOSSA CLI v3 `fossa test --json` returns:
          { "issues": [ { "type": "...", "rule": {...}, "dependency": {...} } ] }
        or a flat list of issues.
        """
        issues = []

        if isinstance(data, dict):
            issues = data.get("issues", data.get("violations", []))
        elif isinstance(data, list):
            issues = data

        for issue in issues:
            issue_type = issue.get("type", "").lower()

            if "license" in issue_type or "policy" in issue_type:
                self._process_license_issue(issue)
            elif "vuln" in issue_type or "cve" in issue_type or "security" in issue_type:
                self._process_vulnerability_issue(issue)
            else:
                # Unknown issue type — try to classify from content
                if issue.get("license") or issue.get("licenseId"):
                    self._process_license_issue(issue)
                else:
                    self._process_vulnerability_issue(issue)

    def _process_license_issue(self, issue: Dict):
        # Extract dependency name — FOSSA uses various key names
        dep = issue.get("dependency", issue.get("package", {}))
        if isinstance(dep, dict):
            dep_name = dep.get("name", dep.get("package", "unknown"))
            dep_version = dep.get("version", "")
        else:
            dep_name = str(dep) if dep else "unknown"
            dep_version = ""

        # Extract license
        rule = issue.get("rule", {})
        license_id = (
            issue.get("license") or
            issue.get("licenseId") or
            rule.get("licenseId") or
            rule.get("license") or
            "unknown"
        )
        # Normalise SPDX-style suffixes
        license_id = license_id.replace("-only", "").replace("-or-later", "+")

        # Map to severity via policy
        blocked = self.policy.blocked_licenses
        review  = self.policy.review_licenses

        if license_id in blocked:
            severity = "CRITICAL"
            reason   = blocked[license_id]
        elif any(license_id.startswith(b.rstrip("+")) for b in blocked):
            severity = "CRITICAL"
            reason   = "Blocked license variant"
        elif license_id in review:
            severity = "MEDIUM" if not self.policy.block_on_requires_review else "HIGH"
            reason   = review[license_id]
        elif any(license_id.startswith(r.rstrip("+")) for r in review):
            severity = "MEDIUM"
            reason   = "License requires review"
        else:
            severity = "LOW"
            reason   = issue.get("message", "Unlisted license — flagged for review")

        finding = {
            "dependency": f"{dep_name}@{dep_version}" if dep_version else dep_name,
            "license":    license_id,
            "severity":   severity,
            "reason":     reason,
            "type":       "license",
        }
        self.license_findings.append(finding)
        self._log(f"  [license] {finding['dependency']} — {license_id} — {severity}")

    def _process_vulnerability_issue(self, issue: Dict):
        dep = issue.get("dependency", issue.get("package", {}))
        if isinstance(dep, dict):
            dep_name    = dep.get("name", dep.get("package", "unknown"))
            dep_version = dep.get("version", "")
        else:
            dep_name    = str(dep) if dep else "unknown"
            dep_version = ""

        rule = issue.get("rule", {})

        # CVE / vuln ID
        vuln_id = (
            issue.get("cve") or
            issue.get("vulnId") or
            rule.get("cveId") or
            issue.get("id") or
            "unknown"
        )

        # Severity — prefer named severity, fall back to CVSS
        severity_raw = (
            issue.get("severity") or
            rule.get("severity") or
            issue.get("criticalityScore") or
            ""
        )
        if isinstance(severity_raw, str) and severity_raw.upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            severity = severity_raw.upper()
        else:
            cvss = float(issue.get("cvssScore", issue.get("cvss", 0.0)) or 0.0)
            severity = cvss_to_severity(cvss)

        # Skip if below minimum threshold
        cvss = float(issue.get("cvssScore", issue.get("cvss", 0.0)) or 0.0)
        if cvss > 0 and cvss < self.policy.min_cvss_score:
            self._log(f"  [vuln] skipping {vuln_id} (CVSS {cvss} below min {self.policy.min_cvss_score})")
            return

        # Skip unfixable if policy says so
        fixed_in = issue.get("fixedIn", issue.get("fix", ""))
        if self.policy.ignore_unfixable and not fixed_in:
            self._log(f"  [vuln] skipping {vuln_id} (no fix available, ignore_unfixable=true)")
            return

        finding = {
            "dependency": f"{dep_name}@{dep_version}" if dep_version else dep_name,
            "vuln_id":    vuln_id,
            "cve":        vuln_id if vuln_id.startswith("CVE-") else "",
            "severity":   severity,
            "cvss":       cvss,
            "fixed_in":   fixed_in,
            "type":       "vulnerability",
        }
        self.vulnerability_findings.append(finding)
        self._log(f"  [vuln] {finding['dependency']} — {vuln_id} — {severity}")

    # ── Aggregation ───────────────────────────────────────────────────────────

    @property
    def all_findings(self) -> List[Dict]:
        return self.license_findings + self.vulnerability_findings

    def should_block(self) -> bool:
        return any(
            f["severity"] in self.policy.block_on_severity
            for f in self.all_findings
        )

    def summary(self) -> Dict[str, int]:
        all_f = self.all_findings
        return {
            "total":    len(all_f),
            "critical": sum(1 for f in all_f if f["severity"] == "CRITICAL"),
            "high":     sum(1 for f in all_f if f["severity"] == "HIGH"),
            "medium":   sum(1 for f in all_f if f["severity"] == "MEDIUM"),
            "low":      sum(1 for f in all_f if f["severity"] == "LOW"),
        }

    # ── Output ────────────────────────────────────────────────────────────────

    def print_findings(self):
        s = self.summary()

        if not self.all_findings:
            print("\n  ✅ No FOSSA license or vulnerability issues found.")
            return

        print(f"\n{'═' * 66}")
        print(f"  FOSSA SCAN REPORT")
        print(f"  Block severities: {', '.join(sorted(self.policy.block_on_severity))}")
        print(f"{'═' * 66}")
        print(f"\n  Total: {s['total']}  |  "
              f"Critical: {s['critical']}  High: {s['high']}  "
              f"Medium: {s['medium']}  Low: {s['low']}")

        if self.license_findings:
            print(f"\n  LICENSE ISSUES ({len(self.license_findings)})")
            print("  " + "─" * 60)
            for group_sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                group = [f for f in self.license_findings if f["severity"] == group_sev]
                if group:
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}.get(group_sev, "")
                    print(f"\n  {icon} {group_sev} ({len(group)})")
                    for f in group:
                        print(f"    {f['dependency']}  [{f['license']}]")
                        if f.get("reason"):
                            print(f"      → {f['reason']}")

        if self.vulnerability_findings:
            print(f"\n  VULNERABILITY ISSUES ({len(self.vulnerability_findings)})")
            print("  " + "─" * 60)
            for group_sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                group = [f for f in self.vulnerability_findings if f["severity"] == group_sev]
                if group:
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}.get(group_sev, "")
                    print(f"\n  {icon} {group_sev} ({len(group)})")
                    for f in group:
                        fix_info = f"  · fix: {f['fixed_in']}" if f.get("fixed_in") else "  · no fix available"
                        print(f"    {f['dependency']}  [{f['vuln_id']}]{fix_info}")

        status = "BLOCKED" if self.should_block() else "FLAGGED FOR REVIEW"
        print(f"\n{'─' * 66}")
        print(f"  Result: {status}")
        print(f"{'═' * 66}\n")

    def save_json(self, path: str):
        output = {
            "version": VERSION,
            "blocked": self.should_block(),
            "policy": {
                "block_on_severity":       list(self.policy.block_on_severity),
                "block_on_requires_review": self.policy.block_on_requires_review,
                "min_cvss_score":          self.policy.min_cvss_score,
                "fail_on_cvss_score":      self.policy.fail_on_cvss_score,
            },
            "summary":                 self.summary(),
            "license_findings":        self.license_findings,
            "vulnerability_findings":  self.vulnerability_findings,
        }
        Path(path).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"  JSON report written to: {path}")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [fossa] {msg}")

    def _warn(self, msg: str):
        print(f"  [fossa] ⚠  {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"FOSSA Post-Processor v{VERSION} — convert FOSSA output to standard JSON and apply policy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  No blocking findings (or only warnings)
  1  Blocking license / vulnerability findings found

Examples:
  python fossa-scanner.py \\
    --fossa-output fossa-test-output.json \\
    --policy policies/fossa.yaml \\
    --json-output fossa-scan-results.json \\
    --verbose
""",
    )
    parser.add_argument("--fossa-output",  required=True,  help="Path to `fossa test --json` output file")
    parser.add_argument("--policy",        default="",     help="Path to policies/fossa.yaml")
    parser.add_argument("--json-output",   default="",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--test-exit",     default="0",    help="Exit code returned by `fossa test`")
    parser.add_argument("--block",         action="store_true", help="Exit 1 if blocking severities found")
    parser.add_argument("--verbose",       action="store_true")
    parser.add_argument("--version",       action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    try:
        test_exit = int(args.test_exit)
    except ValueError:
        test_exit = 0

    processor = FOSSAPostProcessor(
        policy_path=args.policy or None,
        verbose=args.verbose,
    )

    processor.load_fossa_output(args.fossa_output, test_exit_code=test_exit)
    processor.print_findings()

    if args.json_output:
        processor.save_json(args.json_output)

    # Block if policy says so OR if `fossa test` itself reported violations
    # and no JSON was parseable (CLI still indicated a problem)
    should_block = processor.should_block() or (
        test_exit == 1 and not processor.all_findings
    )

    if should_block:
        print("  🚫 Blocking FOSSA findings found.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()