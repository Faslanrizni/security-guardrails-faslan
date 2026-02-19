#!/usr/bin/env python3
"""
Secrets Scanner v1.0.0
Enterprise-grade secret detection using pattern matching + entropy analysis.
Outputs structured JSON for CI/CD integration.
"""

import re
import sys
import json
import math
import argparse
from pathlib import Path
from typing import List, Dict, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# Default config (overridden by policies/secrets.yaml if present)
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build",
    "__pycache__", ".venv", ".idea", ".vscode", "vendor", ""
}

DEFAULT_SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "composer.lock","go.sum","go.mod", 
}

DEFAULT_FILE_PATTERNS = [
    "*.py", "*.js", "*.ts", "*.env", "*.json",
    "*.yaml", "*.yml", "*.conf", "*.ini",
    "*.java", "*.go", "*.rb", "*.php", "Dockerfile",
]

FALSE_POSITIVE_KEYWORDS = {
    "example", "sample", "test", "mock", "dummy",
    "fake", "placeholder", "changeme", "ispublic", "public",
}

SECRET_PATTERNS = {
    "aws_access_key":    (r"\bAKIA[0-9A-Z]{16}\b",                                    "CRITICAL"),
    "aws_secret_key":    (r"\b[A-Za-z0-9/+=]{40}\b",                                  "HIGH"),
    "github_pat":        (r"\bgithub_pat_[A-Za-z0-9_]{80,}\b",                        "CRITICAL"),
    "github_token":      (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",                          "CRITICAL"),
    "gcp_api_key":       (r"\bAIza[0-9A-Za-z\-_]{35}\b",                              "HIGH"),
    "google_oauth":      (r"\bya29\.[0-9A-Za-z\-_]+\b",                               "HIGH"),
    "stripe_secret":     (r"\bsk_(live|test)_[0-9A-Za-z]{24,}\b",                     "CRITICAL"),
    "slack_token":       (r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",                       "HIGH"),
    "jwt_token":         (r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "HIGH"),
    "bearer_token":      (r"Bearer\s+([A-Za-z0-9\-._~+/]{40,2000})",                  "HIGH"),
    "azure_storage":     (r"AccountKey=[A-Za-z0-9+/=]{88}",                           "CRITICAL"),
    "firebase_key":      (r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b",            "HIGH"),
    "db_connection":     (r"(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@",         "CRITICAL"),
    "env_secret":        (r"(SECRET|TOKEN|KEY|PASSWORD|PWD)\s*[=:]\s*[\"'][^\"']{8,}[\"']", "HIGH"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class SecretsScanner:

    def __init__(self, repo_path: str = ".", policy_path: Optional[str] = None, verbose: bool = False):
        self.repo_path = Path(repo_path).resolve()
        self.verbose   = verbose
        self.findings: List[Dict] = []

        self._policy   = self._load_policy(policy_path)
        self.skip_dirs      = DEFAULT_SKIP_DIRS
        self.skip_files     = DEFAULT_SKIP_FILES
        self.file_patterns  = DEFAULT_FILE_PATTERNS

        self._private_key_re = re.compile(
            r"-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----"
        )

    # ── policy ────────────────────────────────────────────────────────────────

    def _load_policy(self, policy_path: Optional[str]) -> Dict:
        if not policy_path:
            # Auto-detect: look for policies/secrets.yaml relative to this script
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
        return {}

    @property
    def _block_severities(self) -> set:
        # Which severities cause a CI block — from policy or default HIGH+CRITICAL
        configured = self._policy.get("block_on_severity", ["HIGH", "CRITICAL"])
        return set(configured)

    # ── entropy ───────────────────────────────────────────────────────────────

    @staticmethod
    def _entropy(data: str) -> float:
        if not data:
            return 0.0
        result = 0.0
        for char in set(data):
            p = data.count(char) / len(data)
            result -= p * math.log2(p)
        return result

    def _is_high_entropy(self, token: str) -> bool:
        if len(token) < 20:
            return False
        if not re.fullmatch(r"[A-Za-z0-9+/=]{20,}", token):
            return False
        return self._entropy(token) >= 4.5

    # ── false positive filtering ──────────────────────────────────────────────

    def _is_false_positive(self, line: str, value: str) -> bool:
        line_lower  = line.lower()
        value_lower = value.lower()
        for keyword in FALSE_POSITIVE_KEYWORDS:
            if keyword in line_lower or keyword in value_lower:
                return True
        # Pure git SHA — 40 hex chars is not a secret
        if re.fullmatch(r"[a-f0-9]{40}", value):
            return True
        return False

    def _valid_bearer(self, token: str) -> bool:
        return len(token) >= 40 and self._entropy(token) >= 3.5

    # ── file discovery ────────────────────────────────────────────────────────

    def _get_files(self) -> List[Path]:
        files = []
        for pattern in self.file_patterns:
            for f in self.repo_path.glob(f"**/{pattern}"):
                if any(skip in f.parts for skip in self.skip_dirs):
                    continue
                if f.name in self.skip_files:
                    continue
                files.append(f)
        return files

    # ── scan ─────────────────────────────────────────────────────────────────

    def _add_finding(self, file: Path, line: int, type_: str, match: str, severity: str):
        self.findings.append({
            "file":     str(file.relative_to(self.repo_path)),
            "line":     line,
            "type":     type_,
            "severity": severity,
            "match":    match[:60] + ("..." if len(match) > 60 else ""),
        })

    def _scan_file(self, file: Path):
        try:
            content = file.read_text(errors="ignore")
            lines   = content.splitlines()

            # Multiline private key detection
            if self._private_key_re.search(content):
                self._add_finding(file, 0, "private_key", "PRIVATE KEY BLOCK", "CRITICAL")

            for line_num, line in enumerate(lines, 1):
                # Pattern-based detection
                for name, (pattern, severity) in SECRET_PATTERNS.items():
                    for match in re.finditer(pattern, line):
                        value = match.group(1) if match.groups() else match.group(0)
                        if name == "bearer_token" and not self._valid_bearer(value):
                            continue
                        if self._is_false_positive(line, value):
                            continue
                        self._add_finding(file, line_num, name, value, severity)

                # Entropy-based detection
                for token in re.findall(r"[A-Za-z0-9+/=]{20,}", line):
                    if self._is_high_entropy(token):
                        if not self._is_false_positive(line, token):
                            self._add_finding(file, line_num, "high_entropy_secret", token, "MEDIUM")

        except Exception:
            pass

    def scan(self) -> List[Dict]:
        print(f"🔍  Scanning: {self.repo_path}")
        files = self._get_files()
        self._log(f"Files to scan: {len(files)}")
        for f in files:
            self._log(f"  scanning {f.relative_to(self.repo_path)}")
            self._scan_file(f)
        return self.findings

    # ── output ────────────────────────────────────────────────────────────────

    def print_findings(self):
        if not self.findings:
            print("\n  No secrets found.")
            return

        critical = [f for f in self.findings if f["severity"] == "CRITICAL"]
        high     = [f for f in self.findings if f["severity"] == "HIGH"]
        medium   = [f for f in self.findings if f["severity"] == "MEDIUM"]

        print(f"\n{'═' * 62}")
        print(f"  SECRETS SCAN REPORT — {len(self.findings)} finding(s)")
        print(f"{'═' * 62}")

        for group, label in [(critical, " CRITICAL"), (high, " HIGH"), (medium, "MEDIUM")]:
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
            "version":  VERSION,
            "blocked":  self.should_block(),
            "summary": {
                "total":    len(self.findings),
                "critical": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
                "high":     sum(1 for f in self.findings if f["severity"] == "HIGH"),
                "medium":   sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
            },
            "findings": self.findings,
        }
        Path(path).write_text(json.dumps(output, indent=2))
        print(f"\n📄  JSON report written to: {path}")

    def should_block(self) -> bool:
        return any(f["severity"] in self._block_severities for f in self.findings)

    def _log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scan repository for leaked secrets")
    parser.add_argument("--repo-path",   default=".",  help="Path to repository")
    parser.add_argument("--policy",      default="",   help="Path to policies/secrets.yaml")
    parser.add_argument("--json-output", default="",   metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--block",       action="store_true", help="Exit 1 if HIGH/CRITICAL secrets found")
    parser.add_argument("--verbose",     action="store_true")
    parser.add_argument("--version",     action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    scanner = SecretsScanner(
        repo_path=args.repo_path,
        policy_path=args.policy or None,
        verbose=args.verbose,
    )
    scanner.scan()
    scanner.print_findings()

    if args.json_output:
        scanner.save_json(args.json_output)

    if args.block and scanner.should_block():
        print("  Secrets detected — blocking.")
        sys.exit(1)


if __name__ == "__main__":
    main()