#!/usr/bin/env python3
"""
Allowed Dependencies Enforcer v1.0.0

Validates every dependency in a repository against the approved list
defined in policies/allowed-dependencies.yaml.

Supports: Go (go.mod), JavaScript/Node.js (package.json), Python (requirements.txt)

ENFORCEMENT FLOW:
  1. Detect language from lock/manifest files
  2. Parse all direct dependencies
  3. Check each against policies/allowed-dependencies.yaml
     a. Blocked  → always fails build
     b. Allowed  → passes
     c. requires_review → warns (configurable to block)
     d. Unknown  → fails build (default-deny)
  4. Print report + instructions
  5. Exit 1 if violations found
"""

import os
import sys
import json
import fnmatch
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# Policy loader
# ─────────────────────────────────────────────────────────────────────────────

class Policy:
    def __init__(self, policy_path: Path, verbose: bool = False):
        self._verbose = verbose
        self._raw: Dict = {}

        if not policy_path.exists():
            self._die(f"Policy file not found: {policy_path}\n"
                      f"Expected: policies/allowed-dependencies.yaml in the guardrails repo.")

        if not YAML_AVAILABLE:
            self._die("PyYAML not installed. Run: pip install pyyaml")

        try:
            with open(policy_path, "r") as f:
                self._raw = yaml.safe_load(f) or {}
            self._log(f"Policy loaded from: {policy_path}")
        except yaml.YAMLError as e:
            self._die(f"YAML parse error in policy file: {e}")

    def lang(self, language: str) -> Dict:
        return self._raw.get("allowed_dependencies", {}).get(language, {})

    def allowed(self, language: str) -> List[str]:
        return self.lang(language).get("allowed", [])

    def blocked(self, language: str) -> List[Dict]:
        raw = self.lang(language).get("blocked", [])
        # Normalise — entries may be plain strings or dicts with reason
        result = []
        for item in raw:
            if isinstance(item, str):
                result.append({"package": item, "reason": "Blocked by policy"})
            elif isinstance(item, dict):
                result.append({"package": item.get("package", ""), "reason": item.get("reason", "Blocked by policy")})
        return result

    def requires_review(self, language: str) -> List[str]:
        return self.lang(language).get("requires_review", [])

    @property
    def block_on_unapproved(self) -> bool:
        return self._enforcement.get("block_on_unapproved", True)

    @property
    def block_on_blocked(self) -> bool:
        return self._enforcement.get("block_on_blocked", True)

    @property
    def block_on_requires_review(self) -> bool:
        return self._enforcement.get("block_on_requires_review", False)

    @property
    def check_transitive(self) -> bool:
        return self._enforcement.get("check_transitive", False)

    @property
    def _enforcement(self) -> Dict:
        return self._raw.get("enforcement", {})

    def _log(self, msg: str):
        if self._verbose:
            print(f"  [policy] {msg}")

    @staticmethod
    def _die(msg: str):
        print(f"\n  ERROR: {msg}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Dependency parsers
# ─────────────────────────────────────────────────────────────────────────────

def parse_go_mod(repo_path: Path) -> List[Dict]:
    """Parse direct dependencies from go.mod"""
    deps = []
    go_mod = repo_path / "go.mod"
    if not go_mod.exists():
        return deps

    in_require = False
    try:
        for line in go_mod.read_text().splitlines():
            stripped = line.strip()

            if stripped == "require (":
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue

            # Single-line require
            if stripped.startswith("require ") and "(" not in stripped:
                parts = stripped.replace("require ", "").split()
                if len(parts) >= 2:
                    deps.append({"name": parts[0], "version": parts[1], "language": "go", "source": "direct"})
                continue

            # Inside require block
            if in_require and stripped and not stripped.startswith("//"):
                parts = stripped.split()
                if len(parts) >= 2 and not parts[0].startswith("//"):
                    # Skip indirect if transitive checking is off
                    is_indirect = "// indirect" in line
                    deps.append({
                        "name": parts[0],
                        "version": parts[1],
                        "language": "go",
                        "source": "indirect" if is_indirect else "direct",
                    })
    except Exception as e:
        print(f"  ⚠ Error parsing go.mod: {e}")

    return deps


def parse_package_json(repo_path: Path) -> List[Dict]:
    """Parse dependencies from package.json"""
    deps = []
    pkg_json = repo_path / "package.json"
    if not pkg_json.exists():
        return deps

    try:
        data = json.loads(pkg_json.read_text())
        for dep_type in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in data.get(dep_type, {}).items():
                deps.append({"name": name, "version": version, "language": "js", "source": dep_type})
    except Exception as e:
        print(f"  ⚠ Error parsing package.json: {e}")

    return deps


def parse_requirements_txt(repo_path: Path) -> List[Dict]:
    """Parse dependencies from requirements.txt"""
    deps = []
    req_file = repo_path / "requirements.txt"
    if not req_file.exists():
        return deps

    try:
        for line in req_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-r"):
                continue

            # Strip extras e.g. requests[security]
            name_part = line.split("[")[0]

            for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
                if sep in name_part:
                    name, version = name_part.split(sep, 1)
                    deps.append({"name": name.strip(), "version": version.strip(), "language": "python", "source": "direct"})
                    break
            else:
                deps.append({"name": name_part.strip(), "version": "unspecified", "language": "python", "source": "direct"})
    except Exception as e:
        print(f"  ⚠ Error parsing requirements.txt: {e}")

    return deps


# ─────────────────────────────────────────────────────────────────────────────
# Validator
# ─────────────────────────────────────────────────────────────────────────────

class Violation:
    def __init__(self, kind: str, dep: Dict, reason: str = "", suggestion: str = ""):
        self.kind       = kind        # "blocked" | "unapproved" | "requires_review"
        self.dep        = dep
        self.reason     = reason
        self.suggestion = suggestion

    @property
    def name(self) -> str:
        return self.dep["name"]

    @property
    def language(self) -> str:
        return self.dep["language"]

    @property
    def version(self) -> str:
        return self.dep.get("version", "unknown")


def _matches(name: str, pattern: str) -> bool:
    """Match a package name against an allowed/blocked pattern (supports fnmatch globs)."""
    return fnmatch.fnmatch(name, pattern) or name == pattern or name.startswith(pattern + "/")


def validate(dep: Dict, policy: Policy) -> Optional[Violation]:
    language = dep["language"]
    name     = dep["name"]

    # 1. Check blocked first (highest priority)
    for entry in policy.blocked(language):
        if _matches(name, entry["package"]):
            return Violation("blocked", dep, reason=entry["reason"])

    # 2. Check allowed list
    for pattern in policy.allowed(language):
        if _matches(name, pattern):
            return None  # ✓ approved

    # 3. Check requires_review
    for pattern in policy.requires_review(language):
        if _matches(name, pattern):
            return Violation("requires_review", dep, reason="Requires security review before use")

    # 4. Not in any list → unapproved
    return Violation("unapproved", dep)


# ─────────────────────────────────────────────────────────────────────────────
# Report & approval instructions
# ─────────────────────────────────────────────────────────────────────────────

APPROVAL_INSTRUCTIONS = """
  HOW TO GET A PACKAGE APPROVED
  ─────────────────────────────────────────────────────────────────────
  1. Open a PR in the security-guardrails repo
  2. Edit  policies/allowed-dependencies.yaml
  3. Add the package under the correct language → allowed list
  4. Get approval from the security team
  5. Merge the PR — the build will then pass automatically

  No Slack. No Jira. No tribal knowledge.
  ─────────────────────────────────────────────────────────────────────
"""


def print_report(
    violations: List[Violation],
    policy: Policy,
    total_checked: int,
) -> bool:
    """Print the violation report. Returns True if build should be blocked."""

    blocked_vs      = [v for v in violations if v.kind == "blocked"]
    unapproved_vs   = [v for v in violations if v.kind == "unapproved"]
    review_vs       = [v for v in violations if v.kind == "requires_review"]

    should_block = (
        (blocked_vs   and policy.block_on_blocked) or
        (unapproved_vs and policy.block_on_unapproved) or
        (review_vs     and policy.block_on_requires_review)
    )

    if not violations:
        print(f"\n  ✅  ALL {total_checked} DEPENDENCIES ARE APPROVED")
        return False

    print("\n" + "═" * 66)
    print("  ALLOWED DEPENDENCIES ENFORCER — VIOLATIONS FOUND")
    print("═" * 66)
    print(f"\n  Checked {total_checked} dependenc{'y' if total_checked == 1 else 'ies'}  |  "
          f"{len(violations)} violation{'s' if len(violations) != 1 else ''} found")

    # ── BLOCKED ──────────────────────────────────────────────────────
    if blocked_vs:
        print(f"\n  🚫  BLOCKED PACKAGES  ({len(blocked_vs)})  — must be removed")
        print("  " + "─" * 62)
        for v in blocked_vs:
            print(f"\n    ✗  {v.name}  ({v.language})  {v.version}")
            print(f"       Reason: {v.reason}")

    # ── UNAPPROVED ───────────────────────────────────────────────────
    if unapproved_vs:
        print(f"\n  ⛔  UNAPPROVED PACKAGES  ({len(unapproved_vs)})  — not in allowed list")
        print("  " + "─" * 62)
        for v in unapproved_vs:
            print(f"\n    ✗  {v.name}  ({v.language})  {v.version}")
            if v.dep.get("source") == "indirect":
                print("       Note: Transitive dependency — consider pinning or excluding")

    # ── REQUIRES REVIEW ──────────────────────────────────────────────
    if review_vs:
        icon = "🚫" if policy.block_on_requires_review else "⚠️ "
        label = "BLOCKED — REQUIRES REVIEW" if policy.block_on_requires_review else "REQUIRES REVIEW (warning)"
        print(f"\n  {icon}  {label}  ({len(review_vs)})")
        print("  " + "─" * 62)
        for v in review_vs:
            print(f"\n    {'✗' if policy.block_on_requires_review else '!'}"
                  f"  {v.name}  ({v.language})  {v.version}")
            print(f"       {v.reason}")

    # ── Approval instructions ─────────────────────────────────────────
    if unapproved_vs or review_vs:
        print(APPROVAL_INSTRUCTIONS)

    # ── Result banner ─────────────────────────────────────────────────
    print("─" * 66)
    if should_block:
        print("  Result: BUILD BLOCKED ❌")
    else:
        print("  Result: WARNINGS ONLY — build continues ⚠️ ")
    print("═" * 66 + "\n")

    return should_block


# ─────────────────────────────────────────────────────────────────────────────
# JSON output
# ─────────────────────────────────────────────────────────────────────────────

def build_json_report(
    violations: List[Violation],
    total_checked: int,
    blocked: bool,
    policy: Policy,
) -> str:
    findings = []
    for v in violations:
        findings.append({
            "kind":     v.kind,
            "package":  v.name,
            "language": v.language,
            "version":  v.version,
            "source":   v.dep.get("source", "direct"),
            "reason":   v.reason,
        })

    return json.dumps({
        "version":        VERSION,
        "blocked":        blocked,
        "total_checked":  total_checked,
        "total_violations": len(violations),
        "policy": {
            "block_on_unapproved":        policy.block_on_unapproved,
            "block_on_blocked":           policy.block_on_blocked,
            "block_on_requires_review":   policy.block_on_requires_review,
        },
        "findings": findings,
    }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Allowed Dependencies Enforcer v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  All dependencies approved (or only warnings)
  1  Unapproved / blocked dependencies found
""",
    )
    parser.add_argument("--repo",        default=".",  help="Path to repo to scan (default: .)")
    parser.add_argument("--policy",      default="",   help="Path to allowed-dependencies.yaml (auto-detected if omitted)")
    parser.add_argument("--json-output", default="",   metavar="FILE", help="Write JSON results to FILE")
    parser.add_argument("--verbose",     action="store_true")
    parser.add_argument("--version",     action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    repo_path = Path(args.repo).resolve()

    # Resolve policy
    if args.policy:
        policy_path = Path(args.policy)
    else:
        # Default: relative to this script's guardrails repo
        policy_path = Path(__file__).parent.parent / "policies" / "allowed-dependencies.yaml"

    print("\n  ALLOWED DEPENDENCIES ENFORCER")
    print("  " + "═" * 60)
    print(f"  Repo   : {repo_path}")
    print(f"  Policy : {policy_path}")

    policy = Policy(policy_path, verbose=args.verbose)

    # ── Detect & parse dependencies ───────────────────────────────────
    all_deps: List[Dict] = []

    go_deps = parse_go_mod(repo_path)
    if go_deps:
        direct = [d for d in go_deps if d["source"] == "direct"]
        indirect = [d for d in go_deps if d["source"] == "indirect"]
        print(f"\n  Go      : {len(direct)} direct, {len(indirect)} indirect  (go.mod)")
        if policy.check_transitive:
            all_deps.extend(go_deps)
        else:
            all_deps.extend(direct)

    js_deps = parse_package_json(repo_path)
    if js_deps:
        print(f"  JS/Node : {len(js_deps)} packages  (package.json)")
        all_deps.extend(js_deps)

    py_deps = parse_requirements_txt(repo_path)
    if py_deps:
        print(f"  Python  : {len(py_deps)} packages  (requirements.txt)")
        all_deps.extend(py_deps)

    if not all_deps:
        print("\n  No dependency files found (go.mod, package.json, requirements.txt).")
        print("  Nothing to check.\n")
        sys.exit(0)

    print(f"\n  Total to check: {len(all_deps)} dependenc{'y' if len(all_deps) == 1 else 'ies'}")

    # ── Validate each dependency ──────────────────────────────────────
    violations: List[Violation] = []
    for dep in all_deps:
        v = validate(dep, policy)
        if v is not None:
            violations.append(v)
            if args.verbose:
                print(f"  [validate] ✗ {dep['name']} ({dep['language']}) → {v.kind}")
        else:
            if args.verbose:
                print(f"  [validate] ✓ {dep['name']} ({dep['language']})")

    # ── Print report ──────────────────────────────────────────────────
    should_block = print_report(violations, policy, total_checked=len(all_deps))

    # ── JSON output ───────────────────────────────────────────────────
    if args.json_output:
        report_json = build_json_report(violations, len(all_deps), should_block, policy)
        out_path = Path(args.json_output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report_json)
        print(f"  JSON report written to: {args.json_output}")

    sys.exit(1 if should_block else 0)


if __name__ == "__main__":
    main()