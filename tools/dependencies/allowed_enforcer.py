#!/usr/bin/env python3
"""
Allowed Dependencies Enforcer
Checks every dependency against allowed-dependencies.yaml
Blocks build if unapproved package found

POLICY LOCATION: policies/allowed-dependencies.yaml  (in guardrails repo)
ENFORCER      : tools/dependencies/allowed-deps-enforcer.py
"""

import os
import sys
import json
import yaml
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import argparse
import fnmatch


class AllowedDependenciesEnforcer:
    """
    Enforces that only approved dependencies can be used.

    POLICY RESOLUTION (same pattern as ai-code-detector.py):
      1. Explicit --policy flag  <- CI always passes this from guardrails repo
      2. policies/allowed-dependencies.yaml in the product repo
      3. policies/allowed-dependencies.yaml relative to this script (guardrails fallback)
    """

    def __init__(self, repo_path: str = ".", policy_path: str = ""):
        self.repo_path = Path(repo_path).resolve()

        if policy_path:
            self.policy_file = Path(policy_path).resolve()
        elif (self.repo_path / 'policies' / 'allowed-dependencies.yaml').exists():
            self.policy_file = self.repo_path / 'policies' / 'allowed-dependencies.yaml'
        else:
            # Script lives at tools/dependencies/ -> go up 2 levels to repo root
            self.policy_file = Path(__file__).parent.parent.parent / 'policies' / 'allowed-dependencies.yaml'

        self.violations = []
        self.ai_detected = False
        self.policy = self._load_policy()

    def _load_policy(self) -> Dict:
        if not self.policy_file.exists():
            print(f"  Policy file not found: {self.policy_file}")
            print("  Pass the guardrails policy with --policy guardrails/policies/allowed-dependencies.yaml")
            sys.exit(1)
        try:
            with open(self.policy_file, 'r') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"  Error parsing policy YAML: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"  Error reading policy file: {e}")
            sys.exit(1)

    # ── Main ────────────────────────────────────────────────────────────────

    def enforce(self) -> bool:
        print("\n  ALLOWED DEPENDENCIES ENFORCER")
        print("=" * 60)
        print(f"  Repo   : {self.repo_path}")
        print(f"  Policy : {self.policy_file}")

        deps = self._detect_dependencies()

        if not deps:
            print("  No dependency files found (package.json / go.mod / requirements.txt)")
            return True

        print(f"\n  Found {len(deps)} dependencies to check")

        for dep in deps:
            self._validate_dependency(dep)

        self._print_report()
        return len(self.violations) == 0

    # ── Detection ───────────────────────────────────────────────────────────

    def _detect_dependencies(self) -> List[Dict]:
        dependencies = []

        if (self.repo_path / 'package.json').exists():
            deps = self._parse_npm_deps()
            for dep in deps:
                dep['language'] = 'js'
            dependencies.extend(deps)

        if (self.repo_path / 'go.mod').exists():
            deps = self._parse_go_deps()
            for dep in deps:
                dep['language'] = 'go'
            dependencies.extend(deps)

        if (self.repo_path / 'requirements.txt').exists():
            deps = self._parse_python_deps()
            for dep in deps:
                dep['language'] = 'python'
            dependencies.extend(deps)

        return dependencies

    def _parse_npm_deps(self) -> List[Dict]:
        deps = []
        try:
            with open(self.repo_path / 'package.json') as f:
                data = json.load(f)
            all_deps = {}
            all_deps.update(data.get('dependencies', {}))
            all_deps.update(data.get('devDependencies', {}))
            for name, version in all_deps.items():
                deps.append({'name': name, 'version': version, 'source': 'package.json'})
            lock_file = self.repo_path / 'package-lock.json'
            if lock_file.exists():
                with open(lock_file) as f:
                    lock_data = json.load(f)
                for pkg_path, pkg_info in lock_data.get('packages', {}).items():
                    if pkg_path:
                        name = pkg_path.split('node_modules/')[-1]
                        if name and name not in [d['name'] for d in deps]:
                            deps.append({'name': name, 'version': pkg_info.get('version', 'unknown'), 'source': 'transitive'})
        except Exception as e:
            print(f"  Error parsing package.json: {e}")
        return deps

    def _parse_go_deps(self) -> List[Dict]:
        deps = []
        try:
            in_require_block = False
            with open(self.repo_path / 'go.mod') as f:
                for line in f:
                    line = line.strip()
                    if line == 'require (':
                        in_require_block = True
                        continue
                    if line == ')':
                        in_require_block = False
                        continue
                    if line.startswith('require ') and '(' not in line:
                        parts = line.replace('require ', '').split()
                        if len(parts) >= 2:
                            deps.append({'name': parts[0], 'version': parts[1], 'source': 'direct'})
                    elif in_require_block and line and not line.startswith('//'):
                        parts = line.split()
                        if len(parts) >= 2:
                            deps.append({'name': parts[0], 'version': parts[1], 'source': 'direct'})
        except Exception as e:
            print(f"  Error parsing go.mod: {e}")
        return deps

    def _parse_python_deps(self) -> List[Dict]:
        deps = []
        try:
            with open(self.repo_path / 'requirements.txt') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '==' in line:
                            name, version = line.split('==', 1)
                        elif '>=' in line:
                            name, version = line.split('>=', 1)
                        else:
                            name, version = line, 'latest'
                        deps.append({'name': name.strip(), 'version': version.strip(), 'source': 'direct'})
        except Exception as e:
            print(f"  Error parsing requirements.txt: {e}")
        return deps

    # ── Validation ──────────────────────────────────────────────────────────

    def _validate_dependency(self, dep: Dict):
        language = dep.get('language')
        name = dep.get('name')
        if not language or not name:
            return

        lang_policy     = self.policy.get(language, {})
        allowed         = lang_policy.get('allowed', [])
        blocked         = lang_policy.get('blocked', [])
        requires_review = lang_policy.get('requires_review', [])
        ai_policy           = self.policy.get('ai_code', {}).get('dependency_restrictions', {})
        ai_strict_mode      = ai_policy.get('strict_mode', False)
        ai_blocked_patterns = ai_policy.get('blocked_patterns', [])

        for pattern in blocked:
            if fnmatch.fnmatch(name, pattern):
                self.violations.append({
                    'type': 'blocked',
                    'dependency': name,
                    'language': language,
                    'reason': 'Package is explicitly blocked',
                    'details': self._get_block_reason(name)
                })
                return

        allowed_match = any(fnmatch.fnmatch(name, p) for p in allowed)

        if not allowed_match:
            violation = {
                'type': 'unapproved',
                'dependency': name,
                'language': language,
                'version': dep.get('version', 'unknown'),
                'source': dep.get('source', 'direct')
            }
            for pattern in requires_review:
                if fnmatch.fnmatch(name, pattern):
                    violation['requires_review'] = True
                    violation['reason'] = 'Package requires security review before use'
                    if self.ai_detected:
                        violation['reason'] += ' (AI-generated code — extra scrutiny required)'
                    break
            if self.ai_detected and ai_strict_mode:
                for pattern in ai_blocked_patterns:
                    if fnmatch.fnmatch(name, pattern):
                        violation['ai_blocked'] = True
                        violation['reason'] = f'Matches AI blocked pattern: {pattern}'
                        break
            self.violations.append(violation)

    def _get_block_reason(self, name: str) -> str:
        reasons = {
            'github.com/dgrijalva/jwt-go': 'Unmaintained — use github.com/golang-jwt/jwt',
            'github.com/gorilla/context':  'Deprecated — use stdlib context',
            'github.com/pkg/errors':       'Use native errors package (Go 1.13+)',
            'request':      'Deprecated — use axios or node-fetch',
            'left-pad':     'Trivial — use native String.padStart()',
            'colors.js':    'Supply chain attack history',
            'event-stream': 'Known backdoor incident (2018)',
            'pycrypto':     'Unmaintained — use pycryptodome',
            'pickle':       'Insecure deserialization — never use in production',
        }
        return reasons.get(name, 'Blocked by security policy — see policies/allowed-dependencies.yaml')

    # ── Report ──────────────────────────────────────────────────────────────

    def _print_report(self):
        if not self.violations:
            print("\n  ALL DEPENDENCIES APPROVED")
            return

        print("\n  DEPENDENCY VIOLATIONS FOUND")
        print("=" * 60)

        blocked    = [v for v in self.violations if v['type'] == 'blocked']
        unapproved = [v for v in self.violations if v['type'] == 'unapproved']

        if blocked:
            print(f"\n  BLOCKED PACKAGES ({len(blocked)})")
            print("  " + "-" * 40)
            for v in blocked:
                print(f"\n    {v['dependency']} ({v['language']})")
                print(f"      Reason : {v['details']}")

        if unapproved:
            print(f"\n  UNAPPROVED PACKAGES ({len(unapproved)})")
            print("  " + "-" * 40)
            for v in unapproved:
                print(f"\n    {v['dependency']} ({v['language']})  v{v['version']}")
                if v.get('requires_review'):
                    print(f"      Status : {v['reason']}")
                else:
                    print(f"      Status : Not in approved dependency list")

        print(f"\n  HOW TO GET A PACKAGE APPROVED:")
        print(f"  1. Add it under requires_review in policies/allowed-dependencies.yaml")
        print(f"  2. Open a PR: name, version, purpose, alternatives considered")
        print(f"  3. Security team reviews — SLA 5 business days")
        print(f"  4. On approval it moves to allowed[]")


# ── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Allowed Dependencies Guardrail Enforcer")
    parser.add_argument("--repo",   default=".",  help="Path to repository to scan")
    parser.add_argument("--policy", default="",   metavar="FILE",
                        help="Path to allowed-dependencies.yaml (auto-detected if omitted)")
    args = parser.parse_args()

    enforcer = AllowedDependenciesEnforcer(repo_path=args.repo, policy_path=args.policy)
    success = enforcer.enforce()

    if not success:
        print("\n  BUILD BLOCKED: Unapproved dependencies detected")
        sys.exit(1)
    else:
        print("\n  Guardrail check passed")
        sys.exit(0)