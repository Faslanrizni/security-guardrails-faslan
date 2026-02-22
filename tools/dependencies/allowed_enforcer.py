#!/usr/bin/env python3
"""
Allowed Dependencies Enforcer
Checks every new dependency against allowed-dependencies.yaml
Blocks build if unapproved package found

POLICY LOCATION: policies/allowed-dependencies.yaml
ENFORCER      : tools/security-guardrails/guardrails/dependencies/allowed-deps-enforcer.py
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

    ENFORCEMENT FLOW:
    1. Detect new/changed dependencies in PR
    2. Check against policies/allowed-dependencies.yaml
    3. If not allowed → Build fails
    4. Provide instructions for approval request
    """

    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path).resolve()

        # ── Policy file lives alongside all other policies ──────────────────
        self.policy_file = self.repo_path / 'policies' / 'allowed-dependencies.yaml'

        self.violations = []
        self.ai_detected = False

        # Load policy
        self.policy = self._load_policy()

    def _load_policy(self) -> Dict:
        """Load the allowed dependencies policy from policies/ directory"""
        if not self.policy_file.exists():
            print(f"  Policy file not found at: {self.policy_file}")
            print("  Expected location: policies/allowed-dependencies.yaml")
            print("")
            print("  To fix this:")
            print("  1. Create the policy file: policies/allowed-dependencies.yaml")
            print("  2. Follow the structure in the template")
            sys.exit(1)

        try:
            with open(self.policy_file, 'r') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"  Error parsing YAML policy file: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"  Error reading policy file: {e}")
            sys.exit(1)

    def enforce(self) -> bool:
        """
        Main enforcement method.
        Returns True if all dependencies are allowed, False otherwise.
        """
        print("\n  ALLOWED DEPENDENCIES ENFORCER")
        print("=" * 60)
        print(f"  Policy : {self.policy_file.relative_to(self.repo_path)}")

        # Step 1: Detect project language and dependencies
        deps = self._detect_dependencies()

        if not deps:
            print("  No dependencies found to check")
            return True

        print(f"\n  Found {len(deps)} dependencies to check")

        # Step 2: Validate each dependency
        for dep in deps:
            self._validate_dependency(dep)

        # Step 3: Report results
        self._print_report()

        return len(self.violations) == 0

    # ── Dependency detection ────────────────────────────────────────────────

    def _detect_dependencies(self) -> List[Dict]:
        """Detect project dependencies from manifest / lock files"""
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
                packages = lock_data.get('packages', {})
                for pkg_path, pkg_info in packages.items():
                    if pkg_path and pkg_path != '':
                        name = pkg_path.split('node_modules/')[-1]
                        if name and name not in [d['name'] for d in deps]:
                            deps.append({
                                'name': name,
                                'version': pkg_info.get('version', 'unknown'),
                                'source': 'transitive'
                            })
        except Exception as e:
            print(f"  Error parsing npm deps: {e}")
        return deps

    def _parse_go_deps(self) -> List[Dict]:
        deps = []
        try:
            with open(self.repo_path / 'go.mod') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(('module', 'go ', 'require (')):
                        parts = line.split()
                        if len(parts) >= 2:
                            deps.append({
                                'name': parts[0],
                                'version': parts[1],
                                'source': 'direct'
                            })
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
                        deps.append({
                            'name': name.strip(),
                            'version': version.strip(),
                            'source': 'direct'
                        })
        except Exception as e:
            print(f"  Error parsing requirements.txt: {e}")
        return deps

    # ── Validation ──────────────────────────────────────────────────────────

    def _validate_dependency(self, dep: Dict):
        """Check if a dependency is allowed by policy"""
        language = dep.get('language')
        name = dep.get('name')

        if not language or not name:
            return

        lang_policy = self.policy.get(language, {})
        allowed         = lang_policy.get('allowed', [])
        blocked         = lang_policy.get('blocked', [])
        requires_review = lang_policy.get('requires_review', [])

        ai_policy        = self.policy.get('ai_code', {}).get('dependency_restrictions', {})
        ai_strict_mode   = ai_policy.get('strict_mode', False)
        ai_blocked_patterns = ai_policy.get('blocked_patterns', [])

        # Check explicitly blocked
        for blocked_pattern in blocked:
            if fnmatch.fnmatch(name, blocked_pattern):
                self.violations.append({
                    'type': 'blocked',
                    'dependency': name,
                    'language': language,
                    'reason': 'Package is explicitly blocked',
                    'details': self._get_block_reason(name, language)
                })
                return

        # Check allowed list
        allowed_match = any(fnmatch.fnmatch(name, p) for p in allowed)

        if not allowed_match:
            violation = {
                'type': 'unapproved',
                'dependency': name,
                'language': language,
                'version': dep.get('version', 'unknown'),
                'source': dep.get('source', 'direct')
            }

            for review_pattern in requires_review:
                if fnmatch.fnmatch(name, review_pattern):
                    violation['requires_review'] = True
                    violation['reason'] = 'Package requires security review'
                    if self.ai_detected:
                        violation['ai_restriction'] = True
                        violation['reason'] += ' (AI-generated code — extra scrutiny required)'
                    break

            if self.ai_detected and ai_strict_mode:
                for pattern in ai_blocked_patterns:
                    if fnmatch.fnmatch(name, pattern):
                        violation['ai_blocked'] = True
                        violation['reason'] = f'Package matches AI blocked pattern: {pattern}'
                        break

            self.violations.append(violation)

    def _get_block_reason(self, name: str, language: str) -> str:
        reasons = {
            'github.com/dgrijalva/jwt-go': 'Unmaintained — use github.com/golang-jwt/jwt instead',
            'github.com/gorilla/context':  'Deprecated — use stdlib context',
            'github.com/pkg/errors':       'Use native errors package (Go 1.13+)',
            'request':                     'Deprecated — use axios or node-fetch',
            'left-pad':                    'Trivial — use native String.padStart()',
            'colors.js':                   'Supply chain attack history',
            'event-stream':                'Known backdoor incident (2018)',
            'is-positive':                 'Unnecessary micro-package',
            'pycrypto':                    'Unmaintained — use pycryptodome',
            'pickle':                      'Insecure deserialization — never use in production',
        }
        return reasons.get(name, 'Blocked by security policy — see policies/allowed-dependencies.yaml')

    # ── Reporting ───────────────────────────────────────────────────────────

    def _print_report(self):
        if not self.violations:
            print("\n  ALL DEPENDENCIES APPROVED")
            return

        print("\n  DEPENDENCY VIOLATIONS FOUND")
        print("=" * 60)

        blocked    = [v for v in self.violations if v['type'] == 'blocked']
        unapproved = [v for v in self.violations if v['type'] == 'unapproved']
        ai_blocked = [v for v in self.violations if v.get('ai_blocked')]

        if blocked:
            print(f"\n  BLOCKED PACKAGES ({len(blocked)})")
            print("  " + "-" * 40)
            for v in blocked:
                print(f"\n    {v['dependency']} ({v['language']})")
                print(f"      Reason : {v['details']}")

        if ai_blocked:
            print(f"\n  AI-BLOCKED PACKAGES ({len(ai_blocked)})")
            print("  " + "-" * 40)
            for v in ai_blocked:
                print(f"\n    {v['dependency']} ({v['language']})")
                print(f"      Reason : {v['reason']}")

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
        print(f"  2. Open a PR with: package name, version, purpose, alternatives considered")
        print(f"  3. Security team reviews within 5 business days")
        print(f"  4. On approval, it moves to allowed[]")


# ── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Allowed Dependencies Guardrail Enforcer"
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Path to repository (default: current directory)"
    )
    args = parser.parse_args()

    enforcer = AllowedDependenciesEnforcer(repo_path=args.repo)
    success = enforcer.enforce()

    if not success:
        print("\n  BUILD BLOCKED: Unapproved dependencies detected")
        sys.exit(1)
    else:
        print("\n  Guardrail check passed")
        sys.exit(0)