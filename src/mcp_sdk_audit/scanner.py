"""Walk a project, find MCP SDK dependencies and risky source patterns."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import advisories as adv
from .deps import Dep, collect, dedupe, parser_for
from .rules import SCANNERS, Finding, scan_source
from .versions import in_range

SKIP_DIRS = {
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".nox",
    "__pycache__",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".turbo",
    "coverage",
    "site-packages",
    "vendor",
    ".mypy_cache",
}
MAX_FILE_BYTES = 2_000_000
TEST_DIRS = {"test", "tests", "__tests__", "spec", "e2e", "conformance", "testdata", "fixtures"}
TEST_FILE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^test_.*\.py$)|(_test\.py$)|(^conftest\.py$)")


def is_test(rel: str) -> bool:
    parts = rel.split("/")
    return bool(TEST_DIRS.intersection(parts[:-1])) or TEST_FILE.search(parts[-1]) is not None


SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "unknown": 0}


@dataclass
class VulnDep:
    dep: Dep
    advisory: adv.Affected


@dataclass
class Report:
    root: str
    deps: list[Dep] = field(default_factory=list)
    vulnerable: list[VulnDep] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def max_severity(self) -> int:
        sev = [SEV_ORDER.get(v.advisory.severity, 0) for v in self.vulnerable]
        sev += [SEV_ORDER.get(f.rule.severity, 0) for f in self.findings]
        return max(sev, default=0)


def match(deps: list[Dep], records: list[dict]) -> list[VulnDep]:
    affected = adv.flatten(records)
    out = []
    for d in deps:
        for a in affected:
            if a.ecosystem != d.ecosystem or a.package != d.package:
                continue
            try:
                if in_range(d.version, a.vulnerable_range):
                    out.append(VulnDep(d, a))
            except ValueError:
                continue
    return out


def scan(root: str | Path, records: list[dict], *, deps: bool = True, source: bool = True, include_tests: bool = False) -> Report:
    root = Path(root).resolve()
    report = Report(str(root))
    files = [root] if root.is_file() else None
    found: list[Dep] = []

    def visit(p: Path):
        rel = p.relative_to(root).as_posix() if p != root else p.name
        if deps and parser_for(p.name):
            found.extend(collect(p, rel))
        if source and p.suffix in SCANNERS and (include_tests or p == root or not is_test(rel)):
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    return
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return
            report.files_scanned += 1
            report.findings.extend(scan_source(rel, text, p.suffix))

    if files:
        visit(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".venv"))
            for fn in sorted(filenames):
                visit(Path(dirpath) / fn)

    report.deps = dedupe(found)
    report.vulnerable = match(report.deps, records)
    report.findings.sort(key=lambda f: (-SEV_ORDER[f.rule.severity], f.file, f.line))
    report.vulnerable.sort(key=lambda v: (-SEV_ORDER.get(v.advisory.severity, 0), v.dep.file, v.advisory.ghsa))
    return report
