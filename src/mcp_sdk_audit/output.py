"""Text, JSON and SARIF renderers."""

from __future__ import annotations

import json

from . import __version__
from .rules import R
from .scanner import Report
from .versions import Version

REPO = "https://github.com/garag0l/mcp-sdk-audit"


def _ids(a) -> str:
    return f"{a.ghsa}" + (f" / {a.cve}" if a.cve else "")


def _upgrade_target(hits) -> str | None:
    fixed = []
    for a in hits:
        if not a.patched:
            return None  # at least one advisory has no fix: no single safe target
        try:
            fixed.append(Version(a.patched))
        except ValueError:
            return None
    return max(fixed).raw if fixed else None


def text(report: Report, color: bool = False) -> str:
    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    sev_color = {"critical": "1;31", "high": "31", "medium": "33", "moderate": "33", "low": "36"}
    lines = [c("1", f"mcp-sdk-audit {__version__}") + f"  {report.root}", ""]

    if report.deps:
        lines.append(c("1", "MCP SDK dependencies"))
        for d in report.deps:
            hits = [v.advisory for v in report.vulnerable if v.dep == d]
            if not hits:
                lines.append(f"  {d.package}@{d.version}  ({d.file})  " + c("32", "no known advisories"))
                continue
            lines.append(
                f"  {d.package}@{d.version}  ({d.file})  " + c("31", f"{len(hits)} advisor{'y' if len(hits) == 1 else 'ies'}")
            )
            for a in hits:
                sev = c(sev_color.get(a.severity, "0"), f"{a.severity.upper():<6}")
                summary = a.summary.split(": ", 1)[-1] if a.summary.startswith(("MCP", "Model Context")) else a.summary
                lines.append(f"    {sev} {a.ghsa}  {summary[:96]}")
            target = _upgrade_target(hits)
            if target:
                lines.append(c("1", f"    -> upgrade to {target} or later"))
        lines.append("")
    else:
        lines.append(
            c(
                "2",
                "No MCP SDK found in lockfiles (package-lock, pnpm, yarn, bun, uv, poetry, pdm, Pipfile, requirements, go.mod).",
            )
        )
        lines.append("")

    if report.findings:
        lines.append(c("1", "Code that stays exposed after upgrading"))
        for f in report.findings:
            sev = c(sev_color[f.rule.severity], f.rule.severity.upper())
            lines.append(f"  [{sev}] {f.rule.id} {f.file}:{f.line}")
            lines.append(f"         {f.rule.title}")
            lines.append(c("2", f"         > {f.snippet}"))
            lines.append(f"         fix: {f.rule.fix}")
            lines.append(c("2", f"         see: {', '.join(f.rule.advisories)}"))
        lines.append("")

    summary = (
        f"{len(report.deps)} SDK dependenc{'y' if len(report.deps) == 1 else 'ies'}, "
        f"{len(report.vulnerable)} vulnerable match{'es' if len(report.vulnerable) != 1 else ''}, "
        f"{len(report.findings)} code finding{'s' if len(report.findings) != 1 else ''} "
        f"({report.files_scanned} source file{'s' if report.files_scanned != 1 else ''} scanned)"
    )
    lines.append(c("1", summary))
    return "\n".join(lines)


def as_json(report: Report) -> str:
    return json.dumps(
        {
            "tool": "mcp-sdk-audit",
            "version": __version__,
            "root": report.root,
            "files_scanned": report.files_scanned,
            "dependencies": [d.__dict__ for d in report.deps],
            "vulnerable": [{"dependency": v.dep.__dict__, "advisory": v.advisory.__dict__} for v in report.vulnerable],
            "findings": [
                {
                    "rule": f.rule.id,
                    "severity": f.rule.severity,
                    "title": f.rule.title,
                    "file": f.file,
                    "line": f.line,
                    "snippet": f.snippet,
                    "fix": f.rule.fix,
                    "advisories": list(f.rule.advisories),
                    **f.extra,
                }
                for f in report.findings
            ],
        },
        indent=2,
    )


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "moderate": "warning", "low": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "moderate": "5.5", "low": "3.0", "unknown": "5.0"}


def sarif(report: Report) -> str:
    rules, results, seen = [], [], set()

    def add_rule(rid, name, short, help_text, sev, uri):
        if rid in seen:
            return
        seen.add(rid)
        rules.append(
            {
                "id": rid,
                "name": name,
                "shortDescription": {"text": short[:1000]},
                "help": {"text": help_text, "markdown": help_text},
                "helpUri": uri,
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(sev, "warning")},
                "properties": {"security-severity": _SARIF_SCORE.get(sev, "5.0"), "tags": ["security", "mcp"]},
            }
        )

    for v in report.vulnerable:
        a = v.advisory
        add_rule(
            a.ghsa, a.ghsa, a.summary, f"Upgrade {a.package} to {a.patched or 'a fixed version'}. {a.url}", a.severity, a.url
        )
        results.append(
            {
                "ruleId": a.ghsa,
                "level": _SARIF_LEVEL.get(a.severity, "warning"),
                "message": {"text": f"{v.dep.package}@{v.dep.version} is affected by {_ids(a)}: {a.summary}"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": v.dep.file}, "region": {"startLine": v.dep.line}}}
                ],
            }
        )
    for f in report.findings:
        r = f.rule
        add_rule(r.id, r.id, r.title, f"{r.fix}\n\nAdvisories: {', '.join(r.advisories)}", r.severity, f"{REPO}#{r.id.lower()}")
        results.append(
            {
                "ruleId": r.id,
                "level": _SARIF_LEVEL[r.severity],
                "message": {"text": f"{r.title}. Fix: {r.fix}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line}}}],
            }
        )
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "mcp-sdk-audit", "version": __version__, "informationUri": REPO, "rules": rules}},
                    "results": results,
                }
            ],
        },
        indent=2,
    )


def rules_table() -> str:
    lines = []
    for r in R.values():
        lines.append(f"{r.id}  [{r.lang}] {r.severity:<6} {r.title}")
        lines.append(f"         advisories: {', '.join(r.advisories)}")
    return "\n".join(lines)
