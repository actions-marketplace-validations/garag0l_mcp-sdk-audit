"""Render docs/demo.svg from a real run against the vulnerable fixture. Needs `pip install rich`."""

from pathlib import Path

from rich.console import Console
from rich.text import Text

from mcp_sdk_audit import advisories, output
from mcp_sdk_audit.scanner import scan

root = Path(__file__).resolve().parents[1]
report = scan(root / "tests/fixtures/vulnerable/ts-server", advisories.load())
report.root = "./my-mcp-server"
ansi = output.text(report, color=True)

console = Console(record=True, width=118, file=open("nul" if __import__("os").name == "nt" else "/dev/null", "w"))
console.print("$ mcp-sdk-audit ./my-mcp-server", style="bold green")
console.print(Text.from_ansi(ansi))
console.save_svg(str(root / "docs/demo.svg"), title="mcp-sdk-audit")
print("wrote docs/demo.svg")
