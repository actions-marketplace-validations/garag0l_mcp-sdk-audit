"""Small version parser and range matcher covering semver, PEP 440 and Go module versions.

Only what MCP SDK versions and GitHub advisory ranges actually use: X.Y.Z with optional
pre-release (1.2.0-beta.1, 2.0.0a1, 2.0.0rc2) and constraints like ">= 1.10.0, < 1.30.1".
"""

from __future__ import annotations

import re
from functools import total_ordering

_VER = re.compile(
    r"^\s*v?(?P<rel>\d+(?:\.\d+)*)"
    r"(?:[-.]?(?P<pre>(?:a|b|c|rc|alpha|beta|pre|preview|dev)[.\-]?\d*(?:[.\-][0-9A-Za-z]+)*|[0-9A-Za-z][0-9A-Za-z.\-]*))?"
    r"(?:\+[0-9A-Za-z.\-]+)?\s*$",
    re.IGNORECASE,
)
_PRE_RANK = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "pre": 3, "preview": 3, "c": 4, "rc": 4}


@total_ordering
class Version:
    __slots__ = ("raw", "release", "pre")

    def __init__(self, raw: str):
        m = _VER.match(raw)
        if not m:
            raise ValueError(f"unparseable version: {raw!r}")
        self.raw = raw.strip()
        rel = [int(p) for p in m.group("rel").split(".")]
        while len(rel) < 3:
            rel.append(0)
        self.release = tuple(rel)
        pre = m.group("pre")
        if pre:
            pm = re.match(r"([A-Za-z]+)[.\-]?(\d*)", pre)
            word = pm.group(1).lower() if pm else pre.lower()
            num = int(pm.group(2)) if pm and pm.group(2) else 0
            self.pre = (0, _PRE_RANK.get(word, 3), num, pre.lower())
        else:
            self.pre = (1,)

    def _key(self):
        # Pad release so 1.2 == 1.2.0 for comparison.
        return (self.release + (0,) * (6 - len(self.release)), self.pre)

    def __eq__(self, other):
        return self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())

    def __repr__(self):
        return f"Version({self.raw!r})"


_CONSTRAINT = re.compile(r"^\s*(>=|<=|>|<|==|=)?\s*(\S+)\s*$")


def in_range(version: str, spec: str) -> bool:
    """True if version satisfies every comma-separated constraint in a GHSA range string."""
    v = Version(version)
    for part in spec.split(","):
        if not part.strip():
            continue
        m = _CONSTRAINT.match(part)
        if not m:
            raise ValueError(f"unparseable constraint: {part!r}")
        op, bound = m.group(1) or "=", Version(m.group(2))
        ok = {
            ">=": v >= bound,
            "<=": v <= bound,
            ">": v > bound,
            "<": v < bound,
            "=": v == bound,
            "==": v == bound,
        }[op]
        if not ok:
            return False
    return True
