"""Source rules for MCP SDK advisories where upgrading the package is not enough.

Each rule is a cheap, explainable heuristic over source text. They are tuned to find the
code patterns the advisories themselves describe, and they say which advisory they map to
so a reviewer can confirm or dismiss a finding in seconds.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

TS_EXT = {".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".jsx"}
PY_EXT = {".py"}


@dataclass(frozen=True)
class Rule:
    id: str
    lang: str  # ts | py
    severity: str  # high | medium | low
    title: str
    advisories: tuple[str, ...]
    fix: str


@dataclass
class Finding:
    rule: Rule
    file: str
    line: int
    snippet: str
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------- text helpers


def mask(text: str, lang: str) -> str:
    """Return text with comments and string contents replaced by spaces (same length, newlines kept).

    Lets rules reason about code structure (braces, call boundaries) without being fooled by
    strings or comments, while offsets still map 1:1 to the original text.
    """
    out = list(text)
    i, n = 0, len(text)

    def blank(a: int, b: int):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if lang == "ts" and text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif lang == "ts" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif lang == "py" and c == "#":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif lang == "py" and text.startswith(('"""', "'''"), i):
            q = text[i : i + 3]
            j = text.find(q, i + 3)
            j = n if j < 0 else j + 3
            blank(i + 3, j - 3)
            i = j
        elif c in "\"'" or (lang == "ts" and c == "`"):
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\\":
                    j += 1
                elif text[j] == "\n" and c != "`":
                    break
                j += 1
            blank(i + 1, j)
            i = j + 1
        else:
            i += 1
    return "".join(out)


def depth_map(masked: str) -> list[int]:
    """Curly-brace (block scope) depth at each offset (code only; masked input)."""
    depths, d = [], 0
    for ch in masked:
        if ch == "{":
            depths.append(d)
            d += 1
        elif ch == "}":
            d = max(0, d - 1)
            depths.append(d)
        else:
            depths.append(d)
    return depths


def call_args(text: str, masked: str, open_idx: int) -> str:
    """Original text between the paren at open_idx and its matching close paren."""
    d = 0
    for j in range(open_idx, len(masked)):
        ch = masked[j]
        if ch == "(":
            d += 1
        elif ch == ")":
            d -= 1
            if d == 0:
                return text[open_idx + 1 : j]
    return text[open_idx + 1 :]


def line_at(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def snippet_at(text: str, idx: int) -> str:
    s = text.rfind("\n", 0, idx) + 1
    e = text.find("\n", idx)
    return text[s : e if e >= 0 else len(text)].strip()[:160]


_DEFINITION = re.compile(r"(?:\bfunction\s*\*?|\bclass|\bdef|\binterface|\btype)\s+$")


def calls(text: str, masked: str, pattern: str):
    """Yield (match_start, args_text) for calls whose callee matches `pattern` (a regex ending before '(').

    Skips definitions such as `function requireBearerAuth(` or `class AuthSettings(`.
    """
    for m in re.finditer(pattern + r"\s*\(", masked):
        if _DEFINITION.search(masked[max(0, m.start() - 40) : m.start()]):
            continue
        yield m.start(), call_args(text, masked, m.end() - 1)


def has_kw(args: str, name: str, lang: str) -> bool:
    if lang == "py":
        # keyword argument, or a positional variable with the same name
        return re.search(rf"\b{name}\b", args) is not None
    if "{" not in args:
        return True  # options come from a variable we can't see; don't guess
    # object literal key, shorthand property, or spread we can't see through
    return re.search(rf"\b{name}\b", args) is not None or "..." in args


# ---------------------------------------------------------------- rules

R = {
    r.id: r
    for r in [
        Rule(
            "MCPA001",
            "ts",
            "high",
            "Bundled OAuth provider without expectedIssuer still sends credentials to any authorization server the MCP server names",
            ("GHSA-6qxp-vccf-f47h",),
            "Upgrade to @modelcontextprotocol/sdk >=1.31.0 or @modelcontextprotocol/client >=2.2.0 and pass "
            "expectedIssuer: 'https://<your-auth-server>' to the provider.",
        ),
        Rule(
            "MCPA002",
            "ts",
            "medium",
            "requireBearerAuth/verifyBearerToken without expectedResource accepts tokens issued for other services",
            ("GHSA-rvq5-wwqv-78pq",),
            "Upgrade (sdk >=1.32.0 / server >=2.3.0), pass expectedResource: new URL('<your MCP URL>') AND return "
            "AuthInfo.resource from verifyAccessToken(). Or check `aud` yourself in verifyAccessToken().",
        ),
        Rule(
            "MCPA003",
            "ts",
            "medium",
            "redirectPolicy: 'follow' re-enables cross-origin redirects that leak headers, session ids and token-request bodies",
            ("GHSA-6prh-2h8m-c8cw",),
            "Remove redirectPolicy: 'follow' and configure the final URL directly.",
        ),
        Rule(
            "MCPA004",
            "ts",
            "high",
            "HTTP transport created once at module scope and shared by all clients (responses can reach the wrong client)",
            ("GHSA-345p-7cg4-v4c7", "GHSA-jm63-cq47-j5jp"),
            "Create the transport per request (stateless) or per session (sessionIdGenerator set). "
            "Patched SDKs reject the shared pattern at runtime, so this is also an upgrade blocker.",
        ),
        Rule(
            "MCPA005",
            "ts",
            "high",
            "One McpServer/Server instance connect()ed to many transports (server-to-client messages can cross clients)",
            ("GHSA-345p-7cg4-v4c7", "GHSA-jm63-cq47-j5jp"),
            "Build a new McpServer inside the request/session handler, or pass a factory to createMcpHandler(). "
            "Patched SDKs throw ALREADY_CONNECTED on the second connect().",
        ),
        Rule(
            "MCPA006",
            "ts",
            "medium",
            "Deprecated experimental taskStore in use; one shared InMemoryTaskStore lets clients read and cancel each other's tasks",
            ("GHSA-22jm-h49p-29qw",),
            "Upgrade to @modelcontextprotocol/sdk >=1.32.0, and preferably remove taskStore (deprecated by the 2026-07-28 spec).",
        ),
        Rule(
            "MCPA007",
            "ts",
            "low",
            "HTTP MCP transport on a hand-built Express app with no Host-header / DNS-rebinding protection (matters if served on localhost without auth)",
            ("GHSA-w48q-cv73-mx4w",),
            "Use createMcpExpressApp(), or app.use(hostHeaderValidation(...)), or require authentication on the endpoint.",
        ),
        Rule(
            "MCPA101",
            "py",
            "high",
            "Client-credentials / private-key-JWT OAuth provider without issuer= still follows any authorization server the MCP server advertises",
            ("GHSA-qx49-fqc8-xw99",),
            'Upgrade to mcp >=1.30.0 (1.x) or >=2.2.0 (2.x) and pass issuer="https://<your-auth-server>".',
        ),
        Rule(
            "MCPA102",
            "py",
            "medium",
            "AuthSettings without validate_token_resource: bearer tokens issued for other services are accepted",
            ("GHSA-w4fh-qvv9-3v23",),
            "Upgrade (mcp >=1.30.0 / >=2.2.0), set validate_token_resource=True with resource_server_url, and return "
            "AccessToken.resource from verify_token(). If your TokenVerifier already checks `aud`, set it to False explicitly.",
        ),
        Rule(
            "MCPA103",
            "py",
            "medium",
            "HTTP client with follow_redirects=True passed to MCP client transports re-enables cross-origin redirect leaks",
            ("GHSA-5h93-6whr-6q8j",),
            "Leave follow_redirects at False for clients you hand to MCP transports; point the client at the final URL.",
        ),
        Rule(
            "MCPA104",
            "py",
            "low",
            "Low-level HTTP/SSE/WebSocket server transport without security_settings: no Host/Origin validation (matters if served on localhost without auth)",
            ("GHSA-9h52-p55h-vw2f", "GHSA-vj7q-gjh5-988w"),
            "Pass security_settings=TransportSecuritySettings(...) (mcp >=1.23.0; websocket_server needs >=1.28.1), "
            "or require authentication.",
        ),
    ]
}

_HTTP_HANDLER_TS = re.compile(
    r"\b\w*(?:app|App|router|Router)\.(?:post|get|all|use|route)\s*\(|\bcreateServer\s*\(|new\s+Hono\b|fastify\s*\(|Bun\.serve|Deno\.serve|export\s+default\s*\{\s*fetch"
)


def _ts_rules(path: str, text: str) -> list[Finding]:
    if "mcp" not in text.lower():  # cheap pre-filter: every rule needs an MCP import or type nearby
        return []
    masked = mask(text, "ts")
    depth = depth_map(masked)
    out: list[Finding] = []

    def add(rid, idx, **extra):
        out.append(Finding(R[rid], path, line_at(text, idx), snippet_at(text, idx), extra))

    # MCPA001 bundled providers
    for idx, args in calls(
        text,
        masked,
        r"\bnew\s+(?:ClientCredentialsProvider|PrivateKeyJwtProvider|StaticPrivateKeyJwtProvider|CrossAppAccessProvider)",
    ):
        if not has_kw(args, "expectedIssuer", "ts"):
            add("MCPA001", idx)

    # MCPA002 bearer auth audience
    for idx, args in calls(text, masked, r"\b(?:requireBearerAuth|verifyBearerToken)"):
        if not has_kw(args, "expectedResource", "ts"):
            add("MCPA002", idx)

    # MCPA003 redirect follow
    for m in re.finditer(r"redirectPolicy\s*:\s*['\"`]follow['\"`]", text):
        if masked[m.start()] != " ":  # not inside a comment
            add("MCPA003", m.start())

    has_handler = _HTTP_HANDLER_TS.search(masked) is not None

    # MCPA004 module-scope HTTP transport
    for idx, args in calls(
        text,
        masked,
        r"\bnew\s+(?:StreamableHTTPServerTransport|WebStandardStreamableHTTPServerTransport|NodeStreamableHTTPServerTransport)",
    ):
        # A stateful transport (sessionIdGenerator set) serves exactly one session. The leak is a
        # stateless transport created once and shared by every request.
        stateful = re.search(r"sessionIdGenerator\s*:\s*(?!undefined\b)\S", args) is not None
        if depth[idx] == 0 and has_handler and not stateful:
            add("MCPA004", idx)

    # MCPA005 module-scope server connected inside a handler
    top_servers = {}
    for m in re.finditer(r"\b(?:const|let|var)\s+(\w+)\s*(?::\s*\w+\s*)?=\s*new\s+(?:McpServer|Server)\s*\(", masked):
        if depth[m.start()] == 0:
            top_servers[m.group(1)] = m.start()
    for name, idx in top_servers.items() if has_handler else ():
        for c in re.finditer(rf"\b{re.escape(name)}(?:\.server)?\.connect\s*\(", masked):
            if re.search(r"Stdio|InMemory|createLinkedPair", call_args(text, masked, c.end() - 1)):
                continue  # single local connection, nothing shared
            if depth[c.start()] > 0:
                add("MCPA005", idx, connect_line=line_at(text, c.start()))
                break

    # MCPA006 taskStore
    for m in re.finditer(r"\btaskStore\s*[:,}]|\bnew\s+InMemoryTaskStore\s*\(", masked):
        add("MCPA006", m.start())
        break

    # MCPA007 custom express + HTTP transport, no rebinding protection
    if (
        re.search(r"\bexpress\s*\(\s*\)", masked)
        and re.search(r"\b(?:StreamableHTTPServerTransport|SSEServerTransport)\b", masked)
        and not re.search(
            r"hostHeaderValidation|enableDnsRebindingProtection|createMcpExpressApp|allowedHosts|requireBearerAuth", masked
        )
    ):
        m = re.search(r"\bexpress\s*\(\s*\)", masked)
        add("MCPA007", m.start())

    return out


def _py_rules(path: str, text: str) -> list[Finding]:
    if "mcp" not in text:
        return []
    masked = mask(text, "py")
    out: list[Finding] = []

    def add(rid, idx, **extra):
        out.append(Finding(R[rid], path, line_at(text, idx), snippet_at(text, idx), extra))

    for idx, args in calls(
        text, masked, r"\b(?:ClientCredentialsOAuthProvider|PrivateKeyJWTOAuthProvider|RFC7523OAuthClientProvider)"
    ):
        if not has_kw(args, "issuer", "py") and "**" not in args:
            add("MCPA101", idx)

    for idx, args in calls(text, masked, r"\bAuthSettings"):
        if not has_kw(args, "validate_token_resource", "py") and "**" not in args:
            add("MCPA102", idx)

    # Only files that use MCP client transports; a server tool fetching web pages is out of scope.
    if re.search(
        r"\b(?:streamable_?http_client|streamablehttp_client|sse_client|ClientSessionGroup|create_mcp_http_client)\b", masked
    ):
        for m in re.finditer(r"\bfollow_redirects\s*=\s*True\b", masked):
            add("MCPA103", m.start())

    for idx, args in calls(text, masked, r"\b(?:StreamableHTTPSessionManager|SseServerTransport|websocket_server)"):
        if not has_kw(args, "security_settings", "py") and "**" not in args:
            add("MCPA104", idx)

    return out


SCANNERS: dict[str, Callable[[str, str], list[Finding]]] = {}
for _e in TS_EXT:
    SCANNERS[_e] = _ts_rules
for _e in PY_EXT:
    SCANNERS[_e] = _py_rules


def scan_source(path: str, text: str, suffix: str) -> list[Finding]:
    fn = SCANNERS.get(suffix)
    return fn(path, text) if fn else []
