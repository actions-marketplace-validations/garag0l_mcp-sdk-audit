import httpx
from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.settings import AuthSettings
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

provider = ClientCredentialsOAuthProvider(
    server_url="https://tools.example.com/mcp",
    storage=storage,
    client_id="agent",
    client_secret=secret,
)

http = httpx.AsyncClient(follow_redirects=True)

settings = AuthSettings(
    issuer_url="https://auth.example.com",
    resource_server_url="https://mcp.example.com/mcp",
)

manager = StreamableHTTPSessionManager(app=server, stateless=True)
