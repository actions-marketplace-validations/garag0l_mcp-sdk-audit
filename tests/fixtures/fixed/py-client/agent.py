from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider
from mcp.server.auth.settings import AuthSettings
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings

provider = ClientCredentialsOAuthProvider(
    server_url="https://tools.example.com/mcp",
    storage=storage,
    client_id="agent",
    client_secret=secret,
    issuer="https://auth.example.com",
)

settings = AuthSettings(
    issuer_url="https://auth.example.com",
    resource_server_url="https://mcp.example.com/mcp",
    validate_token_resource=True,
)

# follow_redirects=True would be unsafe here
manager = StreamableHTTPSessionManager(app=server, security_settings=TransportSecuritySettings(allowed_hosts=["localhost:8000"]))
