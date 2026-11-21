import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { ClientCredentialsProvider } from "@modelcontextprotocol/sdk/client/auth-extensions.js";

const app = createMcpExpressApp();
app.use("/mcp", requireBearerAuth({ verifier, expectedResource: new URL("https://mcp.example.com/mcp") }));

// Do not do this: const transport = new StreamableHTTPServerTransport({}) at module scope
app.post("/mcp", async (req, res) => {
  const server = new McpServer({ name: "demo", version: "1.0.0" });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

const upstream = new ClientCredentialsProvider({
  clientId: process.env.CLIENT_ID!,
  clientSecret: process.env.CLIENT_SECRET!,
  expectedIssuer: "https://auth.example.com",
});
const note = "redirectPolicy: 'follow' is unsafe";
