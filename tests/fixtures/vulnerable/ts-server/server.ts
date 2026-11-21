import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { ClientCredentialsProvider } from "@modelcontextprotocol/sdk/client/auth-extensions.js";

// One server and one stateless transport for everyone: the pattern from the old README examples.
const server = new McpServer({ name: "demo", version: "1.0.0" });
const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

const app = express();
app.use(express.json());
app.use("/mcp", requireBearerAuth({ verifier }));

app.post("/mcp", async (req, res) => {
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// Upstream client used by a tool
const upstream = new ClientCredentialsProvider({
  clientId: process.env.CLIENT_ID!,
  clientSecret: process.env.CLIENT_SECRET!,
});
const t2 = new StreamableHTTPClientTransport(new URL(UPSTREAM), { authProvider: upstream, redirectPolicy: "follow" });

app.listen(3000);
