import crypto from "crypto";

// Configuration
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "reach-out-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
const MCP_ENDPOINT = process.env.MCP_ENDPOINT || "";
const MCP_API_KEY = process.env.MCP_API_KEY || "";
const MCP_PROTOCOL_VERSION = "2025-03-26";

// Stateless token verification
const AUTH_CODE_SECRET = process.env.AUTH_CODE_SECRET || process.env.OAUTH_CLIENT_SECRET || "default-secret";
const DCR_SECRET = process.env.DCR_SECRET || process.env.OAUTH_CLIENT_SECRET || "default-dcr-secret";

function verifyAccessToken(token) {
  try {
    const [payloadB64, signature] = token.split(".");
    if (!payloadB64 || !signature) return false;
    const payload = Buffer.from(payloadB64, "base64url").toString();
    const expectedSig = crypto.createHmac("sha256", AUTH_CODE_SECRET).update(payload).digest("hex");
    if (signature !== expectedSig) return false;
    const data = JSON.parse(payload);
    return data.expiresAt > Date.now();
  } catch {
    return false;
  }
}

function isAuthorized(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    if (verifyAccessToken(token)) return true;
  }
  const apiKey = process.env.MCP_API_KEY || "";
  if (apiKey) {
    const provided = req.headers["x-api-key"];
    return provided === apiKey;
  }
  const oauthSecret = process.env.OAUTH_CLIENT_SECRET || "";
  return !oauthSecret && !apiKey;
}

// Tool definitions for Reach Out database
const TOOLS = [
  {
    name: "get_contacts",
    description: "Get all contacts from the reach-out database",
    inputSchema: { type: "object", properties: { limit: { type: "number" }, offset: { type: "number" } } }
  },
  {
    name: "search_contacts",
    description: "Search contacts by name, email, or company",
    inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] }
  },
  {
    name: "get_contact",
    description: "Get a specific contact by ID",
    inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] }
  },
  {
    name: "add_contact",
    description: "Add a new contact to the database",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        email: { type: "string" },
        company: { type: "string" },
        phone: { type: "string" },
        notes: { type: "string" }
      },
      required: ["name"]
    }
  },
  {
    name: "update_contact",
    description: "Update an existing contact",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        name: { type: "string" },
        email: { type: "string" },
        company: { type: "string" },
        phone: { type: "string" },
        notes: { type: "string" }
      },
      required: ["id"]
    }
  },
  {
    name: "get_instructions",
    description: "Get usage instructions for this MCP server",
    inputSchema: { type: "object", properties: {} }
  }
];

// Tool implementations (proxy to upstream if configured, otherwise mock)
async function callTool(name, args) {
  // If we have an upstream MCP endpoint, proxy the call
  if (MCP_ENDPOINT) {
    try {
      const res = await fetch(MCP_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(MCP_API_KEY ? { "X-Api-Key": MCP_API_KEY } : {})
        },
        body: JSON.stringify({ tool: name, arguments: args })
      });
      const data = await res.json();
      if (data.ok) return data.result;
      throw new Error(data.error || "Upstream error");
    } catch (err) {
      // Fall through to local implementation
    }
  }

  // Local implementations
  switch (name) {
    case "get_instructions":
      return {
        description: "Reach Out Contact Database MCP Server",
        version: "1.0.0",
        tools: TOOLS.map(t => t.name),
        notes: "Use these tools to manage your outreach contact database."
      };

    case "get_contacts":
      return {
        contacts: [],
        total: 0,
        message: "No contacts configured. Connect to a data source."
      };

    case "search_contacts":
      return {
        results: [],
        query: args.query,
        message: "Search functionality requires a connected data source."
      };

    case "get_contact":
      return {
        contact: null,
        message: `Contact ${args.id} not found.`
      };

    case "add_contact":
      return {
        success: false,
        message: "Add contact requires a connected data source."
      };

    case "update_contact":
      return {
        success: false,
        message: "Update contact requires a connected data source."
      };

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// JSON-RPC handler
async function handleJsonRpcRequest(message) {
  const { jsonrpc, id, method, params } = message;

  if (jsonrpc !== "2.0") {
    return { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request" } };
  }

  try {
    switch (method) {
      case "initialize": {
        const sessionId = crypto.randomUUID();
        return {
          jsonrpc: "2.0", id,
          result: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            serverInfo: { name: "reach-out-mcp", version: "1.0.0" },
            capabilities: { tools: { listChanged: false } }
          },
          _sessionId: sessionId
        };
      }

      case "initialized":
        return null;

      case "tools/list":
        return { jsonrpc: "2.0", id, result: { tools: TOOLS } };

      case "tools/call": {
        const { name, arguments: args } = params;
        const result = await callTool(name, args || {});
        return {
          jsonrpc: "2.0", id,
          result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] }
        };
      }

      case "ping":
        return { jsonrpc: "2.0", id, result: {} };

      default:
        return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } };
    }
  } catch (err) {
    return { jsonrpc: "2.0", id, error: { code: -32000, message: err.message } };
  }
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Api-Key, Accept, Mcp-Session-Id, MCP-Protocol-Version");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  // Authorization check
  if (!isAuthorized(req)) {
    return res.status(401).json({ jsonrpc: "2.0", error: { code: -32000, message: "Unauthorized" } });
  }

  const acceptHeader = req.headers.accept || "";

  // DELETE - Session termination
  if (req.method === "DELETE") {
    return res.status(204).end();
  }

  // GET - SSE stream (limited support on Vercel)
  if (req.method === "GET") {
    if (!acceptHeader.includes("text/event-stream")) {
      return res.status(400).json({ error: "Accept header must include text/event-stream" });
    }

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    // Send initial ping and close (Vercel has timeout limits)
    const eventId = crypto.randomBytes(16).toString("hex");
    res.write(`id: ${eventId}\n`);
    res.write(`data: ${JSON.stringify({ jsonrpc: "2.0", method: "ping" })}\n\n`);
    return res.end();
  }

  // POST - JSON-RPC messages
  if (req.method === "POST") {
    try {
      let message;
      if (typeof req.body === "string") {
        message = JSON.parse(req.body);
      } else {
        message = req.body;
      }

      const response = await handleJsonRpcRequest(message);

      if (!response) {
        return res.status(202).end();
      }

      // Check if client wants SSE
      if (acceptHeader.includes("text/event-stream")) {
        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache");
        if (response._sessionId) {
          res.setHeader("Mcp-Session-Id", response._sessionId);
        }

        const { _sessionId, ...cleanResponse } = response;
        const eventId = crypto.randomBytes(16).toString("hex");
        res.write(`id: ${eventId}\n`);
        res.write(`data: ${JSON.stringify(cleanResponse)}\n\n`);
        return res.end();
      } else {
        const { _sessionId, ...cleanResponse } = response;
        if (response._sessionId) {
          res.setHeader("Mcp-Session-Id", response._sessionId);
        }
        return res.status(200).json(cleanResponse);
      }
    } catch (err) {
      return res.status(400).json({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" } });
    }
  }

  return res.status(405).json({ error: "Method not allowed" });
}
