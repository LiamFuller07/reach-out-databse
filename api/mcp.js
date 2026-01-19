import crypto from "crypto";

// Configuration
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "reach-out-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
const MCP_ENDPOINT = process.env.MCP_ENDPOINT || "";
const MCP_API_KEY = process.env.MCP_API_KEY || "";
const MCP_PROTOCOL_VERSION = "2025-03-26";

// GitHub Configuration
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const GITHUB_OWNER = process.env.GITHUB_OWNER || "LiamFuller07";
const GITHUB_REPO = process.env.GITHUB_REPO || "reach-out-databse";
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const DATA_FILES = ["founders", "researchers", "vcs", "angels"];
const HAS_GITHUB_WRITE = Boolean(GITHUB_TOKEN);

// Stateless token verification
const AUTH_CODE_SECRET = process.env.AUTH_CODE_SECRET || process.env.OAUTH_CLIENT_SECRET || "default-secret";

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
    inputSchema: { type: "object", properties: { limit: { type: "number" }, offset: { type: "number" }, category: { type: "string" } } }
  },
  {
    name: "search_contacts",
    description: "Search contacts by name, company, tags, or notes",
    inputSchema: { type: "object", properties: { query: { type: "string" }, category: { type: "string" } }, required: ["query"] }
  },
  {
    name: "get_contact",
    description: "Get a specific contact by ID",
    inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] }
  },
  {
    name: "upsert_contact",
    description: "Add or update a contact. Specify category (founders/researchers/vcs/angels). Use id to update existing, or omit for new.",
    inputSchema: {
      type: "object",
      properties: {
        category: { type: "string", enum: ["founders", "researchers", "vcs", "angels"] },
        id: { type: "string" },
        name: { type: "string" },
        city: { type: "string" },
        tags: { type: "array", items: { type: "string" } },
        links: { type: "array", items: { type: "string" } },
        notes: { type: "string" },
        checked: { type: "boolean" }
      },
      required: ["category", "name"]
    }
  },
  {
    name: "delete_contact",
    description: "Delete a contact by ID",
    inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] }
  },
  {
    name: "get_instructions",
    description: "Get usage instructions and stats for this MCP server",
    inputSchema: { type: "object", properties: {} }
  },
  {
    name: "list_categories",
    description: "List available contact categories",
    inputSchema: { type: "object", properties: {} }
  }
];

// GitHub API functions
async function getGitHubFile(category) {
  const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/data/${category}.json?ref=${GITHUB_BRANCH}`;
  const res = await fetch(url, {
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28"
    }
  });
  if (!res.ok) {
    if (res.status === 404) return { json: { category, entries: [], last_updated: "" }, sha: null };
    throw new Error(`GitHub API error: ${res.status}`);
  }
  const data = await res.json();
  const content = Buffer.from(data.content, "base64").toString("utf-8");
  return { json: JSON.parse(content), sha: data.sha };
}

async function putGitHubFile(category, json, message, sha) {
  const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/data/${category}.json`;
  const content = Buffer.from(JSON.stringify(json, null, 2), "utf-8").toString("base64");
  const body = {
    message,
    content,
    branch: GITHUB_BRANCH,
    ...(sha ? { sha } : {})
  };
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub PUT error (${res.status}): ${text}`);
  }
  return res.json();
}

// Read from raw.githubusercontent.com (fast, no auth required)
async function fetchGitHubDataRaw(category) {
  const url = `https://raw.githubusercontent.com/${GITHUB_OWNER}/${GITHUB_REPO}/${GITHUB_BRANCH}/data/${category}.json`;
  const res = await fetch(url);
  if (!res.ok) return { category, entries: [] };
  return res.json();
}

async function fetchAllContacts(categoryFilter = null) {
  const categories = categoryFilter ? [categoryFilter] : DATA_FILES;
  const results = await Promise.all(categories.map(fetchGitHubDataRaw));
  const allContacts = [];
  for (const data of results) {
    for (const entry of (data.entries || [])) {
      allContacts.push({
        id: entry.id,
        name: entry.name,
        company: entry.tags?.[0] || "",
        city: entry.city || "",
        tags: entry.tags || [],
        links: entry.links || [],
        notes: entry.notes || "",
        checked: entry.checked || false,
        category: data.category
      });
    }
  }
  return allContacts;
}

function normalizeContact(entry, category) {
  return {
    id: entry.id || `${category}-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    name: entry.name || "",
    city: entry.city || "SF",
    tags: Array.isArray(entry.tags) ? entry.tags : (entry.tags ? [entry.tags] : []),
    links: Array.isArray(entry.links) ? entry.links : (entry.links ? [entry.links] : []),
    notes: entry.notes || "",
    checked: Boolean(entry.checked)
  };
}

// Tool implementations
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
    } catch (err) {
      // Fall through to local implementation
    }
  }

  switch (name) {
    case "list_categories":
      return { categories: DATA_FILES };

    case "get_instructions": {
      const contacts = await fetchAllContacts();
      const byCategory = {};
      for (const c of contacts) {
        byCategory[c.category] = (byCategory[c.category] || 0) + 1;
      }
      return {
        description: "Reach Out Contact Database MCP Server",
        version: "2.0.0",
        tools: TOOLS.map(t => t.name),
        notes: "Full CRUD: upsert_contact to add/update, delete_contact to remove. Changes sync to GitHub and auto-deploy.",
        stats: { total: contacts.length, byCategory },
        write_enabled: HAS_GITHUB_WRITE,
        categories: DATA_FILES
      };
    }

    case "get_contacts": {
      const contacts = await fetchAllContacts(args.category);
      const limit = args.limit || 100;
      const offset = args.offset || 0;
      return {
        contacts: contacts.slice(offset, offset + limit),
        total: contacts.length,
        limit,
        offset
      };
    }

    case "search_contacts": {
      const contacts = await fetchAllContacts(args.category);
      const query = (args.query || "").toLowerCase();
      const results = contacts.filter(c =>
        c.name.toLowerCase().includes(query) ||
        c.company.toLowerCase().includes(query) ||
        c.notes.toLowerCase().includes(query) ||
        c.tags.some(t => t.toLowerCase().includes(query))
      );
      return {
        results,
        query: args.query,
        total: results.length
      };
    }

    case "get_contact": {
      const contacts = await fetchAllContacts();
      const contact = contacts.find(c => c.id === args.id);
      return {
        contact: contact || null,
        found: Boolean(contact)
      };
    }

    case "upsert_contact": {
      if (!HAS_GITHUB_WRITE) {
        return { success: false, error: "GITHUB_TOKEN not configured. Cannot write." };
      }

      const category = args.category;
      if (!DATA_FILES.includes(category)) {
        return { success: false, error: `Invalid category. Use: ${DATA_FILES.join(", ")}` };
      }

      // Get current data with SHA
      const { json, sha } = await getGitHubFile(category);
      const entries = json.entries || [];

      // Find existing or create new
      let existingIdx = -1;
      if (args.id) {
        existingIdx = entries.findIndex(e => e.id === args.id);
      }
      if (existingIdx < 0 && args.name) {
        existingIdx = entries.findIndex(e => e.name.toLowerCase() === args.name.toLowerCase());
      }

      const newEntry = normalizeContact({
        id: existingIdx >= 0 ? entries[existingIdx].id : args.id,
        name: args.name,
        city: args.city,
        tags: args.tags,
        links: args.links,
        notes: args.notes,
        checked: args.checked
      }, category);

      if (existingIdx >= 0) {
        // Update existing - merge fields
        entries[existingIdx] = { ...entries[existingIdx], ...newEntry };
      } else {
        // Add new
        entries.push(newEntry);
      }

      // Save to GitHub
      const updatedJson = {
        category,
        entries,
        last_updated: new Date().toISOString()
      };

      await putGitHubFile(category, updatedJson, `Upsert contact: ${newEntry.name} in ${category}`, sha);

      return {
        success: true,
        action: existingIdx >= 0 ? "updated" : "created",
        contact: newEntry,
        category,
        synced: true
      };
    }

    case "delete_contact": {
      if (!HAS_GITHUB_WRITE) {
        return { success: false, error: "GITHUB_TOKEN not configured. Cannot write." };
      }

      // Find contact in all categories
      for (const category of DATA_FILES) {
        const { json, sha } = await getGitHubFile(category);
        const entries = json.entries || [];
        const idx = entries.findIndex(e => e.id === args.id);

        if (idx >= 0) {
          const deleted = entries[idx];
          entries.splice(idx, 1);

          const updatedJson = {
            category,
            entries,
            last_updated: new Date().toISOString()
          };

          await putGitHubFile(category, updatedJson, `Delete contact: ${deleted.name} from ${category}`, sha);

          return {
            success: true,
            deleted: { id: deleted.id, name: deleted.name },
            category,
            synced: true
          };
        }
      }

      return { success: false, error: `Contact ${args.id} not found` };
    }

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
            serverInfo: { name: "reach-out-mcp", version: "2.0.0" },
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

  // GET - SSE stream
  if (req.method === "GET") {
    if (!acceptHeader.includes("text/event-stream")) {
      return res.status(400).json({ error: "Accept header must include text/event-stream" });
    }

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

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
