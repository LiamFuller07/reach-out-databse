import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import http from "http";
import crypto from "crypto";
import { URL } from "url";

const OWNER = process.env.GITHUB_OWNER || "LiamFuller07";
const REPO = process.env.GITHUB_REPO || "reach-out-databse";
const BRANCH = process.env.GITHUB_BRANCH || "main";
const TOKEN = process.env.GITHUB_TOKEN;
const PORT = Number(process.env.PORT || process.env.MCP_PORT || 3333);
const API_KEY = process.env.MCP_API_KEY || "";
const HAS_GITHUB = Boolean(TOKEN && OWNER && REPO && BRANCH);

// OAuth 2.0 Configuration
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "reach-out-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
const OAUTH_REDIRECT_URIS = (process.env.OAUTH_REDIRECT_URIS || "https://claude.ai/oauth/callback").split(",").map(s => s.trim());
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// In-memory token storage (use Redis/DB in production for multiple instances)
const authCodes = new Map(); // code -> { clientId, redirectUri, expiresAt }
const accessTokens = new Map(); // token -> { clientId, expiresAt }

const AUTH_CODE_TTL = 5 * 60 * 1000; // 5 minutes
const ACCESS_TOKEN_TTL = 24 * 60 * 60 * 1000; // 24 hours

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function cleanExpiredTokens() {
  const now = Date.now();
  for (const [code, data] of authCodes) {
    if (data.expiresAt < now) authCodes.delete(code);
  }
  for (const [token, data] of accessTokens) {
    if (data.expiresAt < now) accessTokens.delete(token);
  }
}

// Clean expired tokens every 5 minutes
setInterval(cleanExpiredTokens, 5 * 60 * 1000);

function validateBearerToken(authHeader) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return false;
  const token = authHeader.slice(7);
  const data = accessTokens.get(token);
  if (!data) return false;
  if (data.expiresAt < Date.now()) {
    accessTokens.delete(token);
    return false;
  }
  return true;
}

function isAuthorized(req) {
  // Check Bearer token first (OAuth)
  const authHeader = req.headers["authorization"];
  if (authHeader && validateBearerToken(authHeader)) {
    return true;
  }
  // Fall back to API key (legacy)
  if (API_KEY) {
    const provided = req.headers["x-api-key"];
    return provided === API_KEY;
  }
  // If no auth configured, allow (for development)
  return !OAUTH_CLIENT_SECRET && !API_KEY;
}
const ENABLE_GITHUB_SYNC = process.env.ENABLE_GITHUB_SYNC !== "false" && HAS_GITHUB;
const DEPLOY_HOOK_URL = process.env.VERCEL_DEPLOY_HOOK_URL || "";
const AUTO_DEPLOY_ON_WRITE = process.env.AUTO_DEPLOY_ON_WRITE === "true";
const SYNC_DEBOUNCE_MS = Number(process.env.SYNC_DEBOUNCE_MS || 8000);
const DEPLOY_MIN_INTERVAL_MS = Number(process.env.DEPLOY_MIN_INTERVAL_MS || 60000);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || path.resolve(__dirname, "../data");

const CATEGORY_SET = new Set(["founders", "researchers", "vcs", "angels"]);
const REQUIRED_FIELDS = ["id", "name"];
const OPTIONAL_FIELDS = ["city", "tags", "links", "notes", "checked"];
const CITY_ALIASES = new Map([
  ["SF", "SF"],
  ["SAN FRANCISCO", "SF"],
  ["SANFRANCISCO", "SF"],
  ["NYC", "NYC"],
  ["NEW YORK", "NYC"],
  ["NEW YORK CITY", "NYC"]
]);

const pendingSyncs = new Map();
const deployState = { lastAt: 0 };

if (!TOKEN) {
  process.stderr.write("GITHUB_TOKEN not set; GitHub sync will be disabled.\n");
}

function apiUrl(pathname) {
  return `https://api.github.com/repos/${OWNER}/${REPO}/contents/${pathname}?ref=${BRANCH}`;
}

async function githubFetch(pathname, options = {}) {
  if (!HAS_GITHUB) {
    throw new Error("GitHub credentials not configured.");
  }
  const res = await fetch(apiUrl(pathname), {
    ...options,
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {})
    }
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API error (${res.status}): ${text}`);
  }
  return res.json();
}

async function getGithubJsonFile(pathname) {
  const data = await githubFetch(pathname);
  if (!data.content) {
    throw new Error(`No content for ${pathname}`);
  }
  const decoded = Buffer.from(data.content, "base64").toString("utf-8");
  return { json: JSON.parse(decoded), sha: data.sha };
}

async function putGithubJsonFile(pathname, json, message, sha) {
  const content = Buffer.from(JSON.stringify(json, null, 2), "utf-8").toString("base64");
  const body = {
    message,
    content,
    ...(sha ? { sha } : {})
  };

  const res = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${pathname}`,
    {
      method: "PUT",
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${TOKEN}`,
        "X-GitHub-Api-Version": "2022-11-28"
      },
      body: JSON.stringify(body)
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub PUT error (${res.status}): ${text}`);
  }

  return res.json();
}

function localCategoryPath(category) {
  return path.join(DATA_DIR, `${category}.json`);
}

async function readLocalJson(category) {
  const filePath = localCategoryPath(category);
  const content = await fs.readFile(filePath, "utf-8");
  return { json: JSON.parse(content), path: filePath };
}

async function writeLocalJson(category, json) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const filePath = localCategoryPath(category);
  await fs.writeFile(filePath, JSON.stringify(json, null, 2), "utf-8");
  return { path: filePath };
}

async function loadCategory(category) {
  try {
    const { json } = await readLocalJson(category);
    return { json, source: "local", localPath: localCategoryPath(category) };
  } catch (err) {
    if (err.code === "ENOENT" && HAS_GITHUB) {
      const { json, sha } = await getGithubJsonFile(getCategoryPath(category));
      await writeLocalJson(category, json);
      return { json, sha, source: "github", localPath: localCategoryPath(category) };
    }
    throw err;
  }
}

async function syncGithubCategory(category, payload, message) {
  if (!ENABLE_GITHUB_SYNC) {
    return { synced: false, reason: "GitHub sync disabled" };
  }
  try {
    let sha;
    try {
      const file = await getGithubJsonFile(getCategoryPath(category));
      sha = file.sha;
    } catch (err) {
      if (err.message.includes("404")) {
        sha = undefined;
      } else {
        throw err;
      }
    }
    await putGithubJsonFile(getCategoryPath(category), payload, message, sha);
    return { synced: true };
  } catch (err) {
    return { synced: false, error: err.message };
  }
}

async function triggerDeploy(reason = "manual") {
  if (!DEPLOY_HOOK_URL) {
    return { triggered: false, reason: "No deploy hook configured" };
  }
  try {
    const res = await fetch(DEPLOY_HOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason })
    });
    if (!res.ok) {
      const text = await res.text();
      return { triggered: false, error: `Deploy hook failed (${res.status}): ${text}` };
    }
    return { triggered: true };
  } catch (err) {
    return { triggered: false, error: err.message };
  }
}

async function triggerDeployThrottled(reason) {
  if (!DEPLOY_HOOK_URL) {
    return { triggered: false, reason: "No deploy hook configured" };
  }
  const now = Date.now();
  if (DEPLOY_MIN_INTERVAL_MS > 0 && now - deployState.lastAt < DEPLOY_MIN_INTERVAL_MS) {
    return { triggered: false, reason: "Deploy throttled" };
  }
  const result = await triggerDeploy(reason);
  if (result.triggered) {
    deployState.lastAt = now;
  }
  return result;
}

function scheduleSync(category, payload, message, reason) {
  const entry = pendingSyncs.get(category) || {};
  if (entry.timer) {
    clearTimeout(entry.timer);
  }
  pendingSyncs.set(category, { payload, message, reason, timer: null });

  if (SYNC_DEBOUNCE_MS <= 0) {
    flushSync(category);
    return {
      sync: { queued: false, immediate: true },
      deploy: { queued: AUTO_DEPLOY_ON_WRITE }
    };
  }

  const timer = setTimeout(() => {
    flushSync(category);
  }, SYNC_DEBOUNCE_MS);
  pendingSyncs.set(category, { payload, message, reason, timer });

  return {
    sync: { queued: true, delay_ms: SYNC_DEBOUNCE_MS },
    deploy: { queued: AUTO_DEPLOY_ON_WRITE }
  };
}

async function flushSync(category) {
  const entry = pendingSyncs.get(category);
  if (!entry) return;
  pendingSyncs.delete(category);

  if (ENABLE_GITHUB_SYNC) {
    const sync = await syncGithubCategory(category, entry.payload, entry.message);
    if (!sync.synced && sync.error) {
      process.stderr.write(`GitHub sync failed (${category}): ${sync.error}\n`);
    }
  }

  if (AUTO_DEPLOY_ON_WRITE) {
    const deploy = await triggerDeployThrottled(entry.reason || "auto");
    if (!deploy.triggered && deploy.error) {
      process.stderr.write(`Deploy hook failed: ${deploy.error}\n`);
    }
  }
}

const categorySchema = z.enum(["founders", "researchers", "vcs", "angels"]);
const replaceCategorySchema = z.object({
  category: categorySchema,
  data: z.any()
});
const getCategorySchema = z.object({
  category: categorySchema
});
const upsertPersonSchema = z.object({
  category: categorySchema,
  id: z.string().optional(),
  name: z.string().optional(),
  patch: z.record(z.any())
});
const deletePersonSchema = z.object({
  category: categorySchema,
  id: z.string().optional(),
  name: z.string().optional()
});
const searchCategorySchema = z.object({
  category: categorySchema,
  query: z.string(),
  fields: z.array(z.string()).optional()
});
const getInstructionsSchema = z.object({});
const listFilesSchema = z.object({});
const getFileSchema = z.object({
  path: z.string()
});
const triggerDeploySchema = z.object({
  reason: z.string().optional()
});

function getCategoryPath(category) {
  return `data/${category}.json`;
}

function normalizeText(value) {
  return (value || "").trim().toLowerCase();
}

function findPersonIndex(rows, id, name) {
  if (id) {
    const idx = rows.findIndex(r => r.id === id);
    if (idx >= 0) return idx;
  }
  if (name) {
    const needle = normalizeText(name);
    return rows.findIndex(r => normalizeText(r.name) === needle);
  }
  return -1;
}

function normalizeCity(value) {
  if (!value) return "";
  const trimmed = String(value).trim();
  if (!trimmed) return "";
  const upper = trimmed.toUpperCase();
  return CITY_ALIASES.get(upper) || trimmed;
}

function normalizeStringArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map(item => String(item).trim()).filter(Boolean);
  }
  return String(value)
    .split(",")
    .map(part => part.trim())
    .filter(Boolean);
}

function normalizeChecked(value) {
  if (value === true || value === false) return value;
  if (value === undefined || value === null) return false;
  if (typeof value === "string") {
    const norm = value.trim().toLowerCase();
    if (!norm) return false;
    return norm === "true" || norm === "1" || norm === "yes";
  }
  if (typeof value === "number") return value === 1;
  return Boolean(value);
}

function normalizeRow(row, category) {
  const name = row?.name ? String(row.name).trim() : "";
  if (!name) {
    throw new Error(`Missing required fields (${category}): name`);
  }
  const id = row?.id ? String(row.id) : `${category}-new-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
  return {
    id,
    name,
    city: normalizeCity(row.city),
    tags: normalizeStringArray(row.tags),
    links: normalizeStringArray(row.links),
    notes: row.notes ? String(row.notes) : "",
    checked: normalizeChecked(row.checked)
  };
}

function normalizeDataset(category, data) {
  if (!data || !Array.isArray(data.entries)) {
    throw new Error("Dataset must include entries[]");
  }
  const cleaned = data.entries.map((row) => normalizeRow(row, category));
  return { ...data, category, entries: cleaned };
}

function getStats(json) {
  const rows = json.entries || [];
  const byCity = { SF: 0, NYC: 0, other: 0, unknown: 0 };
  rows.forEach((row) => {
    const city = normalizeCity(row.city);
    if (!city) {
      byCity.unknown += 1;
    } else if (city === "SF") {
      byCity.SF += 1;
    } else if (city === "NYC") {
      byCity.NYC += 1;
    } else {
      byCity.other += 1;
    }
  });
  return { count: rows.length, by_city: byCity };
}

function rowMatches(row, query, fields) {
  const needle = String(query).toLowerCase();
  const searchFields = fields && fields.length ? fields : Object.keys(row);
  return searchFields.some((field) => {
    const value = row[field];
    if (Array.isArray(value)) {
      return value.join(" ").toLowerCase().includes(needle);
    }
    if (typeof value === "object" && value !== null) {
      return JSON.stringify(value).toLowerCase().includes(needle);
    }
    return String(value ?? "").toLowerCase().includes(needle);
  });
}

async function callTool(name, args) {
  if (name === "list_categories") {
    return Array.from(CATEGORY_SET);
  }

  if (name === "get_category") {
    const { category } = getCategorySchema.parse(args);
    const { json } = await loadCategory(category);
    return json;
  }

  if (name === "search_category") {
    const { category, query, fields } = searchCategorySchema.parse(args);
    const { json } = await loadCategory(category);
    const rows = (json.entries || []).filter((row) => rowMatches(row, query, fields));
    return { count: rows.length, results: rows };
  }

  if (name === "get_instructions") {
    const categories = Array.from(CATEGORY_SET);
    const stats = {};
    for (const category of categories) {
      const { json } = await loadCategory(category);
      stats[category] = getStats(json);
    }
    return {
      description: "Reach Out MCP. Use tools to query and update contact lists for founders, researchers, VCs, and angels.",
      required_fields: REQUIRED_FIELDS,
      optional_fields: OPTIONAL_FIELDS,
      city_values: ["SF", "NYC", "Other"],
      stats,
      files: [
        path.join(DATA_DIR, "founders.json"),
        path.join(DATA_DIR, "researchers.json"),
        path.join(DATA_DIR, "vcs.json"),
        path.join(DATA_DIR, "angels.json"),
        ...(HAS_GITHUB ? [
          `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/data/founders.json`,
          `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/data/researchers.json`,
          `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/data/vcs.json`,
          `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/data/angels.json`
        ] : [])
      ],
      pages_url: HAS_GITHUB ? `https://${OWNER.toLowerCase()}.github.io/${REPO}/` : null,
      storage: {
        data_dir: DATA_DIR,
        github_sync: ENABLE_GITHUB_SYNC
      },
      deploy: {
        hook_configured: Boolean(DEPLOY_HOOK_URL),
        auto_on_write: AUTO_DEPLOY_ON_WRITE,
        min_interval_ms: DEPLOY_MIN_INTERVAL_MS
      },
      sync: {
        debounce_ms: SYNC_DEBOUNCE_MS
      }
    };
  }

  if (name === "replace_category") {
    const { category, data } = replaceCategorySchema.parse(args);
    const payload = normalizeDataset(category, {
      ...data,
      last_updated: new Date().toISOString()
    });
    await writeLocalJson(category, payload);
    const queued = scheduleSync(category, payload, `Replace ${category} dataset`, `replace_category:${category}`);
    return { status: "ok", message: `Replaced ${category} dataset locally.`, ...queued };
  }

  if (name === "upsert_person") {
    const { category, id, name: personName, patch } = upsertPersonSchema.parse(args);
    const { json } = await loadCategory(category);
    const rows = Array.isArray(json.entries) ? json.entries : [];
    const idx = findPersonIndex(rows, id, personName);

    if (idx >= 0) {
      rows[idx] = normalizeRow({ ...rows[idx], ...patch, id: rows[idx].id }, category);
    } else {
      const newId = id || `${category}-new-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
      const newRow = normalizeRow({
        id: newId,
        name: personName || patch.name,
        ...patch
      }, category);
      rows.push(newRow);
    }

    const payload = { ...json, category, entries: rows, last_updated: new Date().toISOString() };
    await writeLocalJson(category, payload);
    const queued = scheduleSync(category, payload, `Upsert person in ${category}`, `upsert_person:${category}`);
    return { status: "ok", message: `Upserted person in ${category} (local).`, ...queued };
  }

  if (name === "delete_person") {
    const { category, id, name: personName } = deletePersonSchema.parse(args);
    if (!id && !personName) {
      throw new Error("Provide id or name to delete.");
    }
    const { json } = await loadCategory(category);
    const rows = Array.isArray(json.entries) ? json.entries : [];
    const idx = findPersonIndex(rows, id, personName);
    if (idx < 0) {
      return { status: "not_found", message: `No matching person in ${category}.` };
    }
    const [removed] = rows.splice(idx, 1);
    const payload = { ...json, category, entries: rows, last_updated: new Date().toISOString() };
    await writeLocalJson(category, payload);
    const queued = scheduleSync(category, payload, `Delete person in ${category}`, `delete_person:${category}`);
    return {
      status: "ok",
      message: `Deleted person in ${category}.`,
      deleted: { id: removed.id, name: removed.name },
      ...queued
    };
  }

  if (name === "get_schema") {
    return {
      required_fields: REQUIRED_FIELDS,
      optional_fields: OPTIONAL_FIELDS,
      city_values: ["SF", "NYC", "Other"],
      category_values: Array.from(CATEGORY_SET)
    };
  }

  if (name === "list_files") {
    return {
      files: [
        "data/founders.json",
        "data/researchers.json",
        "data/vcs.json",
        "data/angels.json"
      ]
    };
  }

  if (name === "get_file") {
    const { path: filePath } = getFileSchema.parse(args);
    if (!filePath.startsWith("data/")) {
      throw new Error("Only data/* files are accessible.");
    }
    const category = filePath.replace("data/", "").replace(".json", "");
    const { json } = await loadCategory(category);
    return json;
  }

  if (name === "trigger_deploy") {
    const { reason } = triggerDeploySchema.parse(args);
    return await triggerDeployThrottled(reason || "manual");
  }

  throw new Error(`Unknown tool: ${name}`);
}

const server = new Server(
  { name: "reach-out-mcp", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "list_categories",
        description: "List available categories.",
        inputSchema: z.object({})
      },
      {
        name: "get_category",
        description: "Fetch a category dataset.",
        inputSchema: getCategorySchema
      },
      {
        name: "search_category",
        description: "Search a category dataset by query string.",
        inputSchema: searchCategorySchema
      },
      {
        name: "get_instructions",
        description: "Return MCP usage instructions, schema, and dataset stats.",
        inputSchema: getInstructionsSchema
      },
      {
        name: "list_files",
        description: "List available data files.",
        inputSchema: listFilesSchema
      },
      {
        name: "get_file",
        description: "Fetch a data file (data/* only).",
        inputSchema: getFileSchema
      },
      {
        name: "replace_category",
        description: "Replace a category dataset (full overwrite).",
        inputSchema: replaceCategorySchema
      },
      {
        name: "upsert_person",
        description: "Update or insert a person in a category dataset.",
        inputSchema: upsertPersonSchema
      },
      {
        name: "delete_person",
        description: "Delete a person by id or name.",
        inputSchema: deletePersonSchema
      },
      {
        name: "get_schema",
        description: "Return required/optional fields and valid city values.",
        inputSchema: z.object({})
      },
      {
        name: "trigger_deploy",
        description: "Trigger a Vercel deploy via deploy hook (if configured).",
        inputSchema: triggerDeploySchema
      }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const result = await callTool(name, args || {});
  return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function sendJson(res, status, data, cors = true) {
  const headers = { "Content-Type": "application/json" };
  if (cors) headers["Access-Control-Allow-Origin"] = "*";
  res.writeHead(status, headers);
  res.end(JSON.stringify(data));
}

function sendRedirect(res, url) {
  res.writeHead(302, { "Location": url });
  res.end();
}

const httpServer = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Api-Key"
    });
    res.end();
    return;
  }

  // OAuth: Discovery endpoint
  if (req.method === "GET" && pathname === "/.well-known/oauth-authorization-server") {
    const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
    sendJson(res, 200, {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      token_endpoint_auth_methods_supported: ["client_secret_post"],
      code_challenge_methods_supported: ["S256"]
    });
    return;
  }

  // OAuth: Authorization endpoint
  if (req.method === "GET" && pathname === "/oauth/authorize") {
    const clientId = parsedUrl.searchParams.get("client_id");
    const redirectUri = parsedUrl.searchParams.get("redirect_uri");
    const state = parsedUrl.searchParams.get("state");
    const responseType = parsedUrl.searchParams.get("response_type");

    // Validate client_id
    if (clientId !== OAUTH_CLIENT_ID) {
      sendJson(res, 400, { error: "invalid_client", error_description: "Unknown client_id" });
      return;
    }

    // Validate redirect_uri
    if (!redirectUri || !OAUTH_REDIRECT_URIS.includes(redirectUri)) {
      sendJson(res, 400, { error: "invalid_request", error_description: "Invalid redirect_uri" });
      return;
    }

    // Validate response_type
    if (responseType !== "code") {
      sendRedirect(res, `${redirectUri}?error=unsupported_response_type&state=${state || ""}`);
      return;
    }

    // Generate auth code and redirect back
    const code = generateToken();
    authCodes.set(code, {
      clientId,
      redirectUri,
      expiresAt: Date.now() + AUTH_CODE_TTL
    });

    const callbackUrl = new URL(redirectUri);
    callbackUrl.searchParams.set("code", code);
    if (state) callbackUrl.searchParams.set("state", state);
    sendRedirect(res, callbackUrl.toString());
    return;
  }

  // OAuth: Token endpoint
  if (req.method === "POST" && pathname === "/oauth/token") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const grantType = params.get("grant_type");
    const code = params.get("code");
    const clientId = params.get("client_id");
    const clientSecret = params.get("client_secret");
    const redirectUri = params.get("redirect_uri");

    // Validate grant type
    if (grantType !== "authorization_code") {
      sendJson(res, 400, { error: "unsupported_grant_type" });
      return;
    }

    // Validate client credentials
    if (clientId !== OAUTH_CLIENT_ID) {
      sendJson(res, 400, { error: "invalid_client" });
      return;
    }

    if (OAUTH_CLIENT_SECRET && clientSecret !== OAUTH_CLIENT_SECRET) {
      sendJson(res, 400, { error: "invalid_client", error_description: "Invalid client_secret" });
      return;
    }

    // Validate auth code
    const authCode = authCodes.get(code);
    if (!authCode) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "Invalid or expired code" });
      return;
    }

    if (authCode.expiresAt < Date.now()) {
      authCodes.delete(code);
      sendJson(res, 400, { error: "invalid_grant", error_description: "Code expired" });
      return;
    }

    if (authCode.clientId !== clientId || authCode.redirectUri !== redirectUri) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "Code mismatch" });
      return;
    }

    // Consume auth code
    authCodes.delete(code);

    // Generate access token
    const accessToken = generateToken();
    accessTokens.set(accessToken, {
      clientId,
      expiresAt: Date.now() + ACCESS_TOKEN_TTL
    });

    sendJson(res, 200, {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.floor(ACCESS_TOKEN_TTL / 1000)
    });
    return;
  }

  // MCP endpoint - GET for instructions
  if (req.method === "GET" && pathname === "/mcp") {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { ok: false, error: "Unauthorized" });
      return;
    }
    try {
      const result = await callTool("get_instructions", {});
      sendJson(res, 200, { ok: true, result });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
    return;
  }

  // MCP endpoint - POST for tool calls
  if (req.method === "POST" && pathname === "/mcp") {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { ok: false, error: "Unauthorized" });
      return;
    }
    try {
      const body = await parseBody(req);
      const payload = JSON.parse(body || "{}");
      const result = await callTool(payload.tool, payload.arguments || {});
      sendJson(res, 200, { ok: true, result });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err.message });
    }
    return;
  }

  // Not found
  sendJson(res, 404, { error: "Not found" });
});

httpServer.listen(PORT, () => {
  process.stderr.write(`MCP HTTP bridge listening on http://localhost:${PORT}/mcp\n`);
  process.stderr.write(`OAuth endpoints: /oauth/authorize, /oauth/token\n`);
  process.stderr.write(`Discovery: /.well-known/oauth-authorization-server\n`);
});
