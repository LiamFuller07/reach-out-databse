import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import http from "http";

const OWNER = process.env.GITHUB_OWNER || "LiamFuller07";
const REPO = process.env.GITHUB_REPO || "reach-out-databse";
const BRANCH = process.env.GITHUB_BRANCH || "main";
const TOKEN = process.env.GITHUB_TOKEN;
const PORT = Number(process.env.PORT || process.env.MCP_PORT || 3333);
const API_KEY = process.env.MCP_API_KEY || "";
const HAS_GITHUB = Boolean(TOKEN && OWNER && REPO && BRANCH);
const ENABLE_GITHUB_SYNC = process.env.ENABLE_GITHUB_SYNC !== "false" && HAS_GITHUB;
const DEPLOY_HOOK_URL = process.env.VERCEL_DEPLOY_HOOK_URL || "";
const AUTO_DEPLOY_ON_WRITE = process.env.AUTO_DEPLOY_ON_WRITE === "true";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || path.resolve(__dirname, "../data");

const CATEGORY_SET = new Set(["founders", "researchers", "vcs", "angels"]);
const REQUIRED_FIELDS = ["id", "name"];
const OPTIONAL_FIELDS = ["city", "tags", "links", "notes"];
const CITY_ALIASES = new Map([
  ["SF", "SF"],
  ["SAN FRANCISCO", "SF"],
  ["SANFRANCISCO", "SF"],
  ["NYC", "NYC"],
  ["NEW YORK", "NYC"],
  ["NEW YORK CITY", "NYC"]
]);

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
    notes: row.notes ? String(row.notes) : ""
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
        auto_on_write: AUTO_DEPLOY_ON_WRITE
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
    const sync = await syncGithubCategory(category, payload, `Replace ${category} dataset`);
    const deploy = AUTO_DEPLOY_ON_WRITE ? await triggerDeploy(`replace_category:${category}`) : { triggered: false, reason: "auto deploy disabled" };
    return { status: "ok", message: `Replaced ${category} dataset locally.`, sync, deploy };
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
    const sync = await syncGithubCategory(category, payload, `Upsert person in ${category}`);
    const deploy = AUTO_DEPLOY_ON_WRITE ? await triggerDeploy(`upsert_person:${category}`) : { triggered: false, reason: "auto deploy disabled" };
    return { status: "ok", message: `Upserted person in ${category} (local).`, sync, deploy };
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
    const sync = await syncGithubCategory(category, payload, `Delete person in ${category}`);
    const deploy = AUTO_DEPLOY_ON_WRITE ? await triggerDeploy(`delete_person:${category}`) : { triggered: false, reason: "auto deploy disabled" };
    return {
      status: "ok",
      message: `Deleted person in ${category}.`,
      deleted: { id: removed.id, name: removed.name },
      sync,
      deploy
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
    return await triggerDeploy(reason || "manual");
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

const httpServer = http.createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/mcp") {
    if (req.method === "GET" && req.url === "/mcp") {
      if (API_KEY) {
        const provided = req.headers["x-api-key"];
        if (provided !== API_KEY) {
          res.writeHead(401, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
          res.end(JSON.stringify({ ok: false, error: "Unauthorized" }));
          return;
        }
      }
      try {
        const result = await callTool("get_instructions", {});
        res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify({ ok: true, result }));
        return;
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify({ ok: false, error: err.message }));
        return;
      }
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
    return;
  }

  if (API_KEY) {
    const provided = req.headers["x-api-key"];
    if (provided !== API_KEY) {
      res.writeHead(401, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
      res.end(JSON.stringify({ ok: false, error: "Unauthorized" }));
      return;
    }
  }

  let body = "";
  req.on("data", chunk => { body += chunk; });
  req.on("end", async () => {
    try {
      const payload = JSON.parse(body || "{}");
      const result = await callTool(payload.tool, payload.arguments || {});
      res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
      res.end(JSON.stringify({ ok: true, result }));
    } catch (err) {
      res.writeHead(400, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
      res.end(JSON.stringify({ ok: false, error: err.message }));
    }
  });
});

httpServer.listen(PORT, () => {
  process.stderr.write(`MCP HTTP bridge listening on http://localhost:${PORT}/mcp\n`);
});
