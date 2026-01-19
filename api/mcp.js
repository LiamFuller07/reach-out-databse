import crypto from "crypto";

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
  // Check Bearer token (OAuth)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    if (verifyAccessToken(token)) return true;
  }

  // Check API key (legacy)
  const apiKey = process.env.MCP_API_KEY || "";
  if (apiKey) {
    const provided = req.headers["x-api-key"];
    return provided === apiKey;
  }

  // No auth configured - allow for development
  const oauthSecret = process.env.OAUTH_CLIENT_SECRET || "";
  return !oauthSecret && !apiKey;
}

export default async function handler(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Api-Key");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  // Auth check
  if (!isAuthorized(req)) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }

  if (req.method !== "POST" && req.method !== "GET") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  try {
    const endpoint = process.env.MCP_ENDPOINT || "http://localhost:3333/mcp";
    const apiKey = process.env.MCP_API_KEY || "";

    if (req.method === "GET") {
      // Forward GET for instructions
      const upstream = await fetch(endpoint, {
        method: "GET",
        headers: {
          ...(apiKey ? { "X-Api-Key": apiKey } : {})
        }
      });
      const data = await upstream.json();
      return res.status(upstream.ok ? 200 : upstream.status).json(data);
    }

    // POST - tool calls
    const payload = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});

    const upstream = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { "X-Api-Key": apiKey } : {})
      },
      body: JSON.stringify(payload)
    });

    const data = await upstream.json();
    res.status(upstream.ok ? 200 : upstream.status).json(data);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || "Proxy error" });
  }
}
