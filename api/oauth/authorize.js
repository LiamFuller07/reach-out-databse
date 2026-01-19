import crypto from "crypto";

const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "reach-out-client";
const OAUTH_REDIRECT_URIS = (process.env.OAUTH_REDIRECT_URIS || "https://claude.ai/oauth/callback").split(",").map(s => s.trim());
const AUTH_CODE_SECRET = process.env.AUTH_CODE_SECRET || process.env.OAUTH_CLIENT_SECRET || "default-secret";

function generateAuthCode(clientId, redirectUri) {
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
  const payload = JSON.stringify({ clientId, redirectUri, expiresAt });
  const signature = crypto.createHmac("sha256", AUTH_CODE_SECRET).update(payload).digest("hex");
  const code = Buffer.from(payload).toString("base64url") + "." + signature;
  return code;
}

export default function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "method_not_allowed" });
  }

  const clientId = req.query.client_id;
  const redirectUri = req.query.redirect_uri;
  const state = req.query.state;
  const responseType = req.query.response_type;

  // Validate client_id
  if (clientId !== OAUTH_CLIENT_ID) {
    return res.status(400).json({ error: "invalid_client", error_description: "Unknown client_id" });
  }

  // Validate redirect_uri
  if (!redirectUri || !OAUTH_REDIRECT_URIS.includes(redirectUri)) {
    return res.status(400).json({ error: "invalid_request", error_description: "Invalid redirect_uri" });
  }

  // Validate response_type
  if (responseType !== "code") {
    const url = new URL(redirectUri);
    url.searchParams.set("error", "unsupported_response_type");
    if (state) url.searchParams.set("state", state);
    return res.redirect(302, url.toString());
  }

  // Generate auth code
  const code = generateAuthCode(clientId, redirectUri);

  // Redirect back with code
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);

  res.redirect(302, url.toString());
}
