import crypto from "crypto";

const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "reach-out-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
const AUTH_CODE_SECRET = process.env.AUTH_CODE_SECRET || process.env.OAUTH_CLIENT_SECRET || "default-secret";
const DCR_SECRET = process.env.DCR_SECRET || process.env.OAUTH_CLIENT_SECRET || "default-dcr-secret";
const ACCESS_TOKEN_TTL = 24 * 60 * 60 * 1000; // 24 hours

// Verify a dynamically registered client secret
function verifyDynamicClient(clientId, clientSecret) {
  if (!clientId || !clientId.startsWith("dyn-")) return false;
  if (!clientSecret) return false;

  try {
    const [payloadB64, signature] = clientSecret.split(".");
    if (!payloadB64 || !signature) return false;

    const payload = Buffer.from(payloadB64, "base64url").toString();
    const expectedSig = crypto.createHmac("sha256", DCR_SECRET).update(payload).digest("hex");

    if (signature !== expectedSig) return false;

    const data = JSON.parse(payload);
    return data.client_id === clientId;
  } catch {
    return false;
  }
}

function verifyAuthCode(code) {
  try {
    const [payloadB64, signature] = code.split(".");
    if (!payloadB64 || !signature) return null;

    const payload = Buffer.from(payloadB64, "base64url").toString();
    const expectedSig = crypto.createHmac("sha256", AUTH_CODE_SECRET).update(payload).digest("hex");

    if (signature !== expectedSig) return null;

    const data = JSON.parse(payload);
    if (data.expiresAt < Date.now()) return null;

    return data;
  } catch {
    return null;
  }
}

function generateAccessToken() {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + ACCESS_TOKEN_TTL;
  const payload = JSON.stringify({ token, expiresAt });
  const signature = crypto.createHmac("sha256", AUTH_CODE_SECRET).update(payload).digest("hex");
  return Buffer.from(payload).toString("base64url") + "." + signature;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method_not_allowed" });
  }

  // Parse body (could be form-urlencoded or JSON)
  let params;
  if (typeof req.body === "string") {
    params = new URLSearchParams(req.body);
  } else if (req.body && typeof req.body === "object") {
    params = new URLSearchParams(req.body);
  } else {
    return res.status(400).json({ error: "invalid_request" });
  }

  const grantType = params.get("grant_type");
  const code = params.get("code");
  const clientId = params.get("client_id");
  const clientSecret = params.get("client_secret");
  const redirectUri = params.get("redirect_uri");

  // Validate grant type
  if (grantType !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  // Validate client credentials (static or dynamic)
  const isStaticClient = clientId === OAUTH_CLIENT_ID;
  const isDynamic = verifyDynamicClient(clientId, clientSecret);

  if (!isStaticClient && !isDynamic) {
    return res.status(400).json({ error: "invalid_client" });
  }

  if (isStaticClient && OAUTH_CLIENT_SECRET && clientSecret !== OAUTH_CLIENT_SECRET) {
    return res.status(400).json({ error: "invalid_client", error_description: "Invalid client_secret" });
  }

  // Validate auth code
  const authCode = verifyAuthCode(code);
  if (!authCode) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Invalid or expired code" });
  }

  if (authCode.clientId !== clientId || authCode.redirectUri !== redirectUri) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Code mismatch" });
  }

  // Generate access token
  const accessToken = generateAccessToken();

  res.status(200).json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: Math.floor(ACCESS_TOKEN_TTL / 1000)
  });
}
