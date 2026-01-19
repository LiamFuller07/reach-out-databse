import crypto from "crypto";

const DCR_SECRET = process.env.DCR_SECRET || process.env.OAUTH_CLIENT_SECRET || "default-dcr-secret";

// Generate a signed client secret that encodes the registration info
function generateClientCredentials(redirectUris, clientName) {
  const clientId = `dyn-${crypto.randomBytes(16).toString("hex")}`;

  // Encode registration info in the client_secret
  const payload = JSON.stringify({
    client_id: clientId,
    redirect_uris: redirectUris,
    client_name: clientName,
    created_at: Date.now()
  });

  const signature = crypto.createHmac("sha256", DCR_SECRET).update(payload).digest("hex");
  const client_secret = Buffer.from(payload).toString("base64url") + "." + signature;

  return { client_id: clientId, client_secret };
}

export default async function handler(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "method_not_allowed" });
  }

  try {
    // Parse body
    let registration;
    if (typeof req.body === "string") {
      registration = JSON.parse(req.body || "{}");
    } else {
      registration = req.body || {};
    }

    // Extract redirect URIs (required)
    const redirect_uris = registration.redirect_uris || [];
    if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "redirect_uris required"
      });
    }

    const client_name = registration.client_name || "Dynamic Client";

    // Generate credentials
    const { client_id, client_secret } = generateClientCredentials(redirect_uris, client_name);

    // Return registration response
    res.status(201).json({
      client_id,
      client_secret,
      client_secret_expires_at: 0, // Never expires
      redirect_uris,
      client_name,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post"
    });
  } catch (err) {
    res.status(400).json({
      error: "invalid_request",
      error_description: err.message
    });
  }
}
