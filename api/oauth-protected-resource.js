export default function handler(req, res) {
  const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;

  res.setHeader("Access-Control-Allow-Origin", "*");

  res.status(200).json({
    resource: `${baseUrl}/mcp`,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp:read", "mcp:write"]
  });
}
