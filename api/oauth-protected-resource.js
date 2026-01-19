export default function handler(req, res) {
  const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;

  res.status(200).json({
    resource: `${baseUrl}/api/mcp`,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp:read", "mcp:write"]
  });
}
