export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: "Method not allowed" });
    return;
  }

  try {
    const endpoint = process.env.MCP_ENDPOINT || "http://localhost:3333/mcp";
    const apiKey = process.env.MCP_API_KEY || "";
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
