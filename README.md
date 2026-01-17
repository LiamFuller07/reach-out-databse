# Reach Out Database

Lightweight, local-first contact tracker with tabs for founders, researchers, VCs, and angel investors.

## Structure

- `index.html` - single-page UI (AG Grid)
- `data/` - fallback JSON data per category
- `api/mcp.js` - Vercel serverless proxy to the MCP server
- `mcp-server/` - MCP server that reads/writes `data/*.json`

## Run

Open `index.html` in a browser or host the repo (Vercel, GitHub Pages, etc.).

## MCP Server

```bash
cd mcp-server
npm install
export MCP_API_KEY=your_shared_key
npm start
```

Optional env vars for GitHub sync and Vercel deploy hooks are listed in `mcp-server/.env.example`.
