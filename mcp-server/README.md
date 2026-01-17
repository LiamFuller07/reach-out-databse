# Reach Out MCP Server

Local-first MCP server for a lightweight contact database. Reads/writes `data/*.json` on disk and can optionally sync to GitHub and trigger Vercel deploys.

## Setup

```bash
cd mcp-server
npm install
export MCP_API_KEY=your_shared_key
npm start
```

Optional env vars for GitHub sync and deploy hooks are in `.env.example`.

## Tools

- `list_categories` -> returns `founders, researchers, vcs, angels`
- `get_category` `{ category }`
- `search_category` `{ category, query, fields? }` -> `{ count, results }`
- `replace_category` `{ category, data }` (local write + optional GitHub sync)
- `upsert_person` `{ category, id?, name?, patch }` (local write + optional GitHub sync)
- `delete_person` `{ category, id?, name? }` (local write + optional GitHub sync)
- `get_instructions` `{}` -> schema + stats
- `get_schema` `{}` -> required/optional fields + city normalization
- `list_files` `{}` -> `{ files }`
- `get_file` `{ path }` -> JSON (data/* only)
- `trigger_deploy` `{ reason? }` -> POST the Vercel deploy hook (if configured)

## Auth

If `MCP_API_KEY` is set, clients must send:

```
X-Api-Key: your_shared_key
```

## Throttling

You can reduce GitHub and deploy hook bursts with:

```
SYNC_DEBOUNCE_MS=8000
DEPLOY_MIN_INTERVAL_MS=60000
```
