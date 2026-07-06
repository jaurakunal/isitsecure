# isitsecure web UI

The source for the isitsecure web interface — the "no CLI flags to remember" front end that `isitsecure launch` opens in your browser.

> **Most people don't need this directory.** The UI is already built and bundled into the Python package at `isitsecure/server/static/`. Running `isitsecure launch` serves that prebuilt copy — you don't have to build anything here. This folder only matters if you want to **change** the UI.

## How it fits together

This is a [Next.js](https://nextjs.org) app configured as a **static export** (`output: "export"` in `next.config.ts`) — it compiles to plain HTML/JS/CSS with no Node server at runtime.

```
ui/ (this dir, Next.js source)
  └─ npm run build  ──►  ui/out/  ──(copy)──►  isitsecure/server/static/
                                                        │
                                     isitsecure launch  │  (FastAPI + uvicorn)
                                                        ▼
                               serves the static UI  +  /api/* endpoints
                                     on http://127.0.0.1:3000
```

At runtime the FastAPI backend (`isitsecure/server/app.py`) serves both the static UI (mounted at `/`) and the JSON/SSE API it calls (`/api/scan`, `/api/scan/{id}/stream`, `/api/scan/{id}/report`, `/api/fix`, `/api/health`) on the **same origin**. That's why `src/lib/api.ts` defaults `API_BASE` to `http://localhost:3000` — the port `isitsecure launch` uses.

## Structure

| Path | What it is |
|---|---|
| `src/app/page.tsx` | Home / landing |
| `src/app/scan/page.tsx` | Scan configuration + live progress (streams `/api/scan/{id}/stream` via `EventSource`) |
| `src/app/report/page.tsx` | Findings browser with grade, severity filtering, and remediation |
| `src/app/history/page.tsx` | Past scans — stored **client-side** in `localStorage` (see `src/lib/storage.ts`), not on any server |
| `src/lib/api.ts` | Backend client + shared TypeScript types (`ScanReport`, `Finding`, …) |
| `src/components/` | `GradeBadge`, `SeverityBadge`, `FindingCard` |

## Local development

The backend and the Next dev server both default to port 3000, so run the backend on a different port and point the UI at it:

```bash
# Terminal 1 — run the Python backend (from the repo root) on a spare port
isitsecure launch --port 8000

# Terminal 2 — run the UI dev server (from this ui/ dir), pointing at that backend
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

Open http://localhost:3000. Edits under `src/` hot-reload.

## Build and ship a UI change

There is **no automated step** that copies the build into the Python package — it is manual, and the change won't reach users until you do it and commit the result:

```bash
npm run build                          # writes the static export to ui/out/
rm -rf ../isitsecure/server/static     # clear the old bundle
cp -r out/. ../isitsecure/server/static
git add ../isitsecure/server/static ui/src   # commit BOTH the source and the built output
```

If you edit `ui/` but skip this copy, `isitsecure launch` will keep serving the old UI.

## Next.js version note

See `AGENTS.md` — this project pins **Next.js 16**, which has breaking changes relative to older majors. Check `node_modules/next/dist/docs/` before writing code rather than relying on older conventions.

## Requirements

Node.js 18+ and npm. Only needed for UI development — end users of isitsecure never touch this.
