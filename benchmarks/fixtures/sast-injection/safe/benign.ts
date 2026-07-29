// Injection benchmark fixture — SAFE / benign near-misses.
// NOTHING in this file may be flagged. Each case is deliberately close to a
// vulnerable shape but is not actually injectable — this is the false-positive
// side of the scorecard.

import { sql } from "../vulnerable/db";
import fs from "fs";
import path from "path";

// SAFE: parameterized query (tagged template, not `.unsafe`) — the correct fix
export async function getUser(id: string) {
  return sql`SELECT * FROM users WHERE id = ${id}`;
}

// SAFE: non-DB `.query()` with interpolation (analytics client, not SQL)
declare const analytics: { query: (s: string) => void };
export function track(name: string) {
  analytics.query(`event ${name} fired`);
}

// SAFE: GraphQL client `.query` with interpolation — not a SQL sink
declare const gqlClient: { query: (s: string) => Promise<unknown> };
export function fetchUser(id: string) {
  return gqlClient.query(`query { user(id: ${id}) { name } }`);
}

// SAFE: constant-path file write (no user-derived filename)
export function writeLog(data: string) {
  fs.writeFile(path.join(__dirname, "app.log"), data, () => {});
  fs.writeFileSync(path.join(process.cwd(), "out.txt"), data);
}

// SAFE: value passes through a recognized sanitizer before the response, which
// breaks the taint flow (tests sanitizer recognition, not a specific escaper).
export function reflect(req: Request) {
  const url = new URL(req.url);
  const q = encodeURIComponent(url.searchParams.get("q") ?? "");
  return new Response(`<h1>Results for ${q}</h1>`, {
    headers: { "content-type": "text/html" },
  });
}

// SAFE: fetch to a fixed, non-user-controlled URL
export async function health() {
  return fetch("https://api.internal.example.com/health");
}
