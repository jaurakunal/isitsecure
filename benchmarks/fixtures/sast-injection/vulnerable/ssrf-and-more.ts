// Injection benchmark fixture — SSRF, path traversal, command injection (VULNERABLE).

import { exec } from "child_process";
import fs from "fs";
import path from "path";

// --- SSRF: user-controlled URL → outbound fetch ---
export async function proxy(req: Request) {
  const url = new URL(req.url);
  const target = url.searchParams.get("url");
  return fetch(target as string); // EXPECT ssrf
}

// --- Path traversal: request-derived filename → fs write ---
export async function upload(req: any, uploadDir: string) {
  const filename = req.body.filename;
  fs.writeFile(path.join(uploadDir, filename), req.body.data, () => {}); // EXPECT path-traversal
}

// --- Command injection: user input → shell ---
export function ping(req: any) {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`); // EXPECT command-injection
}
