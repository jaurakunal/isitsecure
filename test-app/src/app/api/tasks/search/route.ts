import { NextResponse } from "next/server"
import { query } from "@/lib/db"

// VULNERABILITY: Reflected XSS — search query echoed unescaped in HTML response
// Scanner: xss_scanner (#1)

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const q = searchParams.get("q") || ""

  const tasks = await query("tasks", `title ILIKE '%${q}%'`)

  // VULNERABILITY: Query reflected in HTML without escaping
  const html = `
    <html>
    <body>
      <h1>Search results for: ${q}</h1>
      <div id="results">
        ${tasks.map((t: any) => `<div class="task">${t.title}</div>`).join("")}
      </div>
    </body>
    </html>
  `

  return new Response(html, {
    headers: { "Content-Type": "text/html" },
  })
}
