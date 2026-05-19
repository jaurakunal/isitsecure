import { NextResponse } from "next/server"

// VULNERABILITY: SSRF — fetches arbitrary URLs server-side
// Scanner: ssrf_scanner (#7)

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const url = searchParams.get("url")

  if (!url) {
    return NextResponse.json({ error: "URL required" }, { status: 400 })
  }

  // VULNERABILITY: No URL validation — can fetch internal IPs, AWS metadata, etc.
  try {
    const response = await fetch(url)
    const contentType = response.headers.get("content-type") || ""

    if (contentType.startsWith("image/")) {
      const buffer = await response.arrayBuffer()
      return new Response(buffer, {
        headers: { "Content-Type": contentType },
      })
    }

    // Returns the fetched content — leaks internal responses
    const text = await response.text()
    return NextResponse.json({ content: text.slice(0, 1000) })
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 })
  }
}
