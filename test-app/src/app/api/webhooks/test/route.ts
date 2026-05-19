import { NextResponse } from "next/server"

// VULNERABILITY: Blind SSRF — fetches user-provided URL, no response echoed
// Scanner: oob_callback (#24)

export async function POST(request: Request) {
  const { webhook_url, event } = await request.json()

  if (!webhook_url) {
    return NextResponse.json({ error: "webhook_url required" }, { status: 400 })
  }

  // VULNERABILITY: Fetches arbitrary URL server-side (blind — no response content returned)
  // OOB callback will detect this via DNS/HTTP interaction
  try {
    await fetch(webhook_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event: event || "test", timestamp: Date.now() }),
    })
  } catch {
    // Silently fails — blind SSRF
  }

  return NextResponse.json({ status: "sent" })
}
