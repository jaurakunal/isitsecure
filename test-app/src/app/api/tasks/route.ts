import { NextResponse } from "next/server"
import { query, insertRow } from "@/lib/db"

// VULNERABILITY: No authentication check on task endpoints
// Scanner: route_auth_analyzer (#26)

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const status = searchParams.get("status")

  // VULNERABILITY: Raw SQL injection via status parameter
  // Scanner: active_injection_scanner (#2)
  const filter = status ? `status = '${status}'` : undefined
  const tasks = await query("tasks", filter)

  return NextResponse.json(tasks)
}

export async function POST(request: Request) {
  // VULNERABILITY: No CSRF protection, no auth check
  // Scanner: csrf_scanner (#3)
  const body = await request.json()

  const task = await insertRow("tasks", {
    title: body.title,
    description: body.description,
    status: "pending",
    user_id: body.user_id,  // User controls which user_id to assign
  })

  return NextResponse.json(task, { status: 201 })
}
