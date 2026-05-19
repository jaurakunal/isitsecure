import { NextResponse } from "next/server"
import { query, updateRow } from "@/lib/db"

// VULNERABILITY: No authentication check — any user can access admin endpoints
// Scanner: privilege_escalation_scanner (#19), route_auth_analyzer (#26)

export async function GET(request: Request) {
  // Should check for admin role but doesn't
  const users = await query("profiles")

  return NextResponse.json(users)
}

export async function PATCH(request: Request) {
  // VULNERABILITY: Any user can promote themselves to admin
  const body = await request.json()
  const { userId, role } = body

  const updated = await updateRow("profiles", userId, { role, is_admin: role === "admin" })

  return NextResponse.json(updated[0])
}
