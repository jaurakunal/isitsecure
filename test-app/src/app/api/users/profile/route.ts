import { NextResponse } from "next/server"
import { getById, updateRow } from "@/lib/db"
import { getUserFromRequest } from "@/lib/auth"

// VULNERABILITY: Mass assignment — accepts role and isAdmin in body
// Scanner: mass_assignment_scanner (#9), guided_dast: mass_assignment (#47)

export async function GET(request: Request) {
  const user = getUserFromRequest(request)
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const profile = await getById("profiles", user.userId)
  return NextResponse.json(profile[0])
}

export async function PATCH(request: Request) {
  const user = getUserFromRequest(request)
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  // VULNERABILITY: Accepts any field including role, is_admin
  // No field filtering — whatever the client sends gets written
  const body = await request.json()

  const updated = await updateRow("profiles", user.userId, body)
  return NextResponse.json(updated[0])
}
