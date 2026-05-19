import { NextResponse } from "next/server"
import { getUserFromRequest } from "@/lib/auth"
import { updateRow, getById } from "@/lib/db"

// VULNERABILITY: Prototype pollution via JSON body
// Scanner: body_param_fuzzer (#23)

export async function PATCH(request: Request) {
  const user = getUserFromRequest(request)
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const body = await request.json()

  // VULNERABILITY: Spreads entire body into preferences without sanitization
  // __proto__ or constructor.prototype keys can pollute Object prototype
  const settings = await getById("settings", user.userId)
  const currentPrefs = settings[0]?.preferences || {}
  const merged = { ...currentPrefs, ...body }

  await updateRow("settings", settings[0].id, { preferences: JSON.stringify(merged) })

  return NextResponse.json({ preferences: merged })
}
