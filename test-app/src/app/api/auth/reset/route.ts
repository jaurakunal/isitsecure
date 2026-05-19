import { NextResponse } from "next/server"
import { query } from "@/lib/db"
import crypto from "crypto"

// VULNERABILITY: Reset token leaked in response, no rate limiting
// Scanner: password_reset_scanner (#15)

export async function POST(request: Request) {
  const { email } = await request.json()

  const users = await query("profiles", `email = '${email}'`)

  // VULNERABILITY: Different response for valid vs invalid email
  if (!users || users.length === 0) {
    return NextResponse.json({ error: "Email not found" }, { status: 404 })
  }

  // Generate reset token
  const resetToken = crypto.randomBytes(32).toString("hex")

  // VULNERABILITY: Token returned in response body (should only be sent via email)
  return NextResponse.json({
    message: "Reset link sent",
    token: resetToken,
    resetUrl: `https://vibetasks.com/reset?token=${resetToken}`,
  })
}
