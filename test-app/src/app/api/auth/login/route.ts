import { NextResponse } from "next/server"
import { query } from "@/lib/db"
import { signToken } from "@/lib/auth"

// VULNERABILITY: Username enumeration, no rate limiting, default credentials
// Scanner: auth_bypass_scanner (#13), rate_limit_scanner (#4)

export async function POST(request: Request) {
  const { email, password } = await request.json()

  const users = await query("profiles", `email = '${email}'`)

  // VULNERABILITY: Different error messages for "user not found" vs "wrong password"
  // Scanner: auth_bypass_scanner — username enumeration
  if (!users || users.length === 0) {
    return NextResponse.json(
      { error: "No account found with that email" },
      { status: 404 }
    )
  }

  const user = users[0]

  // VULNERABILITY: Default credentials — admin/admin
  // In a real app this would check a hashed password
  if (email === "admin@vibetasks.com" && password === "admin") {
    const token = signToken({ userId: user.id, email: user.email, role: "admin" })
    return NextResponse.json({ token, user })
  }

  // Simplified password check (not production-ready)
  if (password !== "password123") {
    return NextResponse.json(
      { error: "Invalid password" },
      { status: 401 }
    )
  }

  // VULNERABILITY: No rate limiting — can brute force indefinitely
  const token = signToken({ userId: user.id, email: user.email, role: user.role })
  return NextResponse.json({ token, user })
}
