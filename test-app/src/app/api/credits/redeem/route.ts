import { NextResponse } from "next/server"
import { getUserFromRequest } from "@/lib/auth"
import { query, updateRow } from "@/lib/db"

// VULNERABILITY: Race condition — no mutex on balance check + deduction
// Scanner: race_condition_scanner (#21), guided_dast: race_condition (#48)
// Scanner: llm_code_reviewer via financial_operation trigger (#50)

export async function POST(request: Request) {
  const user = getUserFromRequest(request)
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const { amount } = await request.json()

  // VULNERABILITY: TOCTOU — read balance, then deduct, no transaction/lock
  // Concurrent requests can both read balance=100, both deduct 100, resulting in -100
  const credits = await query("credits", `user_id = '${user.userId}'`)

  if (!credits || credits.length === 0) {
    return NextResponse.json({ error: "No credits found" }, { status: 404 })
  }

  const currentBalance = credits[0].balance

  if (currentBalance < amount) {
    return NextResponse.json({ error: "Insufficient credits" }, { status: 400 })
  }

  // Time gap between check and update — race window
  const newBalance = currentBalance - amount
  await updateRow("credits", credits[0].id, { balance: newBalance })

  return NextResponse.json({
    previousBalance: currentBalance,
    redeemed: amount,
    newBalance: newBalance,
  })
}
