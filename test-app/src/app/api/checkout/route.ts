import { NextResponse } from "next/server"
import { getUserFromRequest } from "@/lib/auth"
import { query, insertRow } from "@/lib/db"

// VULNERABILITY: Price manipulation, no idempotency
// Scanner: llm_code_reviewer (#39), financial_operation trigger (#50)
// Scanner: llm_business_logic_scanner (#41)

export async function POST(request: Request) {
  const user = getUserFromRequest(request)
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const body = await request.json()

  // VULNERABILITY: Accepts price from client instead of looking it up server-side
  const { plan, price } = body

  // VULNERABILITY: No idempotency key — double-submit charges twice
  const order = await insertRow("orders", {
    user_id: user.userId,
    plan: plan,
    amount: price,  // Client-controlled price!
    status: "paid",
  })

  return NextResponse.json({ order: order[0], message: "Payment processed" })
}
