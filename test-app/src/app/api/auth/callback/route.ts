import { NextResponse } from "next/server"

// VULNERABILITY: Open redirect — redirect_to parameter not validated
// Scanner: open_redirect_scanner (#12)

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const redirectTo = searchParams.get("redirect_to") || "/"

  // VULNERABILITY: Redirects to any URL without validation
  return NextResponse.redirect(redirectTo)
}
