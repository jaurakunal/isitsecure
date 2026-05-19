import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

// VULNERABILITY: Middleware only protects /dashboard, not /api routes
// Scanner: middleware_analyzer (#28)
export function middleware(request: NextRequest) {
  const token = request.cookies.get("auth_token")?.value

  // Only check auth for dashboard pages — API routes are "handled internally"
  if (request.nextUrl.pathname.startsWith("/dashboard")) {
    if (!token) {
      return NextResponse.redirect(new URL("/login", request.url))
    }
  }

  // VULNERABILITY: CORS headers set globally with wildcard
  // Scanner: cors_scanner (#11)
  const response = NextResponse.next()
  response.headers.set("Access-Control-Allow-Origin", "*")
  response.headers.set("Access-Control-Allow-Credentials", "true")
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
  response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization")

  return response
}

export const config = {
  matcher: ["/dashboard/:path*", "/api/:path*"],
}
