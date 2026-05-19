// VULNERABILITY: Weak JWT secret, no algorithm restriction
// Scanner: jwt_scanner (#17)

const JWT_SECRET = process.env.JWT_SECRET || "secret"

// Minimal base64url helpers (no external dependency needed)
function base64url(str: string): string {
  return Buffer.from(str).toString("base64url")
}

function base64urlDecode(str: string): string {
  return Buffer.from(str, "base64url").toString()
}

export function signToken(payload: { userId: string; email: string; role: string }) {
  // VULNERABILITY: No expiration, weak secret, manual JWT construction
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))
  const body = base64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000) }))

  const crypto = require("crypto")
  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(`${header}.${body}`)
    .digest("base64url")

  return `${header}.${body}.${signature}`
}

export function verifyToken(token: string) {
  try {
    const parts = token.split(".")
    if (parts.length !== 3) return null

    const header = JSON.parse(base64urlDecode(parts[0]))

    // VULNERABILITY: Accepts alg:none — no signature verification
    if (header.alg === "none") {
      return JSON.parse(base64urlDecode(parts[1]))
    }

    // VULNERABILITY: Weak secret "secret"
    const crypto = require("crypto")
    const expected = crypto
      .createHmac("sha256", JWT_SECRET)
      .update(`${parts[0]}.${parts[1]}`)
      .digest("base64url")

    if (expected !== parts[2]) return null

    return JSON.parse(base64urlDecode(parts[1])) as {
      userId: string
      email: string
      role: string
    }
  } catch {
    return null
  }
}

export function getUserFromRequest(request: Request) {
  const authHeader = request.headers.get("Authorization")
  if (!authHeader?.startsWith("Bearer ")) return null

  const token = authHeader.slice(7)
  return verifyToken(token)
}
