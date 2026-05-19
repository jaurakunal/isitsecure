import jwt from "jsonwebtoken"

// VULNERABILITY: Weak JWT secret, no algorithm restriction
// Scanner: jwt_scanner (#17)

const JWT_SECRET = process.env.JWT_SECRET || "secret"

export function signToken(payload: { userId: string; email: string; role: string }) {
  // VULNERABILITY: No expiration set, weak secret
  return jwt.sign(payload, JWT_SECRET)
}

export function verifyToken(token: string) {
  try {
    // VULNERABILITY: Does not restrict algorithms — accepts alg:none
    return jwt.verify(token, JWT_SECRET) as {
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
