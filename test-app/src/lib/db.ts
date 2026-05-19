import postgres from "postgres"

// VULNERABILITY: Raw SQL concatenation helper used by many routes
// Scanner: llm_code_reviewer via import_graph_centrality (#53)
// Scanner: injection_analyzer (#54)

// In-memory store for standalone mode (no Postgres required)
const SEED_DATA: Record<string, any[]> = {
  profiles: [
    { id: "11111111-1111-1111-1111-111111111111", email: "admin@vibetasks.com", display_name: "Admin", role: "admin", is_admin: true, avatar_url: null, created_at: new Date().toISOString() },
    { id: "22222222-2222-2222-2222-222222222222", email: "alice@example.com", display_name: "Alice", role: "user", is_admin: false, avatar_url: null, created_at: new Date().toISOString() },
    { id: "33333333-3333-3333-3333-333333333333", email: "bob@example.com", display_name: "Bob", role: "user", is_admin: false, avatar_url: null, created_at: new Date().toISOString() },
  ],
  tasks: [
    { id: "aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa", user_id: "22222222-2222-2222-2222-222222222222", title: "Fix landing page", description: "The hero section is broken", status: "pending", priority: 1, created_at: new Date().toISOString() },
    { id: "aaaa2222-aaaa-aaaa-aaaa-aaaaaaaaaaaa", user_id: "22222222-2222-2222-2222-222222222222", title: "Add dark mode", description: "Users keep asking for it", status: "in_progress", priority: 2, created_at: new Date().toISOString() },
    { id: "bbbb1111-bbbb-bbbb-bbbb-bbbbbbbbbbbb", user_id: "33333333-3333-3333-3333-333333333333", title: "Deploy to Vercel", description: "Bob's private task", status: "pending", priority: 0, created_at: new Date().toISOString() },
  ],
  credits: [
    { id: "cccc1111-cccc-cccc-cccc-cccccccccccc", user_id: "22222222-2222-2222-2222-222222222222", balance: 100, last_redeemed_at: null },
    { id: "cccc2222-cccc-cccc-cccc-cccccccccccc", user_id: "33333333-3333-3333-3333-333333333333", balance: 50, last_redeemed_at: null },
  ],
  settings: [
    { id: "dddd1111-dddd-dddd-dddd-dddddddddddd", user_id: "22222222-2222-2222-2222-222222222222", preferences: {}, notifications_enabled: true },
  ],
  orders: [],
}

const memDb: Record<string, any[]> = JSON.parse(JSON.stringify(SEED_DATA))

const USE_MEMORY = !process.env.DATABASE_URL

// Only connect to Postgres if DATABASE_URL is set
const sql = USE_MEMORY ? null : postgres(process.env.DATABASE_URL!)

// Simple filter evaluator for in-memory mode
// Handles: "status = 'pending'", "email = 'alice@example.com'", "user_id = '...'"
// VULNERABILITY: Still demonstrates SQL concat pattern for SAST scanners
function evalFilter(rows: any[], filter: string): any[] {
  // Match simple "column = 'value'" or "column ILIKE '%value%'"
  const eqMatch = filter.match(/^(\w+)\s*=\s*'([^']*)'$/)
  if (eqMatch) {
    const [, col, val] = eqMatch
    return rows.filter(r => String(r[col]) === val)
  }
  const ilikeMatch = filter.match(/^(\w+)\s+ILIKE\s+'%([^%]*)%'$/i)
  if (ilikeMatch) {
    const [, col, val] = ilikeMatch
    return rows.filter(r => String(r[col] || "").toLowerCase().includes(val.toLowerCase()))
  }
  return rows
}

export async function query(table: string, filter?: string) {
  // VULNERABILITY: SQL injection via string concatenation
  // Scanner: active_injection_scanner (#2), injection_targeted strategy (#46)
  if (USE_MEMORY) {
    const rows = memDb[table] || []
    return filter ? evalFilter(rows, filter) : rows
  }
  if (filter) {
    return sql!.unsafe(`SELECT * FROM ${table} WHERE ${filter}`)
  }
  return sql!.unsafe(`SELECT * FROM ${table}`)
}

export async function getById(table: string, id: string) {
  // VULNERABILITY: No parameterized query
  if (USE_MEMORY) {
    return (memDb[table] || []).filter(r => r.id === id)
  }
  return sql!.unsafe(`SELECT * FROM ${table} WHERE id = '${id}'`)
}

export async function insertRow(table: string, data: Record<string, any>) {
  if (USE_MEMORY) {
    const id = data.id || crypto.randomUUID()
    const row = { id, ...data, created_at: new Date().toISOString() }
    if (!memDb[table]) memDb[table] = []
    memDb[table].push(row)
    return [row]
  }
  const keys = Object.keys(data).join(", ")
  const values = Object.values(data).map(v => `'${v}'`).join(", ")
  return sql!.unsafe(`INSERT INTO ${table} (${keys}) VALUES (${values}) RETURNING *`)
}

export async function updateRow(table: string, id: string, data: Record<string, any>) {
  if (USE_MEMORY) {
    const rows = memDb[table] || []
    const idx = rows.findIndex(r => r.id === id)
    if (idx === -1) return [null]
    rows[idx] = { ...rows[idx], ...data }
    return [rows[idx]]
  }
  const sets = Object.entries(data).map(([k, v]) => `${k} = '${v}'`).join(", ")
  return sql!.unsafe(`UPDATE ${table} SET ${sets} WHERE id = '${id}' RETURNING *`)
}

export async function deleteRow(table: string, id: string) {
  if (USE_MEMORY) {
    const rows = memDb[table] || []
    memDb[table] = rows.filter(r => r.id !== id)
    return []
  }
  return sql!.unsafe(`DELETE FROM ${table} WHERE id = '${id}'`)
}

export default sql
