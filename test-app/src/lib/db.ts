import postgres from "postgres"

// VULNERABILITY: Raw SQL concatenation helper used by many routes
// Scanner: llm_code_reviewer via import_graph_centrality (#53)
// Scanner: injection_analyzer (#54)

const sql = postgres(process.env.DATABASE_URL!)

export async function query(table: string, filter?: string) {
  // VULNERABILITY: SQL injection via string concatenation
  // Scanner: active_injection_scanner (#2), injection_targeted strategy (#46)
  if (filter) {
    return sql.unsafe(`SELECT * FROM ${table} WHERE ${filter}`)
  }
  return sql.unsafe(`SELECT * FROM ${table}`)
}

export async function getById(table: string, id: string) {
  // VULNERABILITY: No parameterized query
  return sql.unsafe(`SELECT * FROM ${table} WHERE id = '${id}'`)
}

export async function insertRow(table: string, data: Record<string, any>) {
  const keys = Object.keys(data).join(", ")
  const values = Object.values(data).map(v => `'${v}'`).join(", ")
  return sql.unsafe(`INSERT INTO ${table} (${keys}) VALUES (${values}) RETURNING *`)
}

export async function updateRow(table: string, id: string, data: Record<string, any>) {
  const sets = Object.entries(data).map(([k, v]) => `${k} = '${v}'`).join(", ")
  return sql.unsafe(`UPDATE ${table} SET ${sets} WHERE id = '${id}' RETURNING *`)
}

export async function deleteRow(table: string, id: string) {
  return sql.unsafe(`DELETE FROM ${table} WHERE id = '${id}'`)
}

export default sql
