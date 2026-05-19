import { createClient } from "@supabase/supabase-js"

// VULNERABILITY: Supabase keys exposed in client-side code
// Scanner: endpoint_discovery (extracts anon key), session_scanner (#5)

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!

export const supabase = createClient(supabaseUrl, supabaseAnonKey)

// VULNERABILITY: Service role key used in client-importable module
export const supabaseAdmin = createClient(
  supabaseUrl,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
)
