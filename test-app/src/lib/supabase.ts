import { createClient } from "@supabase/supabase-js"

// VULNERABILITY: Supabase keys exposed in client-side code
// Scanner: endpoint_discovery (extracts anon key), session_scanner (#5)

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "https://abcdefghijklmnop.supabase.co"
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.fake-anon-key-for-testing"

export const supabase = createClient(supabaseUrl, supabaseAnonKey)

// VULNERABILITY: Service role key used in client-importable module
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.fake-service-key-for-testing"
export const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey)
