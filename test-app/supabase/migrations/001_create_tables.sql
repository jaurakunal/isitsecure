-- VibeTasks database schema
-- VULNERABILITY: No RLS enabled on any table
-- Scanner: rls_policy_analyzer (#27)

CREATE TABLE profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  display_name TEXT,
  role TEXT DEFAULT 'user',
  is_admin BOOLEAN DEFAULT false,
  avatar_url TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id),
  title TEXT NOT NULL,
  description TEXT,
  status TEXT DEFAULT 'pending',
  priority INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE credits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id),
  balance INTEGER DEFAULT 100,
  last_redeemed_at TIMESTAMPTZ
);

CREATE TABLE settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id),
  preferences JSONB DEFAULT '{}',
  notifications_enabled BOOLEAN DEFAULT true
);

-- VULNERABILITY: RLS policy with wrong column reference
-- Scanner: semantic_rule_verifier (#40)
-- Policy checks auth.uid() = id instead of auth.uid() = user_id
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can view own tasks" ON tasks
  FOR SELECT USING (auth.uid() = id);

-- No RLS on profiles — anyone can read/write any profile
-- No RLS on credits — anyone can modify balances
-- No RLS on settings
