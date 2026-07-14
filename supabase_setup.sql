-- supabase_setup.sql
-- Run this in your Supabase SQL Editor to set up the necessary tables, triggers, and Row Level Security.

-- 1. Create Profiles Table (extends Supabase Auth metadata)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID REFERENCES auth.users ON DELETE CASCADE PRIMARY KEY,
  email TEXT UNIQUE,
  tier TEXT DEFAULT 'free', -- 'free', 'pro', or 'byok'
  total_scans INTEGER DEFAULT 0,
  scans_today INTEGER DEFAULT 0,
  last_scan_date DATE DEFAULT CURRENT_DATE,
  is_banned BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 2. Create Scans Table (for logs and history)
CREATE TABLE IF NOT EXISTS public.scans (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  scan_type TEXT NOT NULL,
  service_used TEXT,
  threat_level TEXT,
  risk_score INTEGER,
  result_summary TEXT,
  scanned_at TIMESTAMPTZ DEFAULT now()
);

-- 3. Create Email Waitlist Table (for limit exceeded marketing list)
CREATE TABLE IF NOT EXISTS public.email_waitlist (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  source TEXT DEFAULT 'limit_modal',
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. Enable Row Level Security (RLS)
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_waitlist ENABLE ROW LEVEL SECURITY;

-- 5. Define Security Policies
-- Profiles policies
CREATE POLICY "Users can view and update own profile" ON public.profiles
  FOR ALL USING (auth.uid() = id);

-- Scans policies
CREATE POLICY "Users can view own scans" ON public.scans
  FOR ALL USING (auth.uid() = public.scans.user_id);

-- Email waitlist policies (allows anonymous signups from client, backend handles duplicates)
CREATE POLICY "Anyone can join waitlist" ON public.email_waitlist
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Admins can view waitlist" ON public.email_waitlist
  FOR SELECT USING (false); -- overridden by service role key in backend

-- 6. Trigger to automatically create profile on auth signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, tier)
  VALUES (NEW.id, NEW.email, 'free');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Drop trigger if it exists, then create it
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
