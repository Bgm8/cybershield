-- supabase_setup.sql
-- Database initialization schema for CyberShield Threat Intelligence Platform

-- 1. Create Profiles Table (user metrics and tiers)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    tier TEXT DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'byok')),
    total_scans INTEGER DEFAULT 0,
    scans_today INTEGER DEFAULT 0,
    last_scan_date TEXT,
    is_banned BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Enable RLS on Profiles
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- 2. Create Scans Table (scan telemetry logs history)
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    service_used TEXT NOT NULL,
    threat_level TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    result_summary TEXT,
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Enable RLS on Scans
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

-- 3. Create Email Waitlist Table
CREATE TABLE IF NOT EXISTS public.email_waitlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    source TEXT DEFAULT 'limit_modal',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Enable RLS on Waitlist
ALTER TABLE public.email_waitlist ENABLE ROW LEVEL SECURITY;

-- ── ROW LEVEL SECURITY (RLS) POLICIES ────────────────────────────────────────

-- Profiles Policies
CREATE POLICY "Users can view their own profile."
    ON public.profiles FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "Users can update their own profile."
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id);

-- Scans Policies
CREATE POLICY "Users can view their own scan history."
    ON public.scans FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own scans."
    ON public.scans FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- Waitlist Policies
CREATE POLICY "Anyone can join waitlist."
    ON public.email_waitlist FOR INSERT
    WITH CHECK (true);

-- ── DATABASE TRIGGER FOR AUTO-PROFILE CREATION ────────────────────────────────

-- Create function to trigger on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, email, tier)
    VALUES (new.id, new.email, 'free');
    RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Bind trigger to auth.users insertions
CREATE OR REPLACE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ── INDEXES FOR PERFORMANCE OPTIMIZATION ─────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON public.scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON public.scans(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_waitlist_email ON public.email_waitlist(email);
