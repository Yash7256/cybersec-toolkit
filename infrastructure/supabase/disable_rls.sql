-- WARNING: This script DISABLES Row-Level Security on all application tables.
--
-- When RLS is disabled, any client with a valid Supabase connection string
-- (including the anon key) can read and write ALL rows in these tables without
-- any per-user access controls at the database level.
--
-- This is intentional for this application because:
--   1. The app uses its own authentication layer (Clerk + FastAPI deps) — all
--      external access goes through the FastAPI backend which enforces auth.
--   2. The Supabase database is accessed exclusively through the backend's
--      SQLAlchemy connection (not exposed directly to the frontend/browser).
--   3. The Supabase anon key is not used for direct DB access anywhere in the app.
--
-- DO NOT run this script against a Supabase project where the anon key is used
-- for direct database queries (e.g. supabase-js in the browser), as it would
-- remove the only access control layer.
--
-- Run via: Supabase Dashboard → SQL Editor → paste and execute.

ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE scan_results DISABLE ROW LEVEL SECURITY;
ALTER TABLE tool_results DISABLE ROW LEVEL SECURITY;
ALTER TABLE reports DISABLE ROW LEVEL SECURITY;
ALTER TABLE worker_heartbeats DISABLE ROW LEVEL SECURITY;
ALTER TABLE nvd_cve_cache DISABLE ROW LEVEL SECURITY;
ALTER TABLE nvd_service_lookup_cache DISABLE ROW LEVEL SECURITY;
