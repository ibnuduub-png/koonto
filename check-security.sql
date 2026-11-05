-- READ-ONLY check. Run in Supabase: SQL Editor -> New query -> paste -> Run.
-- It changes nothing. Send me the results of both tables.

-- 1) Which tables are protected by row-level security (rls_on must be true for every table)
select c.relname as table_name, c.relrowsecurity as rls_on
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r'
order by c.relname;

-- 2) Every access rule on those tables
select tablename, policyname, cmd, roles, qual as who_can_see_or_change, with_check as what_may_be_written
from pg_policies
where schemaname = 'public'
order by tablename, cmd, policyname;
