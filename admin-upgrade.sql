-- ADMIN UPGRADE: run once in Supabase > SQL Editor > New query > Run.
-- Safe to run again.

-- 1. Columns the admin panel uses (no-op if they already exist)
alter table public.profiles add column if not exists blocked boolean not null default false;
alter table public.profiles add column if not exists session_epoch int not null default 0;
alter table public.profiles add column if not exists last_seen timestamptz;

-- 2. Helper functions
create or replace function public.adm_is_mgr() returns boolean
language sql security definer set search_path = public stable as $$
  select exists(select 1 from public.profiles
    where id = auth.uid() and role = 'manager' and not coalesce(blocked,false))
$$;
create or replace function public.adm_is_blocked() returns boolean
language sql security definer set search_path = public stable as $$
  select exists(select 1 from public.profiles where id = auth.uid() and coalesce(blocked,false))
$$;
grant execute on function public.adm_is_mgr() to authenticated;
grant execute on function public.adm_is_blocked() to authenticated;

-- 3. Sign-in history (every successful sign-in and every blocked attempt)
create table if not exists public.login_log (
  id bigint generated always as identity primary key,
  user_id uuid,
  email text,
  name text,
  ua text,
  ok boolean not null default true,
  note text,
  created_at timestamptz not null default now()
);
create index if not exists login_log_time on public.login_log (created_at desc);
alter table public.login_log enable row level security;
drop policy if exists adm_login_log_insert on public.login_log;
create policy adm_login_log_insert on public.login_log for insert to authenticated
  with check (user_id = auth.uid());
drop policy if exists adm_login_log_read on public.login_log;
create policy adm_login_log_read on public.login_log for select to authenticated
  using (public.adm_is_mgr());

-- 4. Admin action log (who blocked / removed / promoted whom)
create table if not exists public.admin_log (
  id bigint generated always as identity primary key,
  admin_id uuid,
  admin_name text,
  action text not null,
  target text,
  created_at timestamptz not null default now()
);
create index if not exists admin_log_time on public.admin_log (created_at desc);
alter table public.admin_log enable row level security;
drop policy if exists adm_admin_log_insert on public.admin_log;
create policy adm_admin_log_insert on public.admin_log for insert to authenticated
  with check (public.adm_is_mgr() and admin_id = auth.uid());
drop policy if exists adm_admin_log_read on public.admin_log;
create policy adm_admin_log_read on public.admin_log for select to authenticated
  using (public.adm_is_mgr());

-- 5. Admins may change and remove profiles (block, role, remove)
drop policy if exists adm_profiles_update on public.profiles;
create policy adm_profiles_update on public.profiles for update to authenticated
  using (public.adm_is_mgr()) with check (public.adm_is_mgr());
drop policy if exists adm_profiles_delete on public.profiles;
create policy adm_profiles_delete on public.profiles for delete to authenticated
  using (public.adm_is_mgr());

-- 6. REAL blocking on the server: a blocked user is refused by the database
--    even if they still hold a valid login token.
drop policy if exists adm_block_docs on public.docs;
create policy adm_block_docs on public.docs as restrictive for all to authenticated
  using (not public.adm_is_blocked()) with check (not public.adm_is_blocked());
