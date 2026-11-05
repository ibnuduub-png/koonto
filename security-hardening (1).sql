-- Run ONCE in Supabase: SQL Editor -> New query -> paste -> Run (safe to run again)
-- Run signup-lock.sql first if you have not yet.

-- 0) Marker so the app can tell this file has been run
create or replace function public.security_ready() returns boolean
language sql stable as $$ select true $$;
grant execute on function public.security_ready() to authenticated;

-- 0b) Tables and columns the app needs (created only if they are missing)
alter table public.profiles add column if not exists email text;
alter table public.profiles add column if not exists blocked boolean default false;
alter table public.profiles add column if not exists session_epoch integer default 0;
alter table public.profiles add column if not exists last_seen timestamptz;

create table if not exists public.login_alerts (
  id bigint generated always as identity primary key,
  email text, tab text, ip text, place text,
  seen boolean default false,
  created_at timestamptz default now()
);
create table if not exists public.login_log (
  id bigint generated always as identity primary key,
  user_id uuid, email text, name text, ua text, ok boolean, note text, ip text, place text,
  created_at timestamptz default now()
);
create table if not exists public.admin_log (
  id bigint generated always as identity primary key,
  admin_id uuid, admin_name text, action text, target text,
  created_at timestamptz default now()
);
alter table public.login_alerts add column if not exists ip text;
alter table public.login_alerts add column if not exists place text;
alter table public.login_log    add column if not exists ip text;
alter table public.login_log    add column if not exists place text;

alter table public.login_alerts enable row level security;
alter table public.login_log    enable row level security;
alter table public.admin_log    enable row level security;

-- anyone may report a failed sign-in (the guard below limits abuse); only admins read or mark them
drop policy if exists la_insert on public.login_alerts;
drop policy if exists la_admin_read on public.login_alerts;
drop policy if exists la_admin_update on public.login_alerts;
create policy la_insert on public.login_alerts for insert to anon, authenticated with check (true);
create policy la_admin_read on public.login_alerts for select to authenticated
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'));
create policy la_admin_update on public.login_alerts for update to authenticated
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'))
  with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'));

-- a signed-in person may record their own sign-in; only admins read the history
drop policy if exists ll_insert on public.login_log;
drop policy if exists ll_admin_read on public.login_log;
create policy ll_insert on public.login_log for insert to authenticated with check (user_id = auth.uid());
create policy ll_admin_read on public.login_log for select to authenticated
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'));

-- only admins write and read the admin log
drop policy if exists al_admin_insert on public.admin_log;
drop policy if exists al_admin_read on public.admin_log;
create policy al_admin_insert on public.admin_log for insert to authenticated
  with check (admin_id = auth.uid() and exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'));
create policy al_admin_read on public.admin_log for select to authenticated
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'));

-- 1) "Is this person allowed to use the data right now?" (has a profile and is not blocked)
create or replace function public.is_active() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles p
                 where p.id = auth.uid() and coalesce(p.blocked, false) = false)
$$;

-- 2) Block / unblock for real: also disables the Supabase login and ends every session
create or replace function public.admin_set_blocked(target uuid, block boolean)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if not exists (select 1 from public.profiles p
                 where p.id = auth.uid() and p.role = 'manager' and coalesce(p.blocked, false) = false) then
    raise exception 'Admins only';
  end if;
  if target = auth.uid() then raise exception 'You cannot block yourself'; end if;
  update public.profiles
     set blocked = block,
         session_epoch = coalesce(session_epoch, 0) + (case when block then 1 else 0 end)
   where id = target;
  if not found then raise exception 'User not found'; end if;
  update auth.users
     set banned_until = case when block then 'infinity'::timestamptz else null end
   where id = target;
  if block then
    begin delete from auth.sessions where user_id = target; exception when others then null; end;
    begin delete from auth.refresh_tokens where user_id::text = target::text; exception when others then null; end;
  end if;
end $$;
revoke all on function public.admin_set_blocked(uuid, boolean) from public, anon;
grant execute on function public.admin_set_blocked(uuid, boolean) to authenticated;

-- 3) Nobody but an admin can create, delete, or change anyone's profile (role, blocked, email, name...).
--    The only thing a user may change on their own profile is "last seen".
create or replace function public.guard_profile() returns trigger
language plpgsql security definer set search_path = public as $$
declare is_mgr boolean;
begin
  if auth.uid() is null then
    if tg_op = 'DELETE' then return old; else return new; end if;
  end if;
  select exists (select 1 from public.profiles p
                 where p.id = auth.uid() and p.role = 'manager' and coalesce(p.blocked, false) = false) into is_mgr;
  if is_mgr then
    if tg_op = 'DELETE' then return old; else return new; end if;
  end if;
  if tg_op = 'UPDATE' and (to_jsonb(new) - 'last_seen') = (to_jsonb(old) - 'last_seen') then
    return new;
  end if;
  raise exception 'Not allowed';
end $$;
drop trigger if exists guard_profile_ins on public.profiles;
drop trigger if exists guard_profile_upd on public.profiles;
drop trigger if exists guard_profile_del on public.profiles;
create trigger guard_profile_ins before insert on public.profiles for each row execute function public.guard_profile();
create trigger guard_profile_upd before update on public.profiles for each row execute function public.guard_profile();
create trigger guard_profile_del before delete on public.profiles for each row execute function public.guard_profile();

-- 4) Blocked people and accounts without a profile cannot read or write receipts/invoices at all.
--    (A "restrictive" rule is added ON TOP of your existing rules; it never widens access.)
do $$
begin
  if exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = 'public' and c.relname = 'docs' and c.relrowsecurity) then
    execute 'drop policy if exists docs_active_only on public.docs';
    execute 'create policy docs_active_only on public.docs as restrictive for all to authenticated using (public.is_active()) with check (public.is_active())';
  else
    raise notice 'docs has NO row security. Run check-security.sql and send me the result.';
  end if;
end $$;

-- 5) Fake sign-in warnings: cap their size and how many one email / everyone can make in 10 minutes
alter table public.login_alerts add column if not exists ip text;
alter table public.login_alerts add column if not exists place text;
create or replace function public.guard_alert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.email := left(coalesce(new.email, ''), 200);
  new.tab   := left(coalesce(new.tab, ''), 20);
  new.ip    := left(new.ip, 60);
  new.place := left(new.place, 120);
  if (select count(*) from public.login_alerts a where a.created_at > now() - interval '10 minutes') >= 80 then
    return null;
  end if;
  if (select count(*) from public.login_alerts a
       where lower(a.email) = lower(new.email) and a.created_at > now() - interval '10 minutes') >= 8 then
    return null;
  end if;
  return new;
end $$;
drop trigger if exists guard_alert on public.login_alerts;
create trigger guard_alert before insert on public.login_alerts for each row execute function public.guard_alert();

-- 6) Admin "Set password": 8 or more characters
create or replace function public.admin_set_password(target uuid, new_password text)
returns void language plpgsql security definer set search_path = public, extensions, auth as $$
begin
  if not exists (select 1 from public.profiles p
                 where p.id = auth.uid() and p.role = 'manager' and coalesce(p.blocked, false) = false) then
    raise exception 'Admins only';
  end if;
  if length(coalesce(new_password, '')) < 8 then
    raise exception 'Password must be 8 or more characters';
  end if;
  update auth.users
     set encrypted_password = crypt(new_password, gen_salt('bf')), updated_at = now()
   where id = target;
  if not found then raise exception 'User not found'; end if;
end $$;
revoke all on function public.admin_set_password(uuid, text) from public, anon;
grant execute on function public.admin_set_password(uuid, text) to authenticated;
