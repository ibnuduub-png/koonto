-- WORK HOURS: run once in Supabase > SQL Editor > New query > Run.
-- Safe to run again. Run admin-upgrade.sql first (this uses its adm_is_mgr function).

-- 1. The schedule (one row). days: 0 = Sunday ... 6 = Saturday
create table if not exists public.work_hours (
  id int primary key default 1 check (id = 1),
  enabled boolean not null default false,
  start_time time not null default '08:00',
  end_time time not null default '18:00',
  days int[] not null default '{1,2,3,4,5,6}',
  tz text not null default 'Africa/Nairobi',
  updated_at timestamptz not null default now()
);
insert into public.work_hours (id) values (1) on conflict (id) do nothing;
alter table public.work_hours enable row level security;
drop policy if exists wh_read on public.work_hours;
create policy wh_read on public.work_hours for select to authenticated using (true);
drop policy if exists wh_insert on public.work_hours;
create policy wh_insert on public.work_hours for insert to authenticated with check (public.adm_is_mgr());
drop policy if exists wh_update on public.work_hours;
create policy wh_update on public.work_hours for update to authenticated
  using (public.adm_is_mgr()) with check (public.adm_is_mgr());

-- 2. Is the app open for the current user right now? (server clock, admins always yes)
create or replace function public.adm_work_open() returns boolean
language plpgsql security definer set search_path = public stable as $$
declare w public.work_hours; t timestamp; m int; d int; s int; e int;
begin
  select * into w from public.work_hours where id = 1;
  if not found or not w.enabled then return true; end if;
  if public.adm_is_mgr() then return true; end if;
  t := now() at time zone w.tz;
  d := extract(dow from t)::int;
  m := extract(hour from t)::int * 60 + extract(minute from t)::int;
  s := extract(hour from w.start_time)::int * 60 + extract(minute from w.start_time)::int;
  e := extract(hour from w.end_time)::int * 60 + extract(minute from w.end_time)::int;
  if s = e then return true; end if;
  if s < e then return d = any(w.days) and m >= s and m < e; end if;
  return (m >= s and d = any(w.days)) or (m < e and ((d + 6) % 7) = any(w.days));
exception when others then
  return true;
end $$;
grant execute on function public.adm_work_open() to authenticated;

-- 3. What the app reads to show the lock screen
create or replace function public.work_status() returns json
language plpgsql security definer set search_path = public stable as $$
declare w public.work_hours;
begin
  select * into w from public.work_hours where id = 1;
  if not found then
    return json_build_object('enabled', false, 'open', true, 'now', (extract(epoch from now()) * 1000)::bigint);
  end if;
  return json_build_object('enabled', w.enabled, 'start', to_char(w.start_time, 'HH24:MI'),
    'end', to_char(w.end_time, 'HH24:MI'), 'days', to_json(w.days), 'tz', w.tz,
    'open', public.adm_work_open(), 'now', (extract(epoch from now()) * 1000)::bigint);
end $$;
grant execute on function public.work_status() to authenticated;

-- 4. REAL lock on the server: outside work hours the database refuses employees,
--    even if someone edits the app on their phone.
drop policy if exists adm_hours_docs on public.docs;
create policy adm_hours_docs on public.docs as restrictive for all to authenticated
  using (public.adm_work_open()) with check (public.adm_work_open());
