-- Baraka Shop: staff controls
-- Run once: Supabase > SQL Editor > New query > paste this > Run.
-- It adds two tables:
--   shop_settings : limits you set on your phone, sent to every staff phone
--   shop_events   : cash counts, change log and staff-phone alerts, sent to you

create table if not exists public.shop_settings (
  key text primary key,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid
);
alter table public.shop_settings enable row level security;

drop policy if exists shop_settings_read on public.shop_settings;
create policy shop_settings_read on public.shop_settings
  for select to authenticated using (true);

drop policy if exists shop_settings_write on public.shop_settings;
create policy shop_settings_write on public.shop_settings
  for all to authenticated
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'))
  with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'));

create table if not exists public.shop_events (
  id text primary key,
  user_id uuid not null default auth.uid(),
  name text not null default '',
  kind text not null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists shop_events_created_idx on public.shop_events (created_at desc);
alter table public.shop_events enable row level security;

drop policy if exists shop_events_insert on public.shop_events;
create policy shop_events_insert on public.shop_events
  for insert to authenticated
  with check (user_id = auth.uid());

drop policy if exists shop_events_select on public.shop_events;
create policy shop_events_select on public.shop_events
  for select to authenticated
  using (
    user_id = auth.uid()
    or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager')
  );
