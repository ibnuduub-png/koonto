-- view-access.sql
-- Lets an admin allow chosen employees to see EVERYONE's receipts and invoices,
-- and/or unlock the full app (Store, More, Bin, Menu, Export). Admin can hide it again anytime.
-- Run once in Supabase > SQL Editor. Safe to run again.
-- It only ADDS a read permission; your existing policies are not changed.

create table if not exists public.view_grants (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  see_all    boolean not null default false,   -- sees all receipts & invoices
  full_app   boolean not null default false,   -- full app screens unlocked on the phone
  updated_at timestamptz not null default now()
);

alter table public.view_grants enable row level security;

-- Helper: is the caller an active admin?
create or replace function public.va_is_admin()
returns boolean language sql security definer stable set search_path = public as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'manager' and coalesce(p.blocked, false) = false
  );
$$;

-- Helper: does the caller have the "see all" grant (and is not blocked)?
create or replace function public.va_can_see_all()
returns boolean language sql security definer stable set search_path = public as $$
  select exists (
    select 1
    from public.view_grants g
    join public.profiles p on p.id = g.user_id
    where g.user_id = auth.uid() and g.see_all = true and coalesce(p.blocked, false) = false
  );
$$;

grant execute on function public.va_is_admin()   to authenticated;
grant execute on function public.va_can_see_all() to authenticated;

-- view_grants: everyone can read their OWN row, admins can read/write all.
-- Employees can never change their own grants.
drop policy if exists va_select on public.view_grants;
create policy va_select on public.view_grants for select to authenticated
  using (user_id = auth.uid() or public.va_is_admin());

drop policy if exists va_insert on public.view_grants;
create policy va_insert on public.view_grants for insert to authenticated
  with check (public.va_is_admin());

drop policy if exists va_update on public.view_grants;
create policy va_update on public.view_grants for update to authenticated
  using (public.va_is_admin()) with check (public.va_is_admin());

drop policy if exists va_delete on public.view_grants;
create policy va_delete on public.view_grants for delete to authenticated
  using (public.va_is_admin());

grant select, insert, update, delete on public.view_grants to authenticated;

-- docs: ADD a read-only permission for employees who were granted "see all".
-- (Policies are combined with OR, so this does not remove anything that exists.)
drop policy if exists docs_see_all_grant on public.docs;
create policy docs_see_all_grant on public.docs for select to authenticated
  using (public.va_can_see_all());
