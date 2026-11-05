-- view-access.sql
-- Lets an admin allow chosen employees to see EVERYONE's receipts and invoices,
-- and/or unlock the full app (Store, More, Bin, Menu, Export). Admin can hide it again anytime.
-- Run once in Supabase > SQL Editor. Safe to run again.
-- It only ADDS read permissions and a delete block; your other policies are not changed.

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


-- =====================================================================
-- PART 2: show SELECTED receipts/invoices to an employee
-- =====================================================================
create table if not exists public.doc_shares (
  doc_id     text not null,
  user_id    uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (doc_id, user_id)
);

alter table public.doc_shares enable row level security;

create or replace function public.va_is_shared(d text)
returns boolean language sql security definer stable set search_path = public as $$
  select exists (
    select 1
    from public.doc_shares s
    join public.profiles p on p.id = s.user_id
    where s.doc_id = d and s.user_id = auth.uid() and coalesce(p.blocked, false) = false
  );
$$;
grant execute on function public.va_is_shared(text) to authenticated;

-- An employee can read their OWN share rows; only admins can add or remove shares.
drop policy if exists ds_select on public.doc_shares;
create policy ds_select on public.doc_shares for select to authenticated
  using (user_id = auth.uid() or public.va_is_admin());

drop policy if exists ds_insert on public.doc_shares;
create policy ds_insert on public.doc_shares for insert to authenticated
  with check (public.va_is_admin());

drop policy if exists ds_update on public.doc_shares;
create policy ds_update on public.doc_shares for update to authenticated
  using (public.va_is_admin()) with check (public.va_is_admin());

drop policy if exists ds_delete on public.doc_shares;
create policy ds_delete on public.doc_shares for delete to authenticated
  using (public.va_is_admin());

grant select, insert, update, delete on public.doc_shares to authenticated;

-- Employees may READ docs that were shared with them (read-only).
drop policy if exists docs_shared_read on public.docs;
create policy docs_shared_read on public.docs for select to authenticated
  using (public.va_is_shared(id::text));


-- =====================================================================
-- PART 3: employees can NOT delete anything
-- Blocks both real deletes and "mark as deleted". Admins are not affected.
-- =====================================================================
create or replace function public.va_block_employee_delete()
returns trigger language plpgsql set search_path = public as $$
begin
  if auth.uid() is null or public.va_is_admin() then
    if tg_op = 'DELETE' then return old; end if;
    return new;
  end if;
  if tg_op = 'DELETE' then
    raise exception 'Deleting is not allowed for your account';
  end if;
  if coalesce(new.deleted, false) = true and coalesce(old.deleted, false) = false then
    raise exception 'Deleting is not allowed for your account';
  end if;
  return new;
end;
$$;

drop trigger if exists va_no_delete on public.docs;
create trigger va_no_delete
  before update or delete on public.docs
  for each row execute function public.va_block_employee_delete();


-- =====================================================================
-- PART 4: edit limit for employees (max 3 edits per receipt/invoice)
-- The app keeps the edit history inside each document (data->'elog').
-- The server makes sure an employee can never erase that history
-- and can never go beyond 3 recorded edits. Admins are not affected.
-- =====================================================================
create or replace function public.va_limit_edits()
returns trigger language plpgsql set search_path = public as $$
declare
  o int; n int; c int;
  ol jsonb; nl jsonb;
begin
  if auth.uid() is null or public.va_is_admin() then
    return new;
  end if;
  ol := case when jsonb_typeof((old.data)::jsonb -> 'elog') = 'array' then (old.data)::jsonb -> 'elog' else '[]'::jsonb end;
  nl := case when jsonb_typeof((new.data)::jsonb -> 'elog') = 'array' then (new.data)::jsonb -> 'elog' else '[]'::jsonb end;
  o := jsonb_array_length(ol);
  n := jsonb_array_length(nl);
  if n < o then
    raise exception 'The edit history cannot be removed';
  end if;
  select count(*) into c
  from jsonb_array_elements(nl) e
  where coalesce(e->>'m', '0') not in ('1', 'true');
  if c > 3 then
    raise exception 'This item was edited 3 times and is locked';
  end if;
  return new;
end;
$$;

drop trigger if exists va_edit_limit on public.docs;
create trigger va_edit_limit
  before update on public.docs
  for each row execute function public.va_limit_edits();
