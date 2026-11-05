-- Run once in Supabase > SQL Editor. Safe to run again.
-- Adds "Pick receipts": the admin chooses which receipts/invoices an employee can see.

create table if not exists public.doc_shares (
  doc_id  text not null,
  user_id uuid not null,
  created_at timestamptz default now(),
  primary key (doc_id, user_id)
);

alter table public.doc_shares enable row level security;

-- helper so policies never loop on the profiles table
create or replace function public.ds_is_manager()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'manager' and coalesce(blocked,false) = false);
$$;

drop policy if exists ds_manager_all on public.doc_shares;
create policy ds_manager_all on public.doc_shares
  for all to authenticated
  using (public.ds_is_manager())
  with check (public.ds_is_manager());

drop policy if exists ds_employee_read_own on public.doc_shares;
create policy ds_employee_read_own on public.doc_shares
  for select to authenticated
  using (user_id = auth.uid());

-- let an employee read a document that was shared with them
drop policy if exists docs_read_shared on public.docs;
create policy docs_read_shared on public.docs
  for select to authenticated
  using (exists (select 1 from public.doc_shares s where s.doc_id = docs.id::text and s.user_id = auth.uid()));
