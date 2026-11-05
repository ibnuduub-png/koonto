-- Run ONCE in Supabase: SQL Editor -> New query -> paste -> Run (safe to run again)
-- Closes public sign-up: only emails you add with "Add user" in the app can create an account.

-- 1) The list of emails allowed to create an account (admins only)
create table if not exists public.allowed_emails (
  email text primary key,
  created_at timestamptz default now()
);
alter table public.allowed_emails enable row level security;
drop policy if exists allowed_admin_all on public.allowed_emails;
create policy allowed_admin_all on public.allowed_emails
  for all to authenticated
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'))
  with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager'));

-- 2) The lock: any sign-up with an email that is not on the list is refused
create or replace function public.guard_signup()
returns trigger language plpgsql security definer
set search_path = public, auth
as $$
begin
  if not exists (select 1 from public.allowed_emails a where lower(a.email) = lower(new.email)) then
    raise exception 'Sign-up is closed';
  end if;
  return new;
end;
$$;
drop trigger if exists guard_signup on auth.users;
create trigger guard_signup before insert on auth.users
  for each row execute function public.guard_signup();

-- 3) Lets the admin see and remove accounts that have no role (strangers who signed up earlier)
create or replace function public.admin_strays()
returns table (id uuid, email text, created_at timestamptz)
language plpgsql security definer
set search_path = public, auth
as $$
begin
  if not exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager') then
    raise exception 'Admins only';
  end if;
  return query
    select u.id, u.email::text, u.created_at from auth.users u
    where not exists (select 1 from public.profiles p where p.id = u.id)
    order by u.created_at desc;
end;
$$;

create or replace function public.admin_delete_stray(target uuid)
returns void language plpgsql security definer
set search_path = public, auth
as $$
begin
  if not exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'manager') then
    raise exception 'Admins only';
  end if;
  delete from auth.users u
   where u.id = target and not exists (select 1 from public.profiles p where p.id = u.id);
  if not found then raise exception 'Not an unregistered account'; end if;
end;
$$;

revoke all on function public.admin_strays() from public, anon;
revoke all on function public.admin_delete_stray(uuid) from public, anon;
grant execute on function public.admin_strays() to authenticated;
grant execute on function public.admin_delete_stray(uuid) to authenticated;
