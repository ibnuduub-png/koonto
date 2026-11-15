-- Konto: lets an admin change another user's login email from the Admin panel.
-- Run once in Supabase: SQL Editor > New query > paste > Run.

create or replace function public.admin_set_email(target uuid, new_email text)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  ne text := lower(trim(new_email));
begin
  -- only an active admin may do this
  if not exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'manager' and coalesce(blocked, false) = false
  ) then
    raise exception 'not allowed';
  end if;

  if ne !~ '^[^\s@]+@[^\s@]+\.[^\s@]{2,}$' then
    raise exception 'invalid email';
  end if;

  if exists (select 1 from auth.users where lower(email) = ne and id <> target) then
    raise exception 'email already used';
  end if;

  update auth.users
     set email = ne,
         email_confirmed_at = coalesce(email_confirmed_at, now()),
         updated_at = now()
   where id = target;

  update auth.identities
     set identity_data = jsonb_set(coalesce(identity_data, '{}'::jsonb), '{email}', to_jsonb(ne)),
         updated_at = now()
   where user_id = target and provider = 'email';

  update public.profiles set email = ne where id = target;
end;
$$;

revoke all on function public.admin_set_email(uuid, text) from public, anon;
grant execute on function public.admin_set_email(uuid, text) to authenticated;
