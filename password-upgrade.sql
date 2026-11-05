-- Run ONCE in Supabase: SQL Editor -> New query -> paste -> Run
-- Lets signed-in ADMINS set any user's password from inside the app.
create or replace function public.admin_set_password(target uuid, new_password text)
returns void
language plpgsql
security definer
set search_path = public, extensions, auth
as $$
begin
  if not exists (select 1 from public.profiles
                 where id = auth.uid() and role = 'manager' and coalesce(blocked, false) = false) then
    raise exception 'Admins only';
  end if;
  if length(coalesce(new_password, '')) < 6 then
    raise exception 'Password must be 6 or more characters';
  end if;
  update auth.users
     set encrypted_password = crypt(new_password, gen_salt('bf')),
         updated_at = now()
   where id = target;
  if not found then
    raise exception 'User not found';
  end if;
end;
$$;

revoke all on function public.admin_set_password(uuid, text) from public, anon;
grant execute on function public.admin_set_password(uuid, text) to authenticated;
