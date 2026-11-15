-- Run this file in the Supabase SQL Editor.
-- After creating an account in StockFlow, add its Auth user ID as a member:
-- insert into public.inventory_members (user_id) values ('<AUTH_USER_UUID>');

create table if not exists public.inventory_members (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.inventory_state (
  id text primary key check (id = 'shared'),
  state jsonb not null,
  version bigint not null default 1 check (version > 0),
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users (id) on delete set null
);

alter table public.inventory_members enable row level security;
alter table public.inventory_state enable row level security;

create or replace function public.is_inventory_member()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.inventory_members
    where user_id = auth.uid()
  );
$$;

revoke all on function public.is_inventory_member() from public, anon;
grant execute on function public.is_inventory_member() to authenticated;

grant select on public.inventory_members to authenticated;
grant select, insert, update on public.inventory_state to authenticated;

create or replace function public.save_inventory_state(p_state jsonb, p_expected_version bigint)
returns bigint
language plpgsql
security invoker
set search_path = ''
as $$
declare
  next_version bigint;
begin
  update public.inventory_state
  set state = p_state,
      version = version + 1,
      updated_at = now(),
      updated_by = auth.uid()
  where id = 'shared'
    and version = p_expected_version
  returning version into next_version;

  if next_version is null then
    raise exception 'Shared inventory changed since it was loaded.'
      using errcode = '40001';
  end if;

  return next_version;
end;
$$;

revoke all on function public.save_inventory_state(jsonb, bigint) from public, anon;
grant execute on function public.save_inventory_state(jsonb, bigint) to authenticated;

drop policy if exists inventory_members_select_self on public.inventory_members;
create policy inventory_members_select_self
  on public.inventory_members
  for select
  to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists inventory_state_select_members on public.inventory_state;
create policy inventory_state_select_members
  on public.inventory_state
  for select
  to authenticated
  using ((select public.is_inventory_member()));

drop policy if exists inventory_state_insert_members on public.inventory_state;
create policy inventory_state_insert_members
  on public.inventory_state
  for insert
  to authenticated
  with check (
    (select public.is_inventory_member())
    and updated_by = (select auth.uid())
  );

drop policy if exists inventory_state_update_members on public.inventory_state;
create policy inventory_state_update_members
  on public.inventory_state
  for update
  to authenticated
  using ((select public.is_inventory_member()))
  with check (
    (select public.is_inventory_member())
    and updated_by = (select auth.uid())
  );

do $$
begin
  if exists (
    select 1
    from pg_publication
    where pubname = 'supabase_realtime'
  ) and not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'inventory_state'
  ) then
    execute 'alter publication supabase_realtime add table public.inventory_state';
  end if;
end;
$$;

notify pgrst, 'reload schema';
