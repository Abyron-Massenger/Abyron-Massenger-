create extension if not exists pgcrypto;

create table if not exists profiles(
 id uuid primary key default gen_random_uuid(),
 device_id text unique not null,
 username text unique not null,
 public_key jsonb not null,
 created_at timestamptz default now()
);

-- If the original schema was already installed, add the new username column safely.
alter table profiles add column if not exists username text;

-- Existing rows from the old prototype have no username. Give them a temporary unique device-based name.
update profiles
set username = 'user_' || substr(regexp_replace(device_id, '[^a-zA-Z0-9]', '', 'g'), 1, 16)
where username is null;

alter table profiles alter column username set not null;
create unique index if not exists profiles_username_unique on profiles(lower(username));

create table if not exists messages(
 id uuid primary key default gen_random_uuid(),
 conversation_id text not null,
 sender_device text not null,
 recipient_device text not null,
 sender_public_key jsonb not null,
 ciphertext jsonb not null,
 created_at timestamptz default now()
);
alter table messages add column if not exists sender_public_key jsonb;
create index if not exists messages_conversation_created on messages(conversation_id,created_at);

create table if not exists groups(
 id uuid primary key default gen_random_uuid(),
 name text not null,
 owner_device text not null,
 created_at timestamptz default now()
);
create table if not exists group_members(
 group_id uuid references groups(id) on delete cascade,
 device_id text not null,
 role text default 'member',
 primary key(group_id,device_id)
);
create table if not exists scheduled_messages(
 id uuid primary key default gen_random_uuid(),
 sender_device text not null,
 recipient_device text not null,
 ciphertext jsonb not null,
 deliver_at timestamptz not null,
 status text default 'scheduled',
 created_at timestamptz default now()
);

alter table profiles enable row level security;
alter table messages enable row level security;
alter table groups enable row level security;
alter table group_members enable row level security;
alter table scheduled_messages enable row level security;

-- DEVELOPMENT POLICIES ONLY. Replace with authenticated least-privilege policies before production.
DO $$ BEGIN
create policy "dev_profiles_select" on profiles for select using(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_profiles_insert" on profiles for insert with check(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_profiles_update" on profiles for update using(true) with check(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_messages_select" on messages for select using(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_messages_insert" on messages for insert with check(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_messages_update" on messages for update using(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_groups_select" on groups for select using(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_groups_insert" on groups for insert with check(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_group_members_select" on group_members for select using(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_group_members_insert" on group_members for insert with check(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_schedule_select" on scheduled_messages for select using(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN
create policy "dev_schedule_insert" on scheduled_messages for insert with check(true);
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- Realtime for encrypted message delivery.
DO $$ BEGIN
alter publication supabase_realtime add table messages;
EXCEPTION WHEN duplicate_object THEN null; END $$;
