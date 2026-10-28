-- AuditCanvas admin storage.
-- Dedicated Neon database for AuditCanvas only.
-- No raw passwords, raw session tokens, raw IP addresses, or raw user agents
-- are stored by this schema's application contract.

create table if not exists public.admin_sessions (
  id uuid primary key,
  token_hash text not null unique
    check (token_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_ip_hash text
    check (created_ip_hash is null or created_ip_hash ~ '^[0-9a-f]{64}$'),
  browser_family text,
  os_family text,
  check (expires_at > created_at)
);

create index if not exists admin_sessions_active_idx
  on public.admin_sessions (expires_at)
  where revoked_at is null;

create index if not exists admin_sessions_cleanup_idx
  on public.admin_sessions (revoked_at, expires_at);


create table if not exists public.admin_events (
  id bigint generated always as identity primary key,
  occurred_at timestamptz not null default now(),
  event_type text not null check (
    event_type in (
      'login_success',
      'login_failure',
      'login_rate_limited',
      'login_config_error',
      'logout',
      'session_revoked',
      'csrf_rejected',
      'scan_created',
      'scan_step_completed',
      'scan_finalized',
      'scan_failed',
      'report_viewed',
      'report_downloaded',
      'self_exclusion_changed',
      'prune_completed',
      'prune_failed',
      'storage_error'
    )
  ),
  actor_session_id uuid references public.admin_sessions(id) on delete set null,
  scan_id text,
  target_host text,
  ip_hash text
    check (ip_hash is null or ip_hash ~ '^[0-9a-f]{64}$'),
  browser_family text,
  os_family text,
  metadata jsonb not null default '{}'::jsonb
    check (jsonb_typeof(metadata) = 'object')
);

create index if not exists admin_events_time_idx
  on public.admin_events (occurred_at desc, id desc);

create index if not exists admin_events_type_time_idx
  on public.admin_events (event_type, occurred_at desc);

create index if not exists admin_events_login_source_idx
  on public.admin_events (ip_hash, occurred_at desc)
  where event_type in ('login_success', 'login_failure', 'login_rate_limited');

create index if not exists admin_events_scan_idx
  on public.admin_events (scan_id, occurred_at desc)
  where scan_id is not null;


create table if not exists public.admin_scan_runs (
  scan_id text primary key
    check (scan_id ~ '^[A-Za-z0-9_-]{16,64}$'),
  origin text not null default 'admin'
    check (origin = 'admin'),
  target text not null
    check (char_length(target) between 1 and 2048),
  target_host text not null
    check (char_length(target_host) between 1 and 253),
  target_display text not null
    check (char_length(target_display) between 1 and 2048),
  authorization_state text not null default 'admin'
    check (authorization_state = 'admin'),
  scan_policy text not null default 'full'
    check (scan_policy = 'full'),
  status text not null default 'created'
    check (status in ('created', 'running', 'finalized', 'failed', 'expired')),
  created_by_session_id uuid not null
    references public.admin_sessions(id) on delete restrict,
  rescan_of text,
  completed_groups text[] not null default array[]::text[],
  step_attempts integer not null default 0
    check (step_attempts >= 0),
  bundle_set_digest text
    check (bundle_set_digest is null or bundle_set_digest ~ '^[0-9a-f]{64}$'),
  risk_score integer
    check (risk_score is null or risk_score between 0 and 100),
  risk_grade text
    check (risk_grade is null or risk_grade in ('A', 'B', 'C', 'D', 'E', 'F')),
  findings_count integer
    check (findings_count is null or findings_count >= 0),
  confirmed_findings_count integer
    check (confirmed_findings_count is null or confirmed_findings_count >= 0),
  coverage_ratio numeric(5,4)
    check (coverage_ratio is null or coverage_ratio between 0 and 1),
  confidence_ratio numeric(5,4)
    check (confidence_ratio is null or confidence_ratio between 0 and 1),
  report_json jsonb
    check (report_json is null or jsonb_typeof(report_json) = 'object'),
  report_sha256 text
    check (report_sha256 is null or report_sha256 ~ '^[0-9a-f]{64}$'),
  error_code text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  expires_at timestamptz not null,
  finalized_at timestamptz,
  check (expires_at > created_at),
  check (
    (status = 'finalized' and report_json is not null and finalized_at is not null)
    or status <> 'finalized'
  )
);

create index if not exists admin_scan_runs_history_idx
  on public.admin_scan_runs (created_at desc, scan_id desc);

create index if not exists admin_scan_runs_host_history_idx
  on public.admin_scan_runs (target_host, created_at desc);

create index if not exists admin_scan_runs_status_expiry_idx
  on public.admin_scan_runs (status, expires_at);

create index if not exists admin_scan_runs_cleanup_idx
  on public.admin_scan_runs (created_at);


create table if not exists public.visit_events (
  id bigint generated always as identity primary key,
  occurred_at timestamptz not null default now(),
  local_date date not null,
  path text not null
    check (char_length(path) between 1 and 512 and left(path, 1) = '/'),
  referrer_host text
    check (referrer_host is null or char_length(referrer_host) <= 253),
  referrer_origin text
    check (referrer_origin is null or char_length(referrer_origin) <= 512),
  country_code text
    check (country_code is null or country_code ~ '^[A-Z]{2}$'),
  region_code text
    check (region_code is null or char_length(region_code) <= 16),
  browser_family text not null,
  os_family text not null,
  device_family text not null,
  visitor_day_key text not null
    check (visitor_day_key ~ '^[0-9a-f]{64}$'),
  classification text not null default 'visitor'
    check (classification in ('visitor', 'bot', 'self'))
);

create index if not exists visit_events_time_idx
  on public.visit_events (occurred_at desc, id desc);

create index if not exists visit_events_day_idx
  on public.visit_events (local_date, classification);

create index if not exists visit_events_day_path_idx
  on public.visit_events (local_date, path, classification);

create index if not exists visit_events_day_referrer_idx
  on public.visit_events (local_date, referrer_host, classification)
  where referrer_host is not null;

create index if not exists visit_events_cleanup_idx
  on public.visit_events (occurred_at);


create table if not exists public.admin_meta (
  key text primary key,
  value jsonb not null,
  updated_at timestamptz not null default now()
);

insert into public.admin_meta (key, value)
values ('schema_version', '1'::jsonb)
on conflict (key) do nothing;
