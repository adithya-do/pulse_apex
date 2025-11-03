create table app_users (
  user_id           number generated always as identity primary key,
  login_name        varchar2(100) not null unique,
  full_name         varchar2(200),
  email             varchar2(320) not null,
  pwd_hash          raw(2000)      not null,
  pwd_salt          raw(2000)      not null,
  is_active         char(1) default 'Y' check (is_active in ('Y','N')),
  must_change_pwd   char(1) default 'N' check (must_change_pwd in ('Y','N')),
  created_at        timestamp default systimestamp,
  updated_at        timestamp
);

create table app_roles (
  role_id    number generated always as identity primary key,
  code       varchar2(50) not null unique, -- 'ADMIN','SUPER','ORACLE','MSSQL', etc
  name       varchar2(100) not null
);

create table app_user_roles (
  user_id    number not null references app_users(user_id),
  role_id    number not null references app_roles(role_id),
  constraint app_user_roles_pk primary key (user_id, role_id)
);

create table app_modules (
  module_id  number generated always as identity primary key,
  code       varchar2(50) not null unique, -- 'ORA_DB','MSSQL_DB', etc
  name       varchar2(100) not null
);

create table app_user_modules (
  user_id    number not null references app_users(user_id),
  module_id  number not null references app_modules(module_id),
  constraint app_user_modules_pk primary key (user_id, module_id)
);

-- Forgot-password tokens (emailed via APEX_MAIL)
create table sec_password_reset (
  pr_id       number generated always as identity primary key,
  user_id     number not null references app_users(user_id),
  token       varchar2(128) not null,
  expires_at  timestamp not null,
  used_yn     char(1) default 'N' check (used_yn in ('Y','N'))
);

-- ORACLE DB TARGETS & STATUS
create table ora_db_targets (
  target_id      number generated always as identity primary key,
  db_name        varchar2(128) not null,
  environment    varchar2(30)  not null,    -- PROD / NON-PROD / DEV / TEST
  host           varchar2(255) not null,
  port           number default 1521,
  service_name   varchar2(255),
  sid            varchar2(64),
  tns_alias      varchar2(255),
  conn_pref      varchar2(10) not null check (conn_pref in ('TNS','THIN')),
  common_user    varchar2(128) not null,
  enc_password   raw(2000) not null,        -- encrypted with APEX_CRYPTO
  owner_email    varchar2(320),             -- alert recipient for this target
  is_active      char(1) default 'Y' check (is_active in ('Y','N')),
  created_by     number references app_users(user_id),
  created_at     timestamp default systimestamp,
  updated_at     timestamp
);

create table ora_db_status (
  status_id           number generated always as identity primary key,
  target_id           number not null references ora_db_targets(target_id),
  status              varchar2(20),    -- UP/DOWN/DEGRADED
  instance_status     varchar2(40),
  db_open_mode        varchar2(40),
  worst_tbs_pct       number(5,2),
  tbs_all_online_yn   char(1) check (tbs_all_online_yn in ('Y','N')),
  last_full_backup    timestamp,
  last_arch_backup    timestamp,
  last_check_at       timestamp default systimestamp,
  check_status        varchar2(20),    -- INPROGRESS/COMPLETED/ERROR
  error_message       varchar2(4000)
);

-- SQL SERVER TARGETS & STATUS
create table mssql_targets (
  target_id      number generated always as identity primary key,
  instance_name  varchar2(200) not null,  -- e.g. SERVER\INSTANCE or SERVER
  environment    varchar2(30)  not null,
  host           varchar2(255) not null,
  port           number default 1433,
  auth_mode      varchar2(10) not null check (auth_mode in ('SQL','WIN')),
  username       varchar2(128),
  enc_password   raw(2000),              -- encrypted with APEX_CRYPTO
  owner_email    varchar2(320),
  is_active      char(1) default 'Y' check (is_active in ('Y','N')),
  created_by     number references app_users(user_id),
  created_at     timestamp default systimestamp,
  updated_at     timestamp
);

create table mssql_status (
  status_id           number generated always as identity primary key,
  target_id           number not null references mssql_targets(target_id),
  status              varchar2(20), -- UP/DOWN
  version_string      varchar2(400),
  last_full_backup    timestamp,
  last_log_backup     timestamp,
  last_check_at       timestamp default systimestamp,
  check_status        varchar2(20),
  error_message       varchar2(4000)
);

-- Work queue consumed by Python worker
create table job_queue (
  job_id       number generated always as identity primary key,
  module_code  varchar2(50) not null,    -- 'ORA_DB' or 'MSSQL_DB'
  target_id    number not null,
  job_type     varchar2(30) not null,    -- 'CHECK'
  requested_by number references app_users(user_id),
  requested_at timestamp default systimestamp,
  status       varchar2(20) default 'QUEUED' check (status in ('QUEUED','RUNNING','DONE','ERROR')),
  started_at   timestamp,
  finished_at  timestamp,
  error_message varchar2(4000)
);
