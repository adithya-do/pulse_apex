
prompt ***** PULSEAPP Starter - Install Objects + APEX App (ID 91000) *****

--------------------------------------------------------------------------------
-- 0) Prereqs (run as SYS beforehand):
--    GRANT EXECUTE ON DBMS_CRYPTO TO PULSEAPP;
--    GRANT EXECUTE ON APEX_MAIL   TO PULSEAPP;  -- optional (forgot-password)
-- This script assumes parsing schema is PULSEAPP.
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- 1) Core tables
--------------------------------------------------------------------------------
-- USERS & AUTH
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
  code       varchar2(50) not null unique, -- 'ORA_DB','MSSQL_DB'
  name       varchar2(100) not null
);

create table app_user_modules (
  user_id    number not null references app_users(user_id),
  module_id  number not null references app_modules(module_id),
  constraint app_user_modules_pk primary key (user_id, module_id)
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
  enc_password   raw(2000) not null,        -- encrypted with encrypt_pkg
  owner_email    varchar2(320),
  is_active      char(1) default 'Y' check (is_active in ('Y','N')),
  created_by     number references app_users(user_id),
  created_at     timestamp default systimestamp,
  updated_at     timestamp
);

create table ora_db_status (
  status_id           number generated always as identity primary key,
  target_id           number not null references ora_db_targets(target_id),
  status              varchar2(20),    -- UP/DOWN/ERROR
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
  instance_name  varchar2(200) not null,
  environment    varchar2(30)  not null,
  host           varchar2(255) not null,
  port           number default 1433,
  auth_mode      varchar2(10) not null check (auth_mode in ('SQL','WIN')),
  username       varchar2(128),
  enc_password   raw(2000),
  owner_email    varchar2(320),
  is_active      char(1) default 'Y' check (is_active in ('Y','N')),
  created_by     number references app_users(user_id),
  created_at     timestamp default systimestamp,
  updated_at     timestamp
);

create table mssql_status (
  status_id           number generated always as identity primary key,
  target_id           number not null references mssql_targets(target_id),
  status              varchar2(20), -- UP/DOWN/ERROR
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

--------------------------------------------------------------------------------
-- 2) Packages using DBMS_CRYPTO only
--------------------------------------------------------------------------------
CREATE OR REPLACE PACKAGE encrypt_pkg AUTHID DEFINER AS
  FUNCTION hash_password(p_plain IN VARCHAR2, p_salt OUT RAW) RETURN RAW;
  FUNCTION verify_password(p_plain IN VARCHAR2, p_salt IN RAW, p_hash IN RAW) RETURN NUMBER;
  FUNCTION enc_secret(p_plain IN VARCHAR2) RETURN RAW;
  FUNCTION dec_secret(p_raw   IN RAW) RETURN VARCHAR2;
END encrypt_pkg;
/
CREATE OR REPLACE PACKAGE BODY encrypt_pkg AS
  g_key  RAW(32) := HEXTORAW('7B1D0F8C6A55A4E91F3B2C4D5E6F70811223344556677889900AABBCCDDEEFF0');
  g_iter CONSTANT PLS_INTEGER := 20000;

  FUNCTION pbkdf_sha512(p_data RAW, p_salt RAW, p_iter PLS_INTEGER) RETURN RAW IS
    l_hash RAW(64);
  BEGIN
    l_hash := DBMS_CRYPTO.HASH(p_data || p_salt, DBMS_CRYPTO.HASH_SH512);
    FOR i IN 1 .. p_iter LOOP
      l_hash := DBMS_CRYPTO.HASH(l_hash || p_salt, DBMS_CRYPTO.HASH_SH512);
    END LOOP;
    RETURN l_hash;
  END;

  FUNCTION hash_password(p_plain IN VARCHAR2, p_salt OUT RAW) RETURN RAW IS
    l_raw RAW(2000) := UTL_RAW.CAST_TO_RAW(p_plain);
  BEGIN
    p_salt := DBMS_CRYPTO.RANDOMBYTES(16);
    RETURN pbkdf_sha512(l_raw, p_salt, g_iter);
  END;

  FUNCTION verify_password(p_plain IN VARCHAR2, p_salt IN RAW, p_hash IN RAW) RETURN NUMBER IS
    l_raw RAW(2000) := UTL_RAW.CAST_TO_RAW(p_plain);
  BEGIN
    RETURN CASE WHEN pbkdf_sha512(l_raw, p_salt, g_iter) = p_hash THEN 1 ELSE 0 END;
  END;

  FUNCTION enc_secret(p_plain IN VARCHAR2) RETURN RAW IS
    l_iv RAW(16) := DBMS_CRYPTO.RANDOMBYTES(16);
    l_ct RAW(32767);
  BEGIN
    l_ct := DBMS_CRYPTO.ENCRYPT(
              src => UTL_RAW.CAST_TO_RAW(p_plain),
              typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
              key => g_key,
              iv  => l_iv);
    RETURN l_iv || l_ct;
  END;

  FUNCTION dec_secret(p_raw IN RAW) RETURN VARCHAR2 IS
    l_iv RAW(16);
    l_ct RAW(32767);
    l_pt RAW(32767);
  BEGIN
    l_iv := UTL_RAW.SUBSTR(p_raw, 1, 16);
    l_ct := UTL_RAW.SUBSTR(p_raw, 17);
    l_pt := DBMS_CRYPTO.DECRYPT(
              src => l_ct,
              typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
              key => g_key,
              iv  => l_iv);
    RETURN UTL_RAW.CAST_TO_VARCHAR2(l_pt);
  END;
END encrypt_pkg;
/
SHOW ERRORS

CREATE OR REPLACE PACKAGE auth_pkg AUTHID DEFINER AS
  FUNCTION login(p_login IN VARCHAR2, p_password IN VARCHAR2) RETURN NUMBER;
  PROCEDURE set_password(p_user_id IN NUMBER, p_new IN VARCHAR2);
  PROCEDURE create_user(p_login IN VARCHAR2, p_full IN VARCHAR2, p_email IN VARCHAR2,
                        p_temp_password OUT VARCHAR2);
  PROCEDURE forgot_password(p_login IN VARCHAR2);
END auth_pkg;
/
CREATE OR REPLACE PACKAGE BODY auth_pkg AS
  FUNCTION gen_temp_password(p_len PLS_INTEGER DEFAULT 16) RETURN VARCHAR2 IS
    l_hex VARCHAR2(4000) := LOWER(RAWTOHEX(DBMS_CRYPTO.RANDOMBYTES(32)));
  BEGIN
    RETURN SUBSTR(l_hex, 1, LEAST(p_len, LENGTH(l_hex)));
  END;

  FUNCTION login(p_login IN VARCHAR2, p_password IN VARCHAR2) RETURN NUMBER IS
    l_uid    app_users.user_id%TYPE;
    l_hash   app_users.pwd_hash%TYPE;
    l_salt   app_users.pwd_salt%TYPE;
    l_active app_users.is_active%TYPE;
  BEGIN
    SELECT user_id, pwd_hash, pwd_salt, is_active
      INTO l_uid,   l_hash,   l_salt,   l_active
      FROM app_users
     WHERE login_name = LOWER(p_login);

    IF l_active <> 'Y' THEN
      RETURN NULL;
    END IF;

    IF encrypt_pkg.verify_password(p_password, l_salt, l_hash) = 1 THEN
      RETURN l_uid;
    ELSE
      RETURN NULL;
    END IF;
  EXCEPTION WHEN NO_DATA_FOUND THEN
    RETURN NULL;
  END;

  PROCEDURE set_password(p_user_id IN NUMBER, p_new IN VARCHAR2) IS
    l_salt RAW(2000);
    l_hash RAW(2000);
  BEGIN
    l_hash := encrypt_pkg.hash_password(p_new, l_salt);
    UPDATE app_users
       SET pwd_hash        = l_hash,
           pwd_salt        = l_salt,
           must_change_pwd = 'N',
           updated_at      = SYSTIMESTAMP
     WHERE user_id         = p_user_id;
  END;

  PROCEDURE create_user(p_login IN VARCHAR2, p_full IN VARCHAR2, p_email IN VARCHAR2,
                        p_temp_password OUT VARCHAR2) IS
    l_salt RAW(2000);
    l_hash RAW(2000);
  BEGIN
    p_temp_password := gen_temp_password(16);
    l_hash := encrypt_pkg.hash_password(p_temp_password, l_salt);
    INSERT INTO app_users (login_name, full_name, email, pwd_hash, pwd_salt,
                           is_active, must_change_pwd, created_at)
    VALUES (LOWER(p_login), p_full, p_email, l_hash, l_salt, 'Y', 'Y', SYSTIMESTAMP);
  END;

  PROCEDURE forgot_password(p_login IN VARCHAR2) IS
    l_uid   app_users.user_id%TYPE;
    l_email app_users.email%TYPE;
    l_temp  VARCHAR2(64);
  BEGIN
    SELECT user_id, email INTO l_uid, l_email
      FROM app_users WHERE login_name = LOWER(p_login);
    l_temp := gen_temp_password(16);
    set_password(l_uid, l_temp);
    APEX_MAIL.SEND(
      p_to   => l_email,
      p_from => 'no-reply@yourdomain',
      p_subj => 'Your temporary password',
      p_body => 'Hello,' || CHR(10) ||
                'Your temporary password is: ' || l_temp || CHR(10) ||
                'Please log in and change it immediately.');
    COMMIT;
  EXCEPTION WHEN NO_DATA_FOUND THEN NULL;
  END;
END auth_pkg;
/
SHOW ERRORS

-- Optional auth function for APEX custom auth (not used by default in this app)
CREATE OR REPLACE FUNCTION apex_auth_fn(p_username IN VARCHAR2, p_password IN VARCHAR2)
  RETURN BOOLEAN
IS
  l_uid NUMBER;
BEGIN
  l_uid := auth_pkg.login(p_username, p_password);
  IF l_uid IS NOT NULL THEN
    APEX_UTIL.SET_SESSION_STATE('APP_USER_ID', l_uid);
    RETURN TRUE;
  END IF;
  RETURN FALSE;
END;
/
SHOW ERRORS

--------------------------------------------------------------------------------
-- 3) Seed roles/modules and initial app user
--------------------------------------------------------------------------------
insert into app_roles(code,name) values ('ADMIN','Administrator');
insert into app_roles(code,name) values ('SUPER','Super User');
insert into app_roles(code,name) values ('ORACLE','Oracle Module User');
insert into app_roles(code,name) values ('MSSQL','SQL Server Module User');

insert into app_modules(code,name) values ('ORA_DB','Oracle Databases');
insert into app_modules(code,name) values ('MSSQL_DB','SQL Server Databases');
commit;

declare v_temp varchar2(32);
begin
  auth_pkg.create_user('admin','Platform Admin','admin@example.com', v_temp);
  dbms_output.put_line('Admin temp password = '||v_temp);
end;
/
insert into app_user_roles(user_id, role_id)
select u.user_id, r.role_id
  from app_users u join app_roles r on r.code in ('ADMIN','SUPER')
 where u.login_name='admin';

insert into app_user_modules(user_id, module_id)
select u.user_id, m.module_id
  from app_users u join app_modules m on m.code in ('ORA_DB','MSSQL_DB')
 where u.login_name='admin';
commit;

--------------------------------------------------------------------------------
-- 4) Create APEX Application (ID 91000)
--------------------------------------------------------------------------------
begin
  apex_application_install.set_application_id(91000);
  apex_application_install.set_application_alias('PULSE_HEALTH');
  apex_application_install.set_application_name('Pulse Health Console');
  apex_application_install.set_schema('PULSEAPP');
  apex_application_install.generate_offset;

  apex_application_api.create_application(
    p_id                => 91000,
    p_name              => 'Pulse Health Console',
    p_alias             => 'PULSE_HEALTH',
    p_page_view_logging => 'YES',
    p_flow_language     => 'en',
    p_flow_language_derived_from => 'FLOW_PRIMARY_LANGUAGE',
    p_date_format       => 'YYYY-MM-DD HH24:MI:SS',
    p_theme_number      => 42,   -- Universal Theme
    p_authentication    => 'APEX',  -- APEX accounts to start; switch to custom later if desired
    p_subscribe_to_theme => 'Y'
  );

  --------------------------------------------------------------------
  -- Authorization Scheme: Is_Admin
  --------------------------------------------------------------------
  apex_application_api.create_security_scheme(
    p_id                    => 91000+1,
    p_name                  => 'Is_Admin',
    p_scheme_type           => 'NATIVE_FUNCTION_BODY',
    p_security_scheme_type  => 'AUTHORIZATION',
    p_attribute_01          => 'return exists (select 1 from app_user_roles r join app_roles a on a.role_id=r.role_id where r.user_id = to_number(nvl(v(''APP_USER_ID''),0)) and a.code = ''ADMIN'');',
    p_error_message         => 'Not authorized.'
  );

  --------------------------------------------------------------------
  -- Page 1: Home
  --------------------------------------------------------------------
  apex_application_api.create_page(
    p_id                => 1,
    p_name              => 'Home',
    p_step_title        => 'Home',
    p_autocomplete_on_off => 'OFF',
    p_page_mode         => 'NORMAL',
    p_is_public         => 'N',
    p_last_upd_yyyymmddhh24miss => to_char(sysdate,'YYYYMMDDHH24MISS')
  );
  apex_application_api.create_region(
    p_id            => 91000+100,
    p_name          => 'Welcome',
    p_region_name   => 'Welcome',
    p_parent_id     => null,
    p_page_id       => 1,
    p_region_template_options => null,
    p_display_sequence => 10,
    p_region_template => null,
    p_source_type   => 'NATIVE_STATIC',
    p_source        => q'[
<h2>Pulse Health Console</h2>
<p>Use the links below:</p>
<ul>
  <li><a href="f?p=&APP_ID.:20:&APP_SESSION.">Oracle Databases - Status</a></li>
  <li><a href="f?p=&APP_ID.:21:&APP_SESSION.">Run Oracle Check</a></li>
  <li><a href="f?p=&APP_ID.:30:&APP_SESSION.">SQL Server - Status</a></li>
  <li><a href="f?p=&APP_ID.:31:&APP_SESSION.">Run SQL Server Check</a></li>
  <li><a href="f?p=&APP_ID.:10:&APP_SESSION.">Admin Users</a></li>
</ul>]'
  );

  --------------------------------------------------------------------
  -- Page 20: Oracle Status (latest per target)
  --------------------------------------------------------------------
  apex_application_api.create_page(
    p_id                => 20,
    p_name              => 'Oracle Status',
    p_step_title        => 'Oracle Status',
    p_autocomplete_on_off => 'OFF',
    p_page_mode         => 'NORMAL',
    p_is_public         => 'N',
    p_last_upd_yyyymmddhh24miss => to_char(sysdate,'YYYYMMDDHH24MISS')
  );
  apex_application_api.create_region(
    p_id            => 91000+200,
    p_name          => 'Oracle Databases - Latest Status',
    p_region_name   => 'Oracle Databases - Latest Status',
    p_page_id       => 20,
    p_display_sequence => 10,
    p_source_type   => 'NATIVE_IR',
    p_source        => q'[
select
  t.target_id,
  row_number() over (order by t.target_id) as "S.No",
  t.db_name, t.environment, t.host,
  s.status, s.instance_status, s.db_open_mode,
  s.worst_tbs_pct, s.tbs_all_online_yn,
  s.last_full_backup, s.last_arch_backup,
  s.last_check_at, s.check_status, s.error_message
from ora_db_targets t
left join (
  select *
  from (
    select s.*,
           row_number() over (partition by s.target_id order by s.last_check_at desc) rn
      from ora_db_status s
  ) where rn = 1
) s on s.target_id = t.target_id
order by t.db_name]'
  );

  --------------------------------------------------------------------
  -- Page 21: Run Oracle Check
  --------------------------------------------------------------------
  apex_application_api.create_page(
    p_id                => 21,
    p_name              => 'Run Oracle Check',
    p_step_title        => 'Run Oracle Check',
    p_autocomplete_on_off => 'OFF',
    p_page_mode         => 'NORMAL',
    p_is_public         => 'N',
    p_last_upd_yyyymmddhh24miss => to_char(sysdate,'YYYYMMDDHH24MISS')
  );
  -- Select list
  apex_application_api.create_page_item(
    p_id            => 91000+210,
    p_page_id       => 21,
    p_name          => 'P21_TARGET_ID',
    p_item_sequence => 10,
    p_item_plug_id  => null,
    p_prompt        => 'Oracle Target',
    p_display_as    => 'NATIVE_SELECT_LIST',
    p_lov           => q'[select db_name||' - '||environment d, target_id r from ora_db_targets where is_active='Y' order by 1]',
    p_lov_display_null => 'YES',
    p_lov_null_text    => '- Select -',
    p_source_type      => 'STATIC'
  );
  -- Button to submit
  apex_application_api.create_button(
    p_id            => 91000+211,
    p_button_name   => 'RUN_CHECK',
    p_button_action => 'SUBMIT',
    p_button_position=> 'BELOW_BOX',
    p_button_sequence=> 20,
    p_page_id       => 21,
    p_button_image_alt => 'Run Check'
  );
  -- Process to enqueue
  apex_application_api.create_page_process(
    p_id              => 91000+212,
    p_page_id         => 21,
    p_process_sequence=> 10,
    p_process_point   => 'AFTER_SUBMIT',
    p_process_type    => 'NATIVE_PLSQL',
    p_process_name    => 'Enqueue Oracle Check',
    p_process_sql_clob=> q'[begin if :P21_TARGET_ID is not null then health_pkg.enqueue_check(''ORA_DB'', :P21_TARGET_ID, to_number(nvl(v(''APP_USER_ID''),0))); end if; end;]',
    p_process_success_message => 'Check queued.'
  );

  --------------------------------------------------------------------
  -- Page 30: SQL Server Status
  --------------------------------------------------------------------
  apex_application_api.create_page(
    p_id                => 30,
    p_name              => 'SQL Server Status',
    p_step_title        => 'SQL Server Status',
    p_autocomplete_on_off => 'OFF',
    p_page_mode         => 'NORMAL',
    p_is_public         => 'N',
    p_last_upd_yyyymmddhh24miss => to_char(sysdate,'YYYYMMDDHH24MISS')
  );
  apex_application_api.create_region(
    p_id            => 91000+300,
    p_name          => 'SQL Server - Latest Status',
    p_region_name   => 'SQL Server - Latest Status',
    p_page_id       => 30,
    p_display_sequence => 10,
    p_source_type   => 'NATIVE_IR',
    p_source        => q'[
select
  t.target_id,
  row_number() over (order by t.target_id) as "S.No",
  t.instance_name, t.environment, t.host,
  s.status, s.version_string,
  s.last_full_backup, s.last_log_backup,
  s.last_check_at, s.check_status, s.error_message
from mssql_targets t
left join (
  select *
  from (
    select s.*,
           row_number() over (partition by s.target_id order by s.last_check_at desc) rn
      from mssql_status s
  ) where rn = 1
) s on s.target_id = t.target_id
order by t.instance_name]'
  );

  --------------------------------------------------------------------
  -- Page 31: Run SQL Server Check
  --------------------------------------------------------------------
  apex_application_api.create_page(
    p_id                => 31,
    p_name              => 'Run SQL Server Check',
    p_step_title        => 'Run SQL Server Check',
    p_autocomplete_on_off => 'OFF',
    p_page_mode         => 'NORMAL',
    p_is_public         => 'N',
    p_last_upd_yyyymmddhh24miss => to_char(sysdate,'YYYYMMDDHH24MISS')
  );
  -- Select list
  apex_application_api.create_page_item(
    p_id            => 91000+310,
    p_page_id       => 31,
    p_name          => 'P31_TARGET_ID',
    p_item_sequence => 10,
    p_item_plug_id  => null,
    p_prompt        => 'SQL Server Target',
    p_display_as    => 'NATIVE_SELECT_LIST',
    p_lov           => q'[select instance_name||' - '||environment d, target_id r from mssql_targets where is_active='Y' order by 1]',
    p_lov_display_null => 'YES',
    p_lov_null_text    => '- Select -',
    p_source_type      => 'STATIC'
  );
  -- Button
  apex_application_api.create_button(
    p_id            => 91000+311,
    p_button_name   => 'RUN_CHECK',
    p_button_action => 'SUBMIT',
    p_button_position=> 'BELOW_BOX',
    p_button_sequence=> 20,
    p_page_id       => 31,
    p_button_image_alt => 'Run Check'
  );
  -- Process
  apex_application_api.create_page_process(
    p_id              => 91000+312,
    p_page_id         => 31,
    p_process_sequence=> 10,
    p_process_point   => 'AFTER_SUBMIT',
    p_process_type    => 'NATIVE_PLSQL',
    p_process_name    => 'Enqueue MSSQL Check',
    p_process_sql_clob=> q'[begin if :P31_TARGET_ID is not null then health_pkg.enqueue_check(''MSSQL_DB'', :P31_TARGET_ID, to_number(nvl(v(''APP_USER_ID''),0))); end if; end;]',
    p_process_success_message => 'Check queued.'
  );

  --------------------------------------------------------------------
  -- Page 10: Admin Users (read-only IR; secure with Is_Admin)
  --------------------------------------------------------------------
  apex_application_api.create_page(
    p_id                => 10,
    p_name              => 'Admin Users',
    p_step_title        => 'Admin Users',
    p_autocomplete_on_off => 'OFF',
    p_page_mode         => 'NORMAL',
    p_is_public         => 'N',
    p_security_scheme   => 'Is_Admin',
    p_last_upd_yyyymmddhh24miss => to_char(sysdate,'YYYYMMDDHH24MISS')
  );
  apex_application_api.create_region(
    p_id            => 91000+120,
    p_name          => 'Users',
    p_region_name   => 'Users',
    p_page_id       => 10,
    p_display_sequence => 10,
    p_source_type   => 'NATIVE_IR',
    p_source        => q'[
select u.user_id, u.login_name, u.full_name, u.email, u.is_active, u.must_change_pwd,
       u.created_at, u.updated_at
  from app_users u
order by u.user_id]'
  );

end;
/

prompt ***** DONE. Import completed. *****
