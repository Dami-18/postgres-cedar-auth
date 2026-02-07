-- Basic sanity: extension + GUCs
-- Ensure URL is set (in case it wasn't in postgresql.conf)
ALTER SYSTEM SET pg_authorization.cedar_agent_url = 'http://localhost:8280';
SELECT pg_reload_conf();

-- Wait a moment for reload
SELECT pg_sleep(1);

SELECT
    version(),
    current_database() AS db,
    current_user       AS user,
    pg_authorization_is_enabled() AS auth_enabled;

SHOW shared_preload_libraries;
SHOW pg_authorization.cedar_agent_url;
SHOW pg_authorization.enabled;

-- Create a dedicated test role
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'alice') THEN
        CREATE ROLE alice LOGIN PASSWORD 'alice';
    END IF;
END;
$$;

-- Create test database if it does not exist (psql meta-command + \gexec)
SELECT 'CREATE DATABASE auth_test_db'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = 'auth_test_db'
)\gexec

\connect auth_test_db

-- Create the extension in this new database
CREATE EXTENSION IF NOT EXISTS pg_authorization;

-- Confirm extension is present in this DB
SELECT pg_authorization_is_enabled() AS auth_enabled_in_db;

-- DDL: create a table (should trigger entity sync + DDL authorization)
DROP TABLE IF EXISTS public.docs;
CREATE TABLE public.docs (
    id   int PRIMARY KEY,
    owner text,
    body  text
);

-- DML: as superuser, insert a row (should succeed regardless of Cedar)
INSERT INTO public.docs(id, owner, body) VALUES (1, 'alice', 'hello from superuser');

-- Give alice minimal privileges so that all real decisions come from Cedar
GRANT CONNECT ON DATABASE auth_test_db TO alice;
GRANT USAGE ON SCHEMA public TO alice;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.docs TO alice;

-- Now test as alice (these calls should go through Cedar)
/* Switch session user to alice */
SET SESSION AUTHORIZATION alice;

-- SELECT: should cause a Cedar /is_authorized call with action "Select" on resource "Table::\"public.docs\""
SELECT * FROM public.docs;

-- INSERT: should cause a Cedar call with action "Insert"
INSERT INTO public.docs(id, owner, body) VALUES (2, 'alice', 'insert from alice');

-- UPDATE: should cause a Cedar call with action "Update"
UPDATE public.docs SET body = 'updated by alice' WHERE id = 2;

-- DELETE: should cause a Cedar call with action "Delete"
DELETE FROM public.docs WHERE id = 2;

-- DDL as alice: should also go through Cedar (and likely be denied unless policy allows)
DO $$
BEGIN
    BEGIN
        CREATE TABLE public.alice_tmp (id int);
        RAISE NOTICE 'alice was able to CREATE TABLE';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'alice CREATE TABLE was denied (expected if Cedar denies DDL)';
    END;
END;
$$;

-- Reset to superuser
RESET SESSION AUTHORIZATION;

-- Drop alice_tmp if it was created
DROP TABLE IF EXISTS public.alice_tmp;

-- DDL to trigger DROP entity sync
DROP TABLE IF EXISTS public.docs;

-- Check stats from the extension (authorization + sync counters)
SELECT * FROM pg_authorization_stats();