/* contrib/pg_authorization/pg_authorization--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_authorization" to load this file. \quit

-- Function to check if the authorization plugin is enabled
CREATE FUNCTION pg_authorization_is_enabled()
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_authorization_is_enabled'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pg_authorization_is_enabled() IS
'Returns true if the pg_authorization plugin is enabled';

-- Function to get authorization statistics
CREATE FUNCTION pg_authorization_stats(
    OUT auth_requests bigint,
    OUT auth_grants bigint,
    OUT auth_denies bigint,
    OUT auth_ignores bigint,
    OUT auth_errors bigint,
    OUT sync_requests bigint,
    OUT sync_successes bigint,
    OUT sync_failures bigint,
    OUT avg_total_time_ms double precision,
    OUT avg_remote_time_ms double precision
)
RETURNS record
AS 'MODULE_PATHNAME', 'pg_authorization_stats'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pg_authorization_stats() IS
'Returns authorization and entity sync statistics';

-- Function to reset authorization statistics
CREATE FUNCTION pg_authorization_reset_stats()
RETURNS void
AS 'MODULE_PATHNAME', 'pg_authorization_reset_stats'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pg_authorization_reset_stats() IS
'Resets all authorization and entity sync statistics to zero';

-- Function to manually sync an entity to Cedar Agent
CREATE FUNCTION pg_authorization_sync_entity(entity_type text, entity_id text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_authorization_sync_entity'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pg_authorization_sync_entity(text, text) IS
'Manually sync an entity to the Cedar Agent. Returns true on success.
Example: SELECT pg_authorization_sync_entity(''Table'', ''public.mytable'');';

-- Function to get cache statistics
CREATE FUNCTION pg_authorization_cache_stats(
    OUT hits bigint,
    OUT misses bigint,
    OUT evictions bigint,
    OUT entries bigint
)
RETURNS record
AS 'MODULE_PATHNAME', 'pg_authorization_cache_stats'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pg_authorization_cache_stats() IS
'Returns authorization cache statistics';

-- Function to reset cache
CREATE FUNCTION pg_authorization_cache_reset()
RETURNS void
AS 'MODULE_PATHNAME', 'pg_authorization_cache_reset'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pg_authorization_cache_reset() IS
'Resets the authorization cache';

-- Function to flush system caches
CREATE FUNCTION pg_authorization_flush_syscache()
RETURNS void
AS 'MODULE_PATHNAME', 'pg_authorization_flush_syscache'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pg_authorization_flush_syscache() IS
'Flushes all PostgreSQL system caches (catalog cache, relcache, etc.)';

-- View for easy access to statistics
CREATE VIEW pg_authorization_statistics AS
SELECT * FROM pg_authorization_stats();

COMMENT ON VIEW pg_authorization_statistics IS
'View showing current authorization and entity sync statistics';

-- View for current configuration
CREATE VIEW pg_authorization_config AS
SELECT
    current_setting('pg_authorization.cedar_agent_url', true) AS cedar_agent_url,
    current_setting('pg_authorization.timeout', true) AS timeout_ms,
    current_setting('pg_authorization.namespace', true) AS cedar_namespace,
    current_setting('pg_authorization.enabled', true) AS authorization_enabled,
    current_setting('pg_authorization.entity_sync_enabled', true) AS entity_sync_enabled,
    current_setting('pg_authorization.log_decisions', true) AS log_decisions;

COMMENT ON VIEW pg_authorization_config IS
'View showing current pg_authorization configuration';
