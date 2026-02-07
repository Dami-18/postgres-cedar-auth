-- Disable/Drop extension
DROP EXTENSION IF EXISTS pg_authorization;

-- Reset config
ALTER SYSTEM RESET pg_authorization.cedar_agent_url;
SELECT pg_reload_conf();

-- Verify
SHOW pg_authorization.cedar_agent_url;
SELECT * FROM pg_extension WHERE extname = 'pg_authorization';

