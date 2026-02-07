-- Check current settings
SHOW pg_authorization.cedar_agent_url;

-- Set Cedar Agent URL (cluster-wide setting)
ALTER SYSTEM SET pg_authorization.cedar_agent_url = 'http://localhost:8280';
SELECT pg_reload_conf();

-- Wait for reload
SELECT pg_sleep(1);

-- Verify
SHOW pg_authorization.cedar_agent_url;

-- Create extension (must be done in the database you intend to use)
CREATE EXTENSION IF NOT EXISTS pg_authorization;

-- Verify extension is enabled
SELECT pg_authorization_is_enabled();

