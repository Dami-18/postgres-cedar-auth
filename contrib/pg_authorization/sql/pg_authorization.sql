/* Test the pg_authorization extension */
CREATE EXTENSION pg_authorization;

-- Check if enabled (should be true by default)
SELECT pg_authorization_is_enabled();

-- Check statistics (should be all zeros initially)
SELECT * FROM pg_authorization_statistics;

-- Check configuration
SELECT * FROM pg_authorization_config;

-- Test resetting stats
SELECT pg_authorization_reset_stats();
SELECT * FROM pg_authorization_statistics;

-- Clean up
DROP EXTENSION pg_authorization;
