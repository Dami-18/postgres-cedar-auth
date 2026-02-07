-- Remove demo data/users
DROP TABLE IF EXISTS abac_test.employees;
DROP TABLE IF EXISTS abac_test.projects;
DROP TABLE IF EXISTS abac_test.sensitive_data;

-- Remove schema
DROP SCHEMA IF EXISTS abac_test CASCADE;

-- Remove users (Roles)
DROP ROLE IF EXISTS user_alice;
DROP ROLE IF EXISTS user_bob;
DROP ROLE IF EXISTS user_charlie;

