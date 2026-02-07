-- PostgreSQL initialization script for authorization benchmarking
-- Creates the abac_test database and sets up basic schema

-- Create database (if not exists)
SELECT 'CREATE DATABASE abac_test' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'abac_test')\gexec

-- Connect to the database
\c abac_test;

-- Create test users
CREATE USER user_alice;
CREATE USER user_bob;
CREATE USER user_charlie;

-- Create test tables
CREATE TABLE IF NOT EXISTS projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    owner_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sensitive_data (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id),
    data TEXT,
    classification VARCHAR(50) DEFAULT 'confidential'
);

CREATE TABLE IF NOT EXISTS user_permissions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    permission VARCHAR(100),
    resource_type VARCHAR(100),
    resource_id INTEGER
);

CREATE TABLE IF NOT EXISTS audit_trail (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(100),
    resource_type VARCHAR(100),
    resource_id INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant basic permissions
GRANT SELECT, INSERT, UPDATE ON projects TO user_alice, user_bob, user_charlie;
GRANT SELECT ON sensitive_data TO user_alice;
GRANT SELECT, INSERT, UPDATE, DELETE ON sensitive_data TO user_bob;
GRANT SELECT ON user_permissions TO user_alice, user_bob;
GRANT SELECT, INSERT ON audit_trail TO user_alice, user_bob, user_charlie;

-- Insert test data
INSERT INTO projects (name, owner_id) VALUES
    ('Project Alpha', 1),
    ('Project Beta', 2),
    ('Project Gamma', 3)
ON CONFLICT DO NOTHING;

INSERT INTO sensitive_data (project_id, data, classification) VALUES
    (1, 'Secret project data A', 'confidential'),
    (2, 'Secret project data B', 'restricted'),
    (3, 'Secret project data C', 'confidential')
ON CONFLICT DO NOTHING;

INSERT INTO user_permissions (user_id, permission, resource_type, resource_id) VALUES
    (1, 'read', 'project', 1),
    (1, 'write', 'project', 1),
    (2, 'read', 'sensitive_data', 2),
    (2, 'write', 'sensitive_data', 2),
    (3, 'read', 'project', 3)
ON CONFLICT DO NOTHING;

-- Create pg_authorization extension (for modified PostgreSQL)
-- This will only work on the modified PostgreSQL with hooks
DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_authorization;
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'Note: pg_authorization extension not available or failed: %', SQLERRM;
    END;
END $$;
