-- Create Users (Roles)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'user_alice') THEN
        CREATE ROLE user_alice LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'user_bob') THEN
        CREATE ROLE user_bob LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'user_charlie') THEN
        CREATE ROLE user_charlie LOGIN;
    END IF;
END;
$$;

-- Create Schema (analogous to MySQL Database)
CREATE SCHEMA IF NOT EXISTS abac_test;

-- Grant usage on schema to users
GRANT USAGE ON SCHEMA abac_test TO user_alice, user_bob, user_charlie;

-- Create Tables
CREATE TABLE IF NOT EXISTS abac_test.employees ( 
    id INT PRIMARY KEY, 
    name VARCHAR(100), 
    department VARCHAR(50) 
);

INSERT INTO abac_test.employees (id, name, department) VALUES (1, 'Alice', 'HR');
INSERT INTO abac_test.employees (id, name, department) VALUES (2, 'Bob', 'IT');
INSERT INTO abac_test.employees (id, name, department) VALUES (3, 'Charlie', 'Finance');

CREATE TABLE IF NOT EXISTS abac_test.projects ( 
    id INT PRIMARY KEY, 
    name VARCHAR(100), 
    classification VARCHAR(50) 
);

INSERT INTO abac_test.projects (id, name, classification) VALUES (1, 'Project 1', 'Public');
INSERT INTO abac_test.projects (id, name, classification) VALUES (2, 'Project 2', 'Internal');
INSERT INTO abac_test.projects (id, name, classification) VALUES (3, 'Project 3', 'Confidential');

CREATE TABLE IF NOT EXISTS abac_test.sensitive_data ( 
    id INT PRIMARY KEY, 
    info TEXT 
);

INSERT INTO abac_test.sensitive_data (id, info) VALUES (1, 'Sensitive data 1');
INSERT INTO abac_test.sensitive_data (id, info) VALUES (2, 'Sensitive data 2');
INSERT INTO abac_test.sensitive_data (id, info) VALUES (3, 'Sensitive data 3');

-- Grant privileges to allow users to reach the authorization hook
-- In standard Postgres, if they don't have permission, it fails before the hook (usually).
-- Assuming the Cedar extension enforces policy *in addition* to or *instead of* standard ACLs if configured.
-- But standard practice for these tests usually grants nominal privileges.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA abac_test TO user_alice, user_bob, user_charlie;

