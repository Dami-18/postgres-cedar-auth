-- Authorization checks based on cedar_authorize.sh

-- 1. user_alice selects from sensitive_data
SET SESSION AUTHORIZATION user_alice;
SELECT * FROM abac_test.sensitive_data;
RESET SESSION AUTHORIZATION;

-- 2. user_bob selects from projects
SET SESSION AUTHORIZATION user_bob;
SELECT * FROM abac_test.projects;
RESET SESSION AUTHORIZATION;

-- 3. user_bob inserts into projects
SET SESSION AUTHORIZATION user_bob;
INSERT INTO abac_test.projects (id, name, classification) VALUES (4, 'Project A', 'Top Secret');
RESET SESSION AUTHORIZATION;

-- 4. user_bob updates projects
SET SESSION AUTHORIZATION user_bob;
UPDATE abac_test.projects SET classification = 'Top Secret' WHERE id = 1;
RESET SESSION AUTHORIZATION;

-- 5. user_bob deletes from projects
SET SESSION AUTHORIZATION user_bob;
DELETE FROM abac_test.projects WHERE id = 1;
RESET SESSION AUTHORIZATION;

-- 6. user_charlie selects from employees
SET SESSION AUTHORIZATION user_charlie;
SELECT * FROM abac_test.employees;
RESET SESSION AUTHORIZATION;

