-- 000001_platform_core.down.sql
BEGIN;
DROP TABLE IF EXISTS platform.kill_switches;
DROP TABLE IF EXISTS platform.outbox;
DROP TABLE IF EXISTS platform.agents;
DROP TABLE IF EXISTS platform.task_state_transitions;
DROP TABLE IF EXISTS platform.tasks;
DROP TABLE IF EXISTS platform.plans;
DROP TABLE IF EXISTS platform.missions;
DROP SCHEMA IF EXISTS platform;
COMMIT;
