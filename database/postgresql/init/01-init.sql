-- CyberSentinel DLP - PostgreSQL Database Initialization Script
-- This script is executed when PostgreSQL container starts for the first time

-- Create database if not exists
SELECT 'CREATE DATABASE cybersentinel_dlp'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cybersentinel_dlp')\gexec

-- Connect to database
\c cybersentinel_dlp;

-- Create UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create ENUM types
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer', 'agent');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE event_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE agent_status AS ENUM ('online', 'offline', 'error', 'maintenance');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Grant privileges to DLP user
GRANT ALL PRIVILEGES ON DATABASE cybersentinel_dlp TO dlp_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO dlp_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO dlp_user;
GRANT USAGE ON SCHEMA public TO dlp_user;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO dlp_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO dlp_user;

-- Create audit logging function
CREATE OR REPLACE FUNCTION audit_trigger_func()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (table_name, operation, new_data, changed_at)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(NEW), now());
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (table_name, operation, old_data, new_data, changed_at)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD), row_to_json(NEW), now());
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (table_name, operation, old_data, changed_at)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD), now());
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create indexes for performance
-- Note: These will be created after Alembic migration creates the tables
-- This is a reference for manual indexing if needed

COMMENT ON SCHEMA public IS 'CyberSentinel DLP Database Schema';
