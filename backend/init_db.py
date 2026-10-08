import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("SOC_DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("SOC_DB_PORT", "5432")),
    "dbname": os.getenv("SOC_DB_NAME", "soc_dashboard"),
    "user": os.getenv("SOC_DB_USER", "soc_app"),
    "password": os.getenv("SOC_DB_PASSWORD"),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    alert_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    source_ip INET,
    destination_ip INET,
    severity INTEGER DEFAULT 3,
    status TEXT NOT NULL DEFAULT 'NEW',
    assigned_to TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_history (
    id BIGSERIAL PRIMARY KEY,
    event_id TEXT,
    timestamp TIMESTAMPTZ,
    source_ip INET,
    destination_ip INET,
    protocol TEXT,
    signature TEXT,
    severity INTEGER,
    category TEXT,
    raw_event JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    username TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    details JSONB,
    source_ip INET,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alert_history_timestamp
ON alert_history(timestamp);

CREATE INDEX IF NOT EXISTS idx_alert_history_source_ip
ON alert_history(source_ip);

CREATE INDEX IF NOT EXISTS idx_alert_history_destination_ip
ON alert_history(destination_ip);

CREATE INDEX IF NOT EXISTS idx_incidents_status
ON incidents(status);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
ON audit_log(created_at);
"""


def main():
    print("Connecting to PostgreSQL...")

    with psycopg.connect(**DB_CONFIG) as connection:
        with connection.cursor() as cursor:
            cursor.execute(SCHEMA)

    print("SOC database schema created successfully.")


if __name__ == "__main__":
    main()
