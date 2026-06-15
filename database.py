from db import get_db


def init_db():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        two_factor_secret TEXT DEFAULT '',
        two_factor_enabled INTEGER DEFAULT 0,
        strict_mode INTEGER DEFAULT 0,
        login_alerts INTEGER DEFAULT 0,
        theme TEXT DEFAULT 'dark',
        reuse_alerts INTEGER DEFAULT 1,
        backup_codes TEXT DEFAULT '',
        weak_alerts INTEGER DEFAULT 1,
        breach_alerts INTEGER DEFAULT 1,
        auto_logout INTEGER DEFAULT 30
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault (
        id SERIAL PRIMARY KEY,
        website TEXT NOT NULL,
        site_username TEXT NOT NULL,
        site_password TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()

    # Database migration: add google_id column to users table if it does not exist
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN google_id TEXT DEFAULT '';")
        conn.commit()
    except Exception:
        # If the column already exists, rollback the transaction and ignore
        conn.rollback()

    conn.close()