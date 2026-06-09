import sqlite3


def init_db():
    from db import get_db

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now')),
        two_factor_secret TEXT DEFAULT '',
        two_factor_enabled INTEGER DEFAULT 0,
        strict_mode INTEGER DEFAULT 0,
        login_alerts INTEGER DEFAULT 0
    )
    """)

    cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    website TEXT NOT NULL,
    site_username TEXT NOT NULL,
    site_password TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    last_updated TEXT DEFAULT (datetime('now'))
)
""")

    # ── Migrations for databases created before these columns existed ──
    user_cols = [row[1] for row in cursor.execute("PRAGMA table_info(users)")]

    if "email" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")

    if "created_at" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
        cursor.execute(
            "UPDATE users SET created_at = datetime('now') WHERE created_at IS NULL"
        )

    if "two_factor_secret" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN two_factor_secret TEXT DEFAULT ''")
        cursor.execute("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE users ADD COLUMN strict_mode INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE users ADD COLUMN login_alerts INTEGER DEFAULT 0")

    vault_cols = [row[1] for row in cursor.execute("PRAGMA table_info(vault)")]

    if "created_at" not in vault_cols:
        cursor.execute("ALTER TABLE vault ADD COLUMN created_at TEXT")
        cursor.execute(
            "UPDATE vault SET created_at = datetime('now') WHERE created_at IS NULL"
        )

    if "last_updated" not in vault_cols:
        cursor.execute(
            "ALTER TABLE vault ADD COLUMN last_updated TEXT"
        )

        cursor.execute(
            """
            UPDATE vault
            SET last_updated = created_at
            WHERE last_updated IS NULL
            """
        )
    if "theme" not in user_cols:
        cursor.execute(
        "ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'dark'"
    )

    if "reuse_alerts" not in user_cols:
        cursor.execute(
        "ALTER TABLE users ADD COLUMN reuse_alerts INTEGER DEFAULT 1"
    )
    if "backup_codes" not in user_cols:
        cursor.execute(
        "ALTER TABLE users ADD COLUMN backup_codes TEXT DEFAULT ''"
    )
    if "weak_alerts" not in user_cols:
        cursor.execute(
        "ALTER TABLE users ADD COLUMN weak_alerts INTEGER DEFAULT 1"
    )

    if "breach_alerts" not in user_cols:
        cursor.execute(
        "ALTER TABLE users ADD COLUMN breach_alerts INTEGER DEFAULT 1"
    )

    if "auto_logout" not in user_cols:
        cursor.execute(
        "ALTER TABLE users ADD COLUMN auto_logout INTEGER DEFAULT 30"
    )
    
    conn.commit()
    conn.close()