import sqlite3


def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        website TEXT NOT NULL,
        site_username TEXT NOT NULL,
        site_password TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )
    """)

    # ── Migration: add created_at to existing databases that pre-date this column
    existing_columns = [
        row[1]
        for row in cursor.execute("PRAGMA table_info(vault)")
    ]
    if "created_at" not in existing_columns:
        # SQLite ALTER TABLE does not allow function-based DEFAULT expressions,
        # so we add the column without a default and back-fill manually.
        cursor.execute(
            "ALTER TABLE vault ADD COLUMN created_at TEXT"
        )
        cursor.execute(
            "UPDATE vault SET created_at = datetime('now') WHERE created_at IS NULL"
        )

    conn.commit()
    conn.close()