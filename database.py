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
    user_id INTEGER NOT NULL
)
""")

    conn.commit()
    conn.close()