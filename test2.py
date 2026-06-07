import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
SELECT id, website, site_password
FROM vault
""")

for row in cursor.fetchall():
    print(row)

conn.close()