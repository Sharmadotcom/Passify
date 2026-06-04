import sqlite3
import os
print(os.path.abspath("database.db"))
conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
SELECT COUNT(*)
FROM vault
""")

print(cursor.fetchone())

cursor.execute("""
SELECT id, website, site_username
FROM vault
""")

rows = cursor.fetchall()

print(rows)

conn.close()