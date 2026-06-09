from db import get_db

conn = get_db()

cursor = conn.cursor()

cursor.execute("SELECT version();")

print(cursor.fetchone())

conn.close()