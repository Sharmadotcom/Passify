import sqlite3
conn = sqlite3.connect(r"C:\Study\Projects\password-manager\database.db")
cursor = conn.cursor()
cursor.execute("DELETE FROM vault")
conn.commit()
conn.close()
print("Done")