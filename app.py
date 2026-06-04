import os
print(os.path.abspath("database.db"))
from password_generator import generate_password
from crypto_utils import encrypt_password
from crypto_utils import decrypt_password
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for
)
import sqlite3
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from database import init_db

init_db()
app = Flask(__name__)
app = Flask(__name__)

app.secret_key = "super-secret-key"
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        if user:

            stored_hash = user[2]

            if check_password_hash(
                stored_hash,
                password
            ):

                session["user_id"] = user[0]
                session["username"] = user[1]

                return redirect("/dashboard")

        return "Invalid Username or Password"

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        try:

            cursor.execute(
                """
                INSERT INTO users
                (username, password_hash)
                VALUES (?, ?)
                """,
                (username, password_hash)
            )

            conn.commit()
            conn.close()

            return "User Registered Successfully"

        except sqlite3.IntegrityError:

            conn.close()
            return "User Already Exists"

    return render_template("register.html")

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    search = request.args.get("search", "")

    if search:

        cursor.execute(
            """
            SELECT id,
                   website,
                   site_username
            FROM vault
            WHERE user_id = ?
            AND website LIKE ?
            """,
            (
                session["user_id"],
                f"%{search}%"
            )
        )

    else:

        cursor.execute(
            """
            SELECT id,
                   website,
                   site_username
            FROM vault
            WHERE user_id = ?
            """,
            (session["user_id"],)
        )

    passwords = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        passwords=passwords
    )
@app.route("/view-password/<int:id>")
def view_password(id):

    if "user_id" not in session:
        return redirect("/")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT website,
               site_username,
               site_password
        FROM vault
        WHERE id = ?
        AND user_id = ?
        """,
        (
            id,
            session["user_id"]
        )
    )

    record = cursor.fetchone()

    conn.close()

    if not record:
        return "Password not found"

    decrypted_password = decrypt_password(record[2])

    return render_template(
    "view_password.html",
    website=record[0],
    username=record[1],
    password=decrypted_password
)
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")

@app.route("/generate-password")
def generate_new_password():

    if "user_id" not in session:
        return redirect("/")

    return render_template(
        "generate_password.html"
    )


@app.route("/delete-password/<int:id>")
def delete_password(id):

    if "user_id" not in session:
        return redirect("/")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM vault
        WHERE id = ?
        AND user_id = ?
        """,
        (id, session["user_id"])
    )

    conn.commit()
    conn.close()

    return redirect("/dashboard")
@app.route("/edit-password/<int:id>", methods=["GET", "POST"])
def edit_password(id):

    if "user_id" not in session:
        return redirect("/")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    if request.method == "POST":

        website = request.form["website"]
        site_username = request.form["site_username"]
        site_password = request.form["site_password"]

        encrypted_password = encrypt_password(
            site_password
        )

        cursor.execute(
            """
            UPDATE vault
            SET website = ?,
                site_username = ?,
                site_password = ?
            WHERE id = ?
            AND user_id = ?
            """,
            (
                website,
                site_username,
                encrypted_password,
                id,
                session["user_id"]
            )
        )

        conn.commit()
        conn.close()

        return redirect("/dashboard")

    cursor.execute(
        """
        SELECT website,
               site_username
        FROM vault
        WHERE id = ?
        AND user_id = ?
        """,
        (
            id,
            session["user_id"]
        )
    )

    record = cursor.fetchone()

    conn.close()

    return render_template(
        "edit_password.html",
        record=record
    )
@app.route("/add-password", methods=["GET", "POST"])
def add_password():

    if "user_id" not in session:
        return redirect("/")

    if request.method == "POST":

        website = request.form["website"]
        site_username = request.form["site_username"]
        site_password = request.form["site_password"]
        encrypted_password = encrypt_password(site_password)
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        print("ADDING PASSWORD")
        print(website)
        print(site_username)
        print(encrypted_password)
        print(session["user_id"])
        cursor.execute(
            
            """
            INSERT INTO vault
            (website, site_username, site_password, user_id)
            VALUES (?, ?, ?, ?)
            """,
            (
                website,
                site_username,
                encrypted_password,
                session["user_id"]
            )
        )

        conn.commit()
        conn.close()

        return redirect("/dashboard")
    return render_template("add_password.html")

if __name__ == "__main__":
    app.run(debug=True)
    
    