import os
import secrets
# pyrefly: ignore [missing-import]
from flask import g
from datetime import datetime, timezone
# pyrefly: ignore [missing-import]
from password_generator import generate_password
# pyrefly: ignore [missing-import]
from db import get_db
# pyrefly: ignore [missing-import]
from crypto_utils import encrypt_password
# pyrefly: ignore [missing-import]
from crypto_utils import decrypt_password
# pyrefly: ignore [missing-import]
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash,
    Response
)
# pyrefly: ignore [missing-import]
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
# pyrefly: ignore [missing-import]
import pyotp
import qrcode
import qrcode.image.svg
import io
import base64
import csv
import json
import urllib.parse

from database import init_db
from hibp import check_pwned

# Import security modules
# pyrefly: ignore [missing-import]
# pyrefly: ignore [missing-import]
from flask_limiter import Limiter
# pyrefly: ignore [missing-import]
from flask_limiter.util import get_remote_address
# pyrefly: ignore [missing-import]
from flask_limiter.errors import RateLimitExceeded
# pyrefly: ignore [missing-import]
from pydantic import ValidationError
# pyrefly: ignore [missing-import]
import nh3
from schemas import (
    UserRegisterSchema,
    UserLoginSchema,
    VaultItemSchema,
    EmailUpdateSchema,
    MasterPasswordSchema
)

# Import Authlib for Google Authentication
# pyrefly: ignore [missing-import]
from authlib.integrations.flask_client import OAuth

init_db()
app = Flask(__name__)

# Load environment variables
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
load_dotenv()

app.secret_key = os.getenv("SECRET_KEY")

# Session cookie security settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1")

# Maximum file upload limit (2MB) for vault import
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# Initialize rate limiter (60 requests per minute default)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    storage_uri="memory://"
)

# Initialize OAuth registry
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url=os.getenv('GOOGLE_DISCOVERY_URL', 'https://accounts.google.com/.well-known/openid-configuration'),
    client_kwargs={
        'scope': 'openid email profile'
    }
)

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    if request.path.startswith("/api/"):
        return {"error": "Too many requests. Please try again later."}, 429
    flash("❌ Too many requests. Please try again later.", "error")
    return redirect(request.referrer or "/")

@app.errorhandler(400)
def handle_bad_request(e):
    return render_template("400.html"), 400

@app.errorhandler(404)
def handle_not_found_error(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def handle_internal_server_error(e):
    app.logger.error(f"Internal Server Error: {str(e)}")
    return render_template("500.html"), 500

@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers.pop("X-Powered-By", None)
    return response
import secrets

def generate_backup_codes():

    codes = []

    for _ in range(8):
        codes.append(
            secrets.token_hex(4).upper()
        )

    return codes

def get_age_status(created_at_str: str) -> dict:
    """
    Given an ISO datetime string from SQLite, return a dict with:
        days        — int, days since the password was added
        status      — 'fresh' | 'warn' | 'critical'
        label       — human-readable age string
    """
    try:
        created = datetime.fromisoformat(created_at_str)
    except (TypeError, ValueError):
        return {"days": 0, "status": "fresh", "label": "Unknown"}

    days = (datetime.now() - created).days

    if days >= 180:
        status = "critical"
    elif days >= 90:
        status = "warn"
    else:
        status = "fresh"

    if days == 0:
        label = "Added today"
    elif days == 1:
        label = "Added yesterday"
    elif days < 30:
        label = f"Added {days}d ago"
    elif days < 365:
        label = f"Added {days // 30}mo ago"
    else:
        label = f"Added {days // 365}yr ago"

    return {"days": days, "status": status, "label": label}


def get_password_score(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1
    return score


def calculate_security_score(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT site_password FROM vault WHERE user_id = %s",
        (user_id,)
    )
    records = cursor.fetchall()
    conn.close()

    weak = 0
    medium = 0
    strong = 0
    password_map = {}

    for record in records:
        password = decrypt_password(record[0])
        if not password:
            continue

        password_map[password] = password_map.get(password, 0) + 1
        score = get_password_score(password)

        if score <= 2:
            weak += 1
        elif score <= 4:
            medium += 1
        else:
            strong += 1

    total = weak + medium + strong

    if total == 0:
        return 100, 0, 0, 0, 0, 0

    reused_passwords = sum(count for count in password_map.values() if count > 1)
    base_score = round((strong * 100 + medium * 70 + weak * 30) / total)
    
    # Scale penalty based on proportion of reused passwords (max 40 point penalty)
    reuse_penalty = min(40, (reused_passwords / max(1, total)) * 100)
    security_score = int(max(0, base_score - reuse_penalty))

    return security_score, total, weak, medium, strong, reused_passwords


def get_recommendations(user_id: int) -> list:
    """
    Analyse every vault password for the given user and return a list of
    specific, prioritised, actionable security recommendation dicts.

    Each dict has:
        priority  — 'high' | 'medium' | 'low'
        icon      — emoji
        title     — short headline
        detail    — explanation (may include a count)
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT site_password, created_at FROM vault WHERE user_id = %s",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()

    # ── Counters ─────────────────────────────────────────────
    too_short   = 0   # < 12 characters
    no_upper    = 0   # no uppercase letter
    no_special  = 0   # no special character
    no_digit    = 0   # no number
    seen        = {}  # password → count (for reuse detection)
    stale_count = 0   # 90–179 days old
    overdue_count = 0 # 180+ days old

    for enc_pw, created_at in rows:
        pw = decrypt_password(enc_pw)
        if not pw:
            continue

        seen[pw] = seen.get(pw, 0) + 1

        if len(pw) < 12:
            too_short += 1
        if not any(c.isupper() for c in pw):
            no_upper += 1
        if not any(not c.isalnum() for c in pw):
            no_special += 1
        if not any(c.isdigit() for c in pw):
            no_digit += 1

        age = get_age_status(created_at)
        if age["status"] == "critical":
            overdue_count += 1
        elif age["status"] == "warn":
            stale_count += 1

    reused = sum(1 for c in seen.values() if c > 1)
    total  = len(rows)

    recs = []

    # ── High priority ─────────────────────────────────────────
    if too_short:
        recs.append({
            "priority": "high",
            "icon": "📏",
            "title": "Use at least 12 characters",
            "detail": f"{too_short} of your password(s) are shorter than 12 characters. "
                      "Longer passwords are exponentially harder to crack.",
        })
    if no_special:
        recs.append({
            "priority": "high",
            "icon": "✱️",
            "title": "Add special characters (!, @, #, $…)",
            "detail": f"{no_special} password(s) contain no special characters. "
                      "Symbols dramatically increase entropy.",
        })
    if reused:
        recs.append({
            "priority": "high",
            "icon": "🔄",
            "title": "Use a unique password for every account",
            "detail": f"{reused} password(s) are reused across multiple sites. "
                      "A single breach exposes all of them.",
        })
    if overdue_count:
        recs.append({
            "priority": "high",
            "icon": "🔴",
            "title": "Update overdue passwords immediately",
            "detail": f"{overdue_count} password(s) are over 180 days old. "
                      "Rotating credentials limits exposure from undetected breaches.",
        })

    # ── Medium priority ─────────────────────────────────────
    if no_upper:
        recs.append({
            "priority": "medium",
            "icon": "🔠",
            "title": "Mix uppercase and lowercase letters",
            "detail": f"{no_upper} password(s) use no uppercase letters. "
                      "Case variation increases the keyspace significantly.",
        })
    if no_digit:
        recs.append({
            "priority": "medium",
            "icon": "🔢",
            "title": "Include numbers in your passwords",
            "detail": f"{no_digit} password(s) contain no digits. "
                      "Adding numbers makes dictionary attacks less effective.",
        })
    if stale_count:
        recs.append({
            "priority": "medium",
            "icon": "⏳",
            "title": "Rotate passwords older than 90 days",
            "detail": f"{stale_count} password(s) are between 90 and 179 days old. "
                      "Regular rotation reduces long-term exposure risk.",
        })

    # ── Low priority (always shown) ──────────────────────────
    recs.append({
        "priority": "low",
        "icon": "🔐",
        "title": "Enable MFA on every important account",
        "detail": "Two-factor authentication stops 99.9% of automated attacks "
                  "even if your password is compromised.",
    })
    if total > 0:
        recs.append({
            "priority": "low",
            "icon": "⭐",
            "title": "Use the built-in password generator",
            "detail": "The generator creates cryptographically random 16-character "
                      "passwords that are near-impossible to brute-force.",
        })

    return recs


@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def login():
    if "user_id" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username_raw = request.form.get("username", "")
        password_raw = request.form.get("password", "")

        try:
            # Enforce schema validation and input sanitization
            data = UserLoginSchema(
                username=nh3.clean(username_raw).strip(),
                password=password_raw
            )
        except ValidationError as e:
            flash(f"❌ {e.errors()[0]['msg']}", "error")
            return redirect("/")

        username = data.username
        password = data.password

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, username, password_hash, two_factor_enabled FROM users WHERE username = %s",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            if user[3] == 1:
                session["pre_2fa_user_id"] = user[0]
                session["pre_2fa_username"] = user[1]
                return redirect("/login-2fa")
            else:
                session["user_id"] = user[0]
                session["username"] = user[1]
                return redirect("/dashboard")

        flash("❌ Invalid username or password.", "error")
        return redirect("/")

    # GET request
    return render_template("login.html")

@app.route('/auth/login/google')
def login_google():
    redirect_uri = url_for('auth_google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback/google')
def auth_google_callback():
    try:
        token = google.authorize_access_token()
    except Exception as e:
        flash("❌ Google authentication failed.", "error")
        return redirect("/")

    userinfo = token.get('userinfo')
    if not userinfo:
        flash("❌ Failed to retrieve user information from Google.", "error")
        return redirect("/")

    google_id = userinfo.get('sub')
    email = userinfo.get('email')
    name = userinfo.get('name') or userinfo.get('given_name') or "Google User"

    if not google_id or not email:
        flash("❌ Google did not provide necessary user identifiers.", "error")
        return redirect("/")

    # Look up user in DB
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, two_factor_enabled FROM users WHERE google_id = %s", (google_id,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        if user[2] == 1:
            session["pre_2fa_user_id"] = user[0]
            session["pre_2fa_username"] = user[1]
            conn.close()
            return redirect("/login-2fa")
        else:
            session["user_id"] = user[0]
            session["username"] = user[1]
            conn.close()
            return redirect("/dashboard")
    else:
        # Check if email already exists
        cursor.execute("SELECT id, username, google_id FROM users WHERE email = %s", (email,))
        existing_email_user = cursor.fetchone()
        if existing_email_user:
            # Link google account to existing user
            cursor.execute("UPDATE users SET google_id = %s WHERE id = %s", (google_id, existing_email_user[0]))
            conn.commit()
            session["user_id"] = existing_email_user[0]
            session["username"] = existing_email_user[1]
            conn.close()
            flash("✅ Linked your Google account to your existing profile.", "success")
            return redirect("/dashboard")
        else:
            # Register a new user
            base_username = nh3.clean(name).strip().replace(" ", "_").lower()
            if not base_username:
                base_username = "google_user"
            
            # Check if username is taken
            cursor.execute("SELECT id FROM users WHERE username = %s", (base_username,))
            if cursor.fetchone():
                import random
                base_username = f"{base_username}_{random.randint(1000, 9999)}"

            placeholder_hash = "google-oauth-only-user-" + secrets.token_hex(16)
            
            try:
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, email, google_id)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, username
                    """,
                    (base_username, placeholder_hash, email, google_id)
                )
                new_user = cursor.fetchone()
                conn.commit()
                
                session["user_id"] = new_user[0]
                session["username"] = new_user[1]
                conn.close()
                flash("✅ Welcome! Registered successfully with Google.", "success")
                return redirect("/dashboard")
            except Exception as e:
                conn.close()
                flash("❌ Registration failed during account creation.", "error")
                return redirect("/")
@app.route("/backup-codes")
def backup_codes():

    if "user_id" not in session:
        return redirect("/")

    codes = session.get("backup_codes")

    if not codes:

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT backup_codes
            FROM users
            WHERE id = %s
            """,
            (session["user_id"],)
        )

        row = cursor.fetchone()

        conn.close()

        if row and row[0]:
            codes = row[0].split(",")
        else:
            codes = []

    return render_template(
        "backup_codes.html",
        codes=codes
    )
@app.teardown_appcontext
def close_db(error=None):

    db = g.pop("db", None)

    if db is not None:
        db.close()
@app.route("/login-2fa", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def login_2fa():
    if "pre_2fa_user_id" not in session:
        return redirect("/")

    if request.method == "POST":
        token = request.form.get("token", "").strip().replace(" ", "")
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT two_factor_secret FROM users WHERE id = %s",
            (session["pre_2fa_user_id"],)
        )
        row = cursor.fetchone()
        conn.close()

        if row and row[0]:
            totp = pyotp.TOTP(row[0])
            if totp.verify(token, valid_window=1):
                session["user_id"] = session["pre_2fa_user_id"]
                session["username"] = session["pre_2fa_username"]
                session.pop("pre_2fa_user_id", None)
                session.pop("pre_2fa_username", None)
                return redirect("/dashboard")

        flash("❌ Invalid 2FA code.", "error")
        return redirect("/login-2fa")

    return render_template("login_2fa.html")
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def register():
    if "user_id" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username_raw = request.form.get("username", "")
        password_raw = request.form.get("password", "")

        try:
            data = UserRegisterSchema(
                username=nh3.clean(username_raw).strip(),
                password=password_raw
            )
        except ValidationError as e:
            flash(f"❌ {e.errors()[0]['msg']}", "error")
            return redirect("/register")

        username = data.username
        password = data.password
        password_hash = generate_password_hash(password)

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO users
                (username, password_hash)
                VALUES (%s, %s)
                """,
                (username, password_hash)
            )

            conn.commit()
            conn.close()

            return redirect("/")

        except Exception:
            conn.close()
            flash("❌ That username is already taken. Please choose another.", "error")
            return redirect("/register")

    return render_template("register.html")
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()
    search = request.args.get("search", "")
    strength_filter = request.args.get("strength", "")
    filter_type = request.args.get("filter", "")

    if search:
        cursor.execute(
            """
            SELECT id, website, site_username, created_at, site_password
            FROM vault
            WHERE user_id = %s AND website LIKE %s
            """,
            (session["user_id"], f"%{search}%")
        )
    else:
        cursor.execute(
            """
            SELECT id, website, site_username, created_at, site_password
            FROM vault
            WHERE user_id = %s
            """,
            (session["user_id"],)
        )

    rows = cursor.fetchall()
    conn.close()

    password_map = {}
    decrypted_map = {}
    for row in rows:
        pw = decrypt_password(row[4])
        decrypted_map[row[0]] = pw
        if pw:
            password_map[pw] = password_map.get(pw, 0) + 1

    passwords = []
    for row in rows:
        pw = decrypted_map[row[0]]
        score = get_password_score(pw) if pw else 0
        
        pw_strength = "weak"
        if score > 4:
            pw_strength = "strong"
        elif score > 2:
            pw_strength = "medium"
            
        if strength_filter and strength_filter != pw_strength:
            continue
            
        age_info = get_age_status(row[3])
        
        if filter_type == "reused" and password_map.get(pw, 0) <= 1:
            continue
        if filter_type == "stale" and age_info["status"] != "warn":
            continue
        if filter_type == "overdue" and age_info["status"] != "critical":
            continue
            
        passwords.append({
            "id":         row[0],
            "website":    row[1],
            "username":   row[2],
            "age":        age_info,
            "strength":   pw_strength
        })

    security_score, _, _, _, _, _ = calculate_security_score(session["user_id"])

    return render_template(
        "dashboard.html",
        passwords=passwords,
        security_score=security_score
    )


@app.route("/view-password/<int:id>")
def view_password(id):
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT website, site_username, site_password
        FROM vault WHERE id = %s AND user_id = %s
        """,
        (id, session["user_id"])
    )
    record = cursor.fetchone()
    cursor.execute("SELECT strict_mode FROM users WHERE id = %s", (session["user_id"],))
    user_row = cursor.fetchone()
    strict_mode = bool(user_row[0]) if user_row else False
    
    conn.close()

    if not record:
        return "Password not found"

    if strict_mode:
        decrypted_password = "***HIDDEN***"
    else:
        decrypted_password = decrypt_password(record[2])

    return render_template(
        "view_password.html",
        website=record[0],
        username=record[1],
        password=decrypted_password,
        strict_mode=strict_mode,
        vault_id=id
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/generate-password")
def generate_new_password():
    if "user_id" not in session:
        return redirect("/")
    return render_template("generate_password.html")


@app.route("/security-center")
def security_center():
    if "user_id" not in session:
        return redirect("/")

    security_score, total, weak, medium, strong, reused_passwords = calculate_security_score(
        session["user_id"]
    )

    # ── Age / expiry counts ──────────────────────────────────
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT created_at FROM vault WHERE user_id = %s",
        (session["user_id"],)
    )
    age_rows = cursor.fetchall()
    conn.close()

    stale    = sum(1 for r in age_rows if get_age_status(r[0])["status"] == "warn")
    overdue  = sum(1 for r in age_rows if get_age_status(r[0])["status"] == "critical")

    recommendations = get_recommendations(session["user_id"])

    return render_template(
        "security_center.html",
        total=total,
        weak=weak,
        medium=medium,
        strong=strong,
        reused_passwords=reused_passwords,
        security_score=security_score,
        stale=stale,
        overdue=overdue,
        recommendations=recommendations,
    )


@app.route("/delete-password/<int:id>")
def delete_password(id):
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM vault WHERE id = %s AND user_id = %s",
        (id, session["user_id"])
    )
    conn.commit()
    conn.close()

    flash("✅ Password deleted.", "success")
    return redirect("/dashboard")

@app.route("/bulk-delete", methods=["POST"])
def bulk_delete():
    if "user_id" not in session:
        return redirect("/")
        
    password_ids = request.form.getlist("password_ids")
    if not password_ids:
        flash("⚠️ No passwords selected.", "warning")
        return redirect("/dashboard")
        
    conn = get_db()
    cursor = conn.cursor()
    
    # Securely delete multiple IDs using PostgreSQL placeholders
    placeholders = ",".join(["%s"] * len(password_ids))
    params = password_ids + [session["user_id"]]
    cursor.execute(f"DELETE FROM vault WHERE id IN ({placeholders}) AND user_id = %s", params)
    
    conn.commit()
    conn.close()
    
    flash(f"✅ Successfully deleted {len(password_ids)} password(s).", "success")
    return redirect(request.referrer or "/dashboard")


@app.route("/edit-password/<int:id>", methods=["GET", "POST"])
def edit_password(id):
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()

    # Enforce database ownership check
    cursor.execute(
        "SELECT website, site_username FROM vault WHERE id = %s AND user_id = %s",
        (id, session["user_id"])
    )
    record = cursor.fetchone()
    if not record:
        conn.close()
        flash("❌ Password not found or unauthorized.", "error")
        return redirect("/dashboard")

    if request.method == "POST":
        website_raw = request.form.get("website", "")
        site_username_raw = request.form.get("site_username", "")
        site_password_raw = request.form.get("site_password", "")

        try:
            data = VaultItemSchema(
                website=nh3.clean(website_raw).strip(),
                site_username=nh3.clean(site_username_raw).strip(),
                site_password=site_password_raw
            )
        except ValidationError as e:
            conn.close()
            flash(f"❌ {e.errors()[0]['msg']}", "error")
            return redirect(url_for("edit_password", id=id))

        website = data.website
        site_username = data.site_username
        site_password = data.site_password
        last_updated = datetime.now().strftime("%Y-%m-%d")
        encrypted_password = encrypt_password(site_password)

        cursor.execute(
            """
            UPDATE vault
            SET website = %s,
                site_username = %s,
                site_password = %s,
                last_updated = %s
            WHERE id = %s AND user_id = %s
            """,
            (website, site_username, encrypted_password, id, session["user_id"])
        )
        conn.commit()
        conn.close()
        flash("✅ Password updated successfully!", "success")
        return redirect("/dashboard")

    conn.close()
    return render_template("edit_password.html", record=record)


@app.route("/add-password", methods=["GET", "POST"])
def add_password():
    if "user_id" not in session:
        return redirect("/")

    if request.method == "POST":
        website_raw = request.form.get("website", "")
        site_username_raw = request.form.get("site_username", "")
        site_password_raw = request.form.get("site_password", "")

        try:
            data = VaultItemSchema(
                website=nh3.clean(website_raw).strip(),
                site_username=nh3.clean(site_username_raw).strip(),
                site_password=site_password_raw
            )
        except ValidationError as e:
            flash(f"❌ {e.errors()[0]['msg']}", "error")
            return redirect("/add-password")

        website = data.website
        site_username = data.site_username
        site_password = data.site_password
        last_updated = datetime.now().strftime("%Y-%m-%d")
        encrypted_password = encrypt_password(site_password)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO vault
            (
                website,
                site_username,
                site_password,
                user_id,
                last_updated
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                website,
                site_username,
                encrypted_password,
                session["user_id"],
                last_updated
            )
        )
        conn.commit()
        conn.close()

        # ── HIBP breach check ───────────────────────────────
        breach_count = check_pwned(site_password)

        if breach_count == -1:
            flash("✅ Password added — breach check unavailable (HIBP API unreachable).", "success")
        elif breach_count == 0:
            flash("✅ Password added — no known breaches found! 🛡️", "success")
        else:
            flash(
                f"✅ Password saved, but ⚠️ WARNING: this password appeared in "
                f"{breach_count:,} known data breaches. Consider using a stronger password!",
                "warning"
            )

        return redirect("/dashboard")

    return render_template("add_password.html")


@app.route("/profile", methods=["GET"])
def profile():
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()

    # GET — fetch user info and stats
    cursor.execute(
        "SELECT username, email, created_at FROM users WHERE id = %s",
        (session["user_id"],)
    )
    user = cursor.fetchone()
    print("USER =", user)
    conn.close()

    password_count, _, _, _, _, _ = calculate_security_score(session["user_id"])
    security_score = password_count  # reuse for count; recalculate score below
    security_score, total, _, _, _, _ = calculate_security_score(session["user_id"])

    # Format joined date
    joined_label = "Unknown"
    if user[2]:
        try:
            joined_label = user[2].strftime("%B %Y")
        except Exception:
            pass

    return render_template(
        "profile.html",
        username=user[0],
        email=user[1] or "",
        joined=joined_label,
        password_count=total,
        security_score=security_score,
    )
@app.route("/account-settings", methods=["GET", "POST"])
def account_settings():
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":
        email_raw = request.form.get("email", "")

        try:
            data = EmailUpdateSchema(
                email=nh3.clean(email_raw).strip()
            )
        except ValidationError as e:
            conn.close()
            flash(f"❌ {e.errors()[0]['msg']}", "error")
            return redirect("/account-settings")

        email = data.email
        cursor.execute(
            "UPDATE users SET email = %s WHERE id = %s",
            (email, session["user_id"])
        )
        conn.commit()
        conn.close()
        flash("✅ Email updated successfully!", "success")
        return redirect("/account-settings")

    cursor.execute(
        "SELECT email, password_hash FROM users WHERE id = %s",
        (session["user_id"],)
    )
    row = cursor.fetchone()
    email = row[0] if row and row[0] else ""
    password_hash = row[1] if row and row[1] else ""
    is_oauth_only = password_hash.startswith("google-oauth-only-user-")
    
    # We still need the password count for the Danger Zone message
    _, total, _, _, _, _ = calculate_security_score(session["user_id"])
    conn.close()

    return render_template("account_settings.html", email=email, password_count=total, is_oauth_only=is_oauth_only)

@app.before_request
def check_auto_logout():

    if "user_id" not in session:
        return

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
    """
    SELECT auto_logout
    FROM users
    WHERE id = %s
    """,
    (session["user_id"],)
)

    result = cursor.fetchone()

    timeout = result[0] if result else 30

    conn.close()

    if timeout == 0:
        return

    now = datetime.now().timestamp()

    last_activity = session.get(
        "last_activity",
        now
    )

    if now - last_activity > timeout * 60:
        session.clear()
        return redirect("/")

    session["last_activity"] = now
@app.route("/security-settings", methods=["GET"])
def security_settings():

    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
    """
    SELECT
        two_factor_enabled,
        strict_mode,
        login_alerts,
        theme,
        auto_logout
    FROM users
    WHERE id = %s
    """,
    (session["user_id"],)
)

    row = cursor.fetchone()

    two_factor_enabled = bool(row[0])
    strict_mode = bool(row[1])
    login_alerts = bool(row[2])
    auto_logout = row[3]
    theme = row[3]

    return render_template(
    "security_settings.html",
    two_factor_enabled=two_factor_enabled,
    strict_mode=strict_mode,
    login_alerts=login_alerts,
    auto_logout=auto_logout
)
@app.route("/update-theme", methods=["POST"])
def update_theme():

    if "user_id" not in session:
        return {"success": False}

    theme = request.json.get("theme")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET theme = %s
        WHERE id = %s
        """,
        (theme, session["user_id"])
    )

    conn.commit()
    conn.close()

    return {"success": True}
@app.context_processor
def inject_theme():

    if "user_id" not in session:
        return {"theme": "dark"}

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
    """
    SELECT theme
    FROM users
    WHERE id = %s
    """,
    (session["user_id"],)
)

    row = cursor.fetchone()

    conn.close()

    return {
        "theme": row[0] if row else "dark"
    }
@app.route("/update-auto-logout", methods=["POST"])
def update_auto_logout():

    if "user_id" not in session:
        return {"success": False}

    minutes = request.json.get("minutes")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET auto_logout = %s
        WHERE id = %s
        """,
        (minutes, session["user_id"])
    )

    conn.commit()
    conn.close()

    return {"success": True}
@app.before_request
def check_session_timeout():

    if "user_id" not in session:
        return

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT auto_logout
        FROM users
        WHERE id = %s
        """,
        (session["user_id"],)
    )

    result = cursor.fetchone()

    conn.close()

    timeout = result[0] if result else 30

    print("TIMEOUT =", timeout)

    if timeout == 0:
        return

    now = datetime.now().timestamp()

    last_activity = session.get(
        "last_activity",
        now
    )

    print("NOW =", now)
    print("LAST =", last_activity)
    print("DIFF =", now - last_activity)

    if now - last_activity > timeout * 60:
        print("LOGGING OUT")
        session.clear()
        return redirect("/")

    session["last_activity"] = now
@app.route("/update-security-settings", methods=["POST"])
def update_security_settings():
    if "user_id" not in session:
        return redirect("/")
    
    setting = request.form.get("setting")
    value = request.form.get("value")
    
    conn = get_db()
    cursor = conn.cursor()
    
    if setting == "strict_mode":
        if value == "true":
            # Enforce that OAuth-only users must set a master password before enabling strict mode
            cursor.execute("SELECT password_hash FROM users WHERE id = %s", (session["user_id"],))
            row = cursor.fetchone()
            if row and row[0].startswith("google-oauth-only-user-"):
                conn.close()
                return "Cannot enable Strict Mode without setting a Master Password first. Please configure one in Account Settings.", 400
        cursor.execute("UPDATE users SET strict_mode = %s WHERE id = %s", (1 if value == "true" else 0, session["user_id"]))
    elif setting == "login_alerts":
        cursor.execute("UPDATE users SET login_alerts = %s WHERE id = %s", (1 if value == "true" else 0, session["user_id"]))
    elif setting == "disable_2fa":
        cursor.execute("UPDATE users SET two_factor_enabled = 0, two_factor_secret = '' WHERE id = %s", (session["user_id"],))
        flash("✅ Two-Factor Authentication disabled.", "success")
        
    conn.commit()
    conn.close()
    
    return "OK", 200


@app.route("/setup-2fa", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def setup_2fa():

    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT email, two_factor_enabled
        FROM users
        WHERE id = %s
        """,
        (session["user_id"],)
    )

    user_row = cursor.fetchone()

    email = user_row[0] if user_row else "user@passify.local"

    if user_row and user_row[1] == 1:
        conn.close()
        flash("⚠️ 2FA is already enabled.", "warning")
        return redirect("/security-settings")

    if request.method == "POST":

        token = request.form.get(
            "token",
            ""
        ).strip().replace(" ", "")

        secret = session.get("temp_2fa_secret")

        if not secret:
            secret = pyotp.random_base32()
            session["temp_2fa_secret"] = secret

        totp = pyotp.TOTP(secret)

        if totp.verify(token, valid_window=1):

            backup_codes = generate_backup_codes()

            cursor.execute(
                """
                UPDATE users
                SET
                    two_factor_enabled = 1,
                    two_factor_secret = %s,
                    backup_codes = %s
                WHERE id = %s
                """,
                (
                    secret,
                    ",".join(backup_codes),
                    session["user_id"]
                )
            )

            conn.commit()
            conn.close()

            session["backup_codes"] = backup_codes
            session.pop("temp_2fa_secret", None)

            flash(
                "✅ Two-Factor Authentication successfully enabled!",
                "success"
            )

            return redirect("/backup-codes")

        conn.close()

        flash(
            "❌ Invalid code. Try again.",
            "error"
        )

        return redirect("/setup-2fa")

    # GET REQUEST

    secret = session.get("temp_2fa_secret")

    if not secret:
        secret = pyotp.random_base32()
        session["temp_2fa_secret"] = secret

    totp_uri = pyotp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name="Passify"
    )

    img = qrcode.make(totp_uri)

    stream = io.BytesIO()
    img.save(stream, format="PNG")

    qr_b64 = (
        "data:image/png;base64,"
        + base64.b64encode(
            stream.getvalue()
        ).decode("utf-8")
    )

    conn.close()

    return render_template(
        "setup_2fa.html",
        qr_b64=qr_b64,
        secret=secret
    )


@app.route("/api/unlock-password/<int:vault_id>", methods=["POST"])
@limiter.limit("10 per minute")
def unlock_password(vault_id):
    if "user_id" not in session:
        return "Unauthorized", 401
        
    master_password_raw = request.form.get("master_password", "")

    try:
        data = MasterPasswordSchema(master_password=master_password_raw)
    except ValidationError as e:
        return f"Invalid Input: {e.errors()[0]['msg']}", 400
        
    master_password = data.master_password
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT password_hash FROM users WHERE id = %s", (session["user_id"],))
    user_row = cursor.fetchone()
    if not user_row or not check_password_hash(user_row[0], master_password):
        conn.close()
        return "Incorrect Master Password", 403
        
    cursor.execute("SELECT site_password FROM vault WHERE id = %s AND user_id = %s", (vault_id, session["user_id"]))
    vault_row = cursor.fetchone()
    conn.close()
    
    if not vault_row:
        return "Not found", 404
        
    decrypted = decrypt_password(vault_row[0])
    return decrypted, 200


@app.route("/change-password", methods=["POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def change_password():
    if "user_id" not in session:
        return redirect("/")

    # Fetch current hash
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash FROM users WHERE id = %s",
        (session["user_id"],)
    )
    row = cursor.fetchone()
    current_hash = row[0] if row else ""
    is_oauth_only = current_hash.startswith("google-oauth-only-user-")

    current_raw = request.form.get("current_password", "")
    new_pw_raw  = request.form.get("new_password", "")
    confirm_raw = request.form.get("confirm_password", "")

    try:
        if not is_oauth_only:
            current_data = MasterPasswordSchema(master_password=current_raw)
            current = current_data.master_password
        else:
            current = ""
            
        new_data = UserRegisterSchema(username="dummy", password=new_pw_raw)
        confirm_data = MasterPasswordSchema(master_password=confirm_raw)
    except ValidationError as e:
        conn.close()
        flash(f"❌ {e.errors()[0]['msg']}", "error")
        return redirect("/account-settings")

    new_pw = new_data.password
    confirm = confirm_data.master_password

    if not is_oauth_only:
        if not check_password_hash(current_hash, current):
            conn.close()
            flash("❌ Current password is incorrect.", "error")
            return redirect("/account-settings")

    if new_pw != confirm:
        conn.close()
        flash("❌ New passwords do not match.", "error")
        return redirect("/account-settings")

    if not is_oauth_only and check_password_hash(current_hash, new_pw):
        conn.close()
        flash("❌ New password must differ from your current password.", "error")
        return redirect("/account-settings")

    new_hash = generate_password_hash(new_pw)
    cursor.execute(
        "UPDATE users SET password_hash = %s WHERE id = %s",
        (new_hash, session["user_id"])
    )
    conn.commit()
    conn.close()

    flash("✅ Password changed successfully!", "success")
    return redirect("/account-settings")


@app.route("/delete-account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return redirect("/")

    confirm_text = request.form.get("confirm_text", "").strip()

    if confirm_text != "DELETE":
        flash("❌ You must type DELETE exactly to confirm account deletion.", "error")
        return redirect("/account-settings")

    user_id = session["user_id"]

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()

    session.clear()
    flash("Your account has been permanently deleted.", "success")
    return redirect("/")


@app.route("/export-vault")
def export_vault():
    if "user_id" not in session:
        return redirect("/")
        
    fmt = request.args.get("format", "csv")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT website, site_username, site_password FROM vault WHERE user_id = %s", (session["user_id"],))
    rows = cursor.fetchall()
    conn.close()
    
    records = []
    for row in rows:
        records.append({
            "website": row[0],
            "username": row[1],
            "password": decrypt_password(row[2])
        })
        
    if fmt == "json":
        json_data = json.dumps(records, indent=4)
        return Response(
            json_data,
            mimetype="application/json",
            headers={"Content-disposition": "attachment; filename=passify_vault.json"}
        )
    else:
        # Default to CSV
        si = io.StringIO()
        cw = csv.DictWriter(si, fieldnames=["website", "username", "password"])
        cw.writeheader()
        cw.writerows(records)
        return Response(
            si.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=passify_vault.csv"}
        )

@app.route("/import-vault", methods=["POST"])
@limiter.limit("5 per minute", methods=["POST"])
def import_vault():
    if "user_id" not in session:
        return redirect("/")
        
    if "import_file" not in request.files:
        flash("❌ No file uploaded.", "error")
        return redirect("/account-settings")
        
    file = request.files["import_file"]
    if file.filename == "":
        flash("❌ No file selected.", "error")
        return redirect("/account-settings")
        
    # Validate extension and content type (MIME) server-side
    if not (file.filename.endswith(".json") or file.filename.endswith(".csv")):
        flash("❌ Invalid file format. Only .json and .csv files are allowed.", "error")
        return redirect("/account-settings")
        
    mime_type = file.mimetype
    if mime_type not in ["application/json", "text/csv", "application/vnd.ms-excel", "text/plain"]:
        flash("❌ Invalid file type. Only JSON and CSV files are allowed.", "error")
        return redirect("/account-settings")

    try:
        content = file.read().decode("utf-8")
    except Exception:
        flash("❌ Failed to decode file. Make sure it is encoded in UTF-8.", "error")
        return redirect("/account-settings")
        
    records = []
    
    def clean_website(url_str):
        if not url_str:
            return ""
        if "://" in url_str:
            parsed = urllib.parse.urlparse(url_str)
            domain = parsed.netloc or parsed.path
            return domain.replace("www.", "")
        return url_str

    try:
        if file.filename.endswith(".json"):
            data = json.loads(content)
            for item in data:
                website_raw = item.get("website") or item.get("url") or item.get("uri") or item.get("name") or ""
                username_raw = item.get("username") or item.get("login") or item.get("login_username") or ""
                password_raw = item.get("password") or item.get("login_password") or ""
                
                # Sanitize using nh3
                website = nh3.clean(website_raw).strip()
                username = nh3.clean(username_raw).strip()
                password = password_raw
                
                records.append({
                    "website": clean_website(website),
                    "username": username,
                    "password": password
                })
        else:
            # Assume CSV
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                # Lowercase all keys for easier matching
                row_lower = {k.lower().strip() if k else "": v for k, v in row.items()}
                website_raw = row_lower.get("website") or row_lower.get("url") or row_lower.get("uri") or row_lower.get("name") or ""
                username_raw = row_lower.get("username") or row_lower.get("login") or row_lower.get("login_username") or ""
                password_raw = row_lower.get("password") or row_lower.get("login_password") or ""
                
                # Sanitize using nh3
                website = nh3.clean(website_raw).strip()
                username = nh3.clean(username_raw).strip()
                password = password_raw
                
                records.append({
                    "website": clean_website(website),
                    "username": username,
                    "password": password
                })
                
        conn = get_db()
        cursor = conn.cursor()
        
        imported_count = 0
        for rec in records:
            if rec["website"] and rec["password"]:
                # Basic Pydantic schema validation check per record
                try:
                    data = VaultItemSchema(
                        website=rec["website"],
                        site_username=rec["username"],
                        site_password=rec["password"]
                    )
                except ValidationError:
                    continue
                    
                encrypted = encrypt_password(data.site_password)
                cursor.execute(
                    "INSERT INTO vault (website, site_username, site_password, user_id) VALUES (%s, %s, %s, %s)",
                    (data.website, data.site_username, encrypted, session["user_id"])
                )
                imported_count += 1
                
        conn.commit()
        conn.close()
        
        flash(f"✅ Successfully imported {imported_count} passwords!", "success")
        
    except Exception as e:
        flash(f"❌ Failed to parse file: {str(e)}", "error")
        
    return redirect("/account-settings")

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1"))
