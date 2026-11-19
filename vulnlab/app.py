"""
VulnLab - Intentionally Vulnerable Practice Web Application
=============================================================
FOR LOCAL SECURITY TESTING / EDUCATIONAL USE ONLY.
Do NOT deploy this on a public server or real network.

This app deliberately contains classic OWASP Top 10 style flaws so it can be
used as a safe, legal target for the companion WebVAPT scanner:

  - SQL Injection            (login form, search form)
  - Reflected XSS            (search results, comment box)
  - Broken/weak Authentication (default creds, no lockout, plaintext passwords)
  - CSRF                     (profile update form, no token)
  - IDOR                     (profile page accessible by changing ?id=)
  - Security Misconfiguration (debug mode, missing security headers,
                                verbose error messages, server banner)
"""

from flask import Flask, request, render_template, redirect, session, g, make_response
import sqlite3
import os

APP_DB = os.path.join(os.path.dirname(__file__), "vulnlab.db")

app = Flask(__name__)
app.secret_key = "dev"          # weak, hardcoded secret key (intentional flaw)
app.config["DEBUG"] = True      # verbose stack traces on error (intentional flaw)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(APP_DB)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if os.path.exists(APP_DB):
        os.remove(APP_DB)
    conn = sqlite3.connect(APP_DB)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT,
        bio TEXT
    )""")
    # plaintext passwords stored on purpose (intentional flaw)
    cur.executemany(
        "INSERT INTO users (username, password, email, bio) VALUES (?,?,?,?)",
        [
            ("admin", "admin123", "admin@vulnlab.local", "Site administrator."),
            ("rahul", "password1", "rahul@vulnlab.local", "CS student, loves cricket."),
            ("priya", "priya@2024", "priya@vulnlab.local", "Digital forensics enthusiast."),
        ],
    )
    cur.execute("""CREATE TABLE comments (
        id INTEGER PRIMARY KEY,
        author TEXT,
        content TEXT
    )""")
    conn.commit()
    conn.close()


# NOTE: no security headers are set anywhere in this app (intentional flaw)
# missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
#          Strict-Transport-Security, and cookies lack HttpOnly/Secure flags.


@app.route("/")
def home():
    return render_template("home.html", user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # --- INTENTIONAL VULNERABILITY: classic SQL Injection ---
        # user input is concatenated directly into the SQL string
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
        except sqlite3.Error as e:
            # verbose DB error exposed to the client (intentional flaw)
            return f"<h3>Database error</h3><pre>{e}</pre><p>Query: {query}</p>", 500

        if row:
            session["username"] = row[1]
            session["user_id"] = row[0]
            resp = make_response(redirect("/profile?id=" + str(row[0])))
            # session cookie set without Secure/HttpOnly (intentional flaw)
            return resp
        else:
            error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/search")
def search():
    # --- INTENTIONAL VULNERABILITY: reflected XSS ---
    # the query is echoed back into the page without escaping
    q = request.args.get("q", "")
    results_html = f"<p>Showing results for: {q}</p>" if q else ""
    return render_template("search.html", results_html=results_html, q=q)


@app.route("/profile")
def profile():
    # --- INTENTIONAL VULNERABILITY: IDOR ---
    # any logged-in (or even anonymous) user can view any profile by id,
    # with no ownership / authorization check
    user_id = request.args.get("id", "1")
    db = get_db()
    cur = db.cursor()
    cur.execute(f"SELECT id, username, email, bio FROM users WHERE id = {user_id}")
    user = cur.fetchone()
    return render_template("profile.html", profile=user)


@app.route("/update_profile", methods=["POST"])
def update_profile():
    # --- INTENTIONAL VULNERABILITY: CSRF ---
    # no CSRF token is required to change account data
    user_id = request.form.get("id")
    new_bio = request.form.get("bio", "")
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE users SET bio = ? WHERE id = ?", (new_bio, user_id))
    db.commit()
    return redirect(f"/profile?id={user_id}")


@app.route("/comments", methods=["GET", "POST"])
def comments():
    db = get_db()
    cur = db.cursor()
    if request.method == "POST":
        author = request.form.get("author", "anon")
        content = request.form.get("content", "")
        # stored XSS possible too: content is rendered unescaped in template
        cur.execute("INSERT INTO comments (author, content) VALUES (?,?)", (author, content))
        db.commit()
    cur.execute("SELECT author, content FROM comments ORDER BY id DESC")
    all_comments = cur.fetchall()
    return render_template("comments.html", comments=all_comments)


@app.route("/robots.txt")
def robots():
    # deliberately discloses a "hidden" admin path (info disclosure)
    return "User-agent: *\nDisallow: /admin-backup/\n", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    init_db()
    print("VulnLab running -> http://127.0.0.1:5000  (LOCAL TESTING ONLY)")
    # use_reloader disabled so the process doesn't fork a watcher subprocess
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
