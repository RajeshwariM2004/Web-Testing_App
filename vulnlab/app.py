"""
VulnLab — intentionally vulnerable Flask app for LOCAL testing only.

WARNING:
- This app contains deliberate XSS and SQL injection vulnerabilities.
- Run only on 127.0.0.1 for educational scanner testing.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from flask import Flask, redirect, render_template, request, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vulnlab.db"

app = Flask(__name__)
app.secret_key = os.environ.get("VULNLAB_SECRET_KEY", "vulnlab-dev")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
            """
        )
        # Seed at least one user so normal login works too.
        existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if existing == 0:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ("admin", "admin123"),
            )
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ("user", "password"),
            )
        conn.commit()
    finally:
        conn.close()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/search")
def search():
    """
    Intentionally vulnerable to reflected XSS.
    Example:
      /search?q=<script>alert(1)</script>
    """
    q = request.args.get("q", "")
    # Render unsanitized on purpose (template uses |safe).
    return render_template("search.html", q=q)


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Intentionally vulnerable to SQL injection.
    The query is built unsafely with string concatenation.

    Example bypass payloads:
      username: ' OR '1'='1
      password: anything
    """
    msg = ""
    ok_user = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # DO NOT COPY THIS PATTERN INTO REAL APPS.
        # This is intentionally vulnerable for scanner testing.
        unsafe_query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )

        conn = get_db()
        try:
            row = conn.execute(unsafe_query).fetchone()
        except sqlite3.Error as e:
            # Show raw error for easier detection (also intentionally unsafe).
            msg = f"Database error: {e}"
            row = None
        finally:
            conn.close()

        if row:
            ok_user = row["username"]
            msg = "Login success (vulnerable app)."
        else:
            if not msg:
                msg = "Login failed."

    return render_template("login.html", message=msg, ok_user=ok_user)


if __name__ == "__main__":
    init_db()
    # Local-only bind for safety.
    app.run(host="127.0.0.1", port=5001, debug=True, use_reloader=False)

