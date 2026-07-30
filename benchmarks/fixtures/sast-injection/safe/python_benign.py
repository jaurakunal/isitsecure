# Injection benchmark fixture — Python SAFE / benign near-misses.
# NOTHING here may be flagged — this is the false-positive side for Python.

import os
import subprocess

import requests
from flask import request
from sqlalchemy import text


# SAFE: parameterized queries (placeholders + params, not string-built)
def get_user(db, uid):
    db.execute("SELECT * FROM users WHERE id = ?", (uid,))
    db.execute("SELECT * FROM users WHERE id = %s", (uid,))


# SAFE: parameterized even though the value comes from the request — the taint
# rule focuses on the query string, so a value in the params tuple is fine.
def param_from_request(db):
    uid = request.args.get("id")
    db.execute("SELECT * FROM users WHERE id = ?", (uid,))


# SAFE: a bare text() call (e.g. an i18n gettext alias) is not a SQL sink —
# only text(...) passed into execute() is flagged.
def label(name):
    return text(f"Hello {name}")


# SAFE: SQLAlchemy with bound parameters
def sa_query(conn, uid):
    return conn.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid})


# SAFE: subprocess WITHOUT shell=True (argv list — no shell parsing)
def run_cmd():
    name = request.args.get("name")
    subprocess.run(["ls", "-la", name])


# SAFE: constant-path file open (not user-derived)
def read_config():
    with open("/etc/app/config.yaml") as f:
        return f.read()


# SAFE: request to a fixed, non-user-controlled URL
def health():
    return requests.get("https://api.internal.example.com/health")


# SAFE: user input used as a query PARAMETER via join, not shelled/executed
def build_path(base):
    return os.path.join(base, "static", "logo.png")
