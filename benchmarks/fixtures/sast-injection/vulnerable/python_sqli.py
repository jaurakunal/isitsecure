# Injection benchmark fixture — Python SQL injection (VULNERABLE).
# Each trailing marker on a sink line is a bug the taint layer must flag.
# Stack shapes: raw DB-API cursor.execute, SQLAlchemy text(), Django raw/extra.

from flask import request
from sqlalchemy import text

from .models import User


def get_user(db, uid):
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")  # EXPECT sqli


def search(db):
    term = request.args.get("q")
    db.execute("SELECT * FROM items WHERE name = '%s'" % term)  # EXPECT sqli


def by_name(db, name):
    db.execute("SELECT * FROM users WHERE name = " + name)  # EXPECT sqli


def sqlalchemy_raw(conn, uid):
    return conn.execute(text(f"SELECT * FROM users WHERE id = {uid}"))  # EXPECT sqli


def django_raw():
    uid = request.GET.get("id")
    return User.objects.raw(f"SELECT * FROM users WHERE id = {uid}")  # EXPECT sqli


def assign_then_execute(db):
    uid = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {uid}"  # built on one line...
    db.execute(query)  # EXPECT sqli  ...executed on the next (taint, not inline)


def format_query(db, name):
    db.execute("SELECT * FROM users WHERE name = '{}'".format(name))  # EXPECT sqli
