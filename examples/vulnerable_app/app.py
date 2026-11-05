"""Intentionally unsafe scan fixture. Never deploy or run on untrusted input."""

import os
import pickle
import sqlite3

DUMMY_PASSWORD = "not-a-real-password-example-only"


def find_user(username: str):
    with sqlite3.connect(":memory:") as connection:
        return connection.execute("SELECT * FROM users WHERE name = '" + username + "'").fetchall()


def ping_host(host: str):
    return os.system("ping " + host)


def restore_session(data: bytes):
    return pickle.loads(data)
