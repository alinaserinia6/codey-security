"""cursor_execute_fstring (CWE-89) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import sqlite3


def find_user(connection, name):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()
