"""cursor_execute_fstring (CWE-89) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import sqlite3


def find_user(connection, name):
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
