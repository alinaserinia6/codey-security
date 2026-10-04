"""execute_percent_format (CWE-89) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import sqlite3


def delete_session(connection, token):
    cursor = connection.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return cursor.rowcount
