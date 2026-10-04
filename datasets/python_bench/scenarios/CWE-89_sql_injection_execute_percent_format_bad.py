"""execute_percent_format (CWE-89) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import sqlite3


def delete_session(connection, token):
    cursor = connection.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = '%s'" % token)
    return cursor.rowcount
