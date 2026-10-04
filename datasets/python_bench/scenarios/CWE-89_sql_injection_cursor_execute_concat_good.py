"""cursor_execute_concat (CWE-89) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import sqlite3


def count_orders(connection, user):
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM orders WHERE user = ?", (user,))
    return cursor.fetchone()
