"""cursor_execute_concat (CWE-89) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import sqlite3


def count_orders(connection, user):
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM orders WHERE user = " + user)
    return cursor.fetchone()
