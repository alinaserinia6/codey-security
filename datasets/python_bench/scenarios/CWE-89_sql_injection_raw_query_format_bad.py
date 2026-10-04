"""raw_query_format (CWE-89) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
from sqlalchemy import text


def recent_posts(session, limit):
    return session.execute(text(f"SELECT * FROM posts LIMIT {limit}"))
