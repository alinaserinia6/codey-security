"""raw_query_format (CWE-89) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
from sqlalchemy import text


def recent_posts(session, limit):
    return session.execute(
        text("SELECT * FROM posts LIMIT :limit"), {"limit": limit}
    )
