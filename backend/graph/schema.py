"""Indexes. Lookups by these properties are what every query starts from, so index them."""
INDEXES = [
    ("CVE", "id"),
    ("Version", "id"),
    ("Package", "name"),
    ("Service", "name"),
    ("Team", "name"),
    ("Decision", "id"),
]


def create_indexes(g):
    for label, prop in INDEXES:
        try:
            g.query(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")
        except Exception as e:  # already exists is fine
            if "already indexed" not in str(e).lower():
                raise
