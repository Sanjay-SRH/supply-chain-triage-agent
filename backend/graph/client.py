"""One place that knows how to connect to FalkorDB."""
from backend import config

_db = None


def get_db():
    global _db
    if _db is not None:
        return _db
    if config.EMBEDDED_PATH:
        from redislite.falkordb_client import FalkorDB  # embedded, no Docker
        _db = FalkorDB(config.EMBEDDED_PATH)
    else:
        from falkordb import FalkorDB
        kwargs = dict(host=config.FALKORDB_HOST, port=config.FALKORDB_PORT)
        if config.FALKORDB_PASSWORD:
            kwargs["password"] = config.FALKORDB_PASSWORD
        if config.FALKORDB_SSL:
            kwargs["ssl"] = True
        _db = FalkorDB(**kwargs)
    return _db


def get_graph(name: str | None = None):
    return get_db().select_graph(name or config.GRAPH_NAME)
