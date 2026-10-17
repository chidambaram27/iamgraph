import os

from dotenv import load_dotenv
from falkordb import FalkorDB, Graph

load_dotenv()


def get_graph(name: str | None = None) -> Graph:
    db = FalkorDB(
        host=os.getenv("FALKORDB_HOST", "localhost"),
        port=int(os.getenv("FALKORDB_PORT", "6379")),
    )
    return db.select_graph(name or os.getenv("FALKORDB_GRAPH", "iam"))
