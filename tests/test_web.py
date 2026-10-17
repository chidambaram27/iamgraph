"""Web UI endpoints, served against the `iam_test` graph built by the shared fixture."""

import pytest
from fastapi.testclient import TestClient

from iamgraph.web import app


@pytest.fixture
def client(g, monkeypatch):
    monkeypatch.setenv("FALKORDB_GRAPH", g.name)
    return TestClient(app)


def test_index_and_graph(client):
    assert "vis-network" in client.get("/").text
    data = client.get("/api/graph").json()
    uids = {n["uid"] for n in data["nodes"]}
    assert data["edges"] and all(e["from"] in uids and e["to"] in uids for e in data["edges"])


def test_fix_cut_edges_are_on_path(client):
    pair = {"source": "web-frontend", "target": "prod-db-credentials"}
    path = client.get("/api/path", params=pair).json()
    fix = client.get("/api/fix", params=pair).json()
    assert fix["verified_no_path_after_fix"]
    on_path = {e["id"] for p in path["paths"] for e in p["edges"]}
    assert all(set(f["cut_edge_ids"]) & on_path for f in fix["fixes"])
    assert any("diff" in f for f in fix["fixes"])


def test_lookup_error_is_returned(client):
    assert "error" in client.get("/api/path", params={"source": "nobody", "target": "prod-db-credentials"}).json()
