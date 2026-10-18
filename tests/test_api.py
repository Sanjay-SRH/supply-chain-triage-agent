import json

import pytest
from fastapi.testclient import TestClient

from backend import api as api_module


@pytest.fixture
def client(test_graph, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)   # force scripted mode: no network, deterministic
    return TestClient(api_module.create_app(graph=test_graph))


def sse(resp):
    return [json.loads(line[6:]) for line in resp.text.splitlines() if line.startswith("data: ")]


def test_health_reports_scripted_without_key(client):
    h = client.get("/api/health").json()
    assert h["mode"] == "scripted" and "acme" in h["tenants"]


def test_suggestions_and_decisions(client):
    assert client.get("/api/suggestions?tenant=acme").json()["cves"][0]["cve"] == "CVE-T-1"
    d = client.get("/api/decisions?tenant=acme").json()["decisions"]
    assert any(x["id"] == "d-old" for x in d)
    assert client.get("/api/decisions?tenant=globex").json()["decisions"] == [] or all(
        x["id"] != "d-old" for x in client.get("/api/decisions?tenant=globex").json()["decisions"])


def test_unknown_tenant_rejected(client):
    assert client.get("/api/decisions?tenant=evil").status_code == 400
    assert client.post("/api/chat", json={"message": "hi", "tenant": "evil"}).status_code == 400


def test_chat_streams_events_with_graph(client):
    r = client.post("/api/chat", json={"message": "Triage CVE-T-1", "tenant": "acme", "session_id": "s1"})
    assert r.headers["content-type"].startswith("text/event-stream")
    ev = sse(r)
    types = [e["type"] for e in ev]
    assert types[0] == "meta" and ev[0]["mode"] == "scripted" and types[-1] == "final"
    tools = [e["tool"] for e in ev if e["type"] == "tool_call"]
    assert tools == ["find_affected_services", "rank_services", "explain_path", "get_owner", "recall_decisions", "blast_radius"]
    with_graph = [e for e in ev if e["type"] == "tool_result" and e.get("graph")]
    assert with_graph and with_graph[0]["graph"]["cve"] == "CVE-T-1"
    assert all(e["queries"] for e in ev if e["type"] == "tool_result")  # Cypher is always shipped for the Why? drawer
    assert "web" in ev[-1]["text"] and "Platform" in ev[-1]["text"]


def test_chat_without_cve_picks_most_exposed(client):
    ev = sse(client.post("/api/chat", json={"message": "what should I worry about?", "tenant": "acme"}))
    assert [e["tool"] for e in ev if e["type"] == "tool_call"][0] == "most_exposed_cves"
    assert any("CVE-T-1" in e.get("text", "") for e in ev if e["type"] == "thought")


def test_unknown_cve_is_reported_not_invented(client):
    ev = sse(client.post("/api/chat", json={"message": "triage CVE-0000-0000", "tenant": "acme"}))
    assert "not in the graph" in ev[-1]["text"]


def test_validation_and_rate_limit(test_graph, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(api_module, "RATE_LIMIT", 2)
    c = TestClient(api_module.create_app(graph=test_graph))
    assert c.post("/api/chat", json={"message": "", "tenant": "acme"}).status_code == 422
    assert c.post("/api/chat", json={"message": "x" * 2001, "tenant": "acme"}).status_code == 422
    assert c.post("/api/chat", json={"message": "hi", "session_id": "bad id!"}).status_code == 422
    for _ in range(2):
        assert c.post("/api/chat", json={"message": "triage CVE-T-1", "tenant": "acme"}).status_code == 200
    assert c.post("/api/chat", json={"message": "triage CVE-T-1", "tenant": "acme"}).status_code == 429


def test_errors_become_events_not_dead_streams(test_graph, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    def boom(*a, **k):
        raise RuntimeError("model exploded")
    monkeypatch.setattr(api_module, "run_agent", boom)
    c = TestClient(api_module.create_app(graph=test_graph))
    ev = sse(c.post("/api/chat", json={"message": "triage CVE-T-1", "tenant": "acme"}))
    assert ev[-1]["type"] == "error" and "model exploded" in ev[-1]["message"]
