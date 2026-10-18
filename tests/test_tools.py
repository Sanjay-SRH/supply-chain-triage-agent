import inspect

from backend.agent.tools import TOOL_NAMES, TOOL_SPECS, Toolbox


def test_every_spec_matches_its_method_signature():
    for spec in TOOL_SPECS:
        params = set(inspect.signature(getattr(Toolbox, spec["name"])).parameters) - {"self"}
        declared = set(spec["input_schema"]["properties"])
        assert declared == params, spec["name"]
        assert set(spec["input_schema"]["required"]) <= declared
        assert spec["description"]


def test_find_affected_services_and_chains(box):
    r = box.find_affected_services("CVE-T-1")
    by = {s["service"]: s for s in r["services"]}
    assert set(by) == {"web", "batch"}
    assert by["web"]["chain"] == ["web", "app@1", "lib@1", "CVE-T-1"] and by["web"]["hops"] == 3
    assert by["batch"]["chain"] == ["batch", "lib@1", "CVE-T-1"] and by["batch"]["hops"] == 2


def test_cve_lookup_is_case_insensitive(box):
    assert box.get_cve("cve-t-1")["id"] == "CVE-T-1"
    assert "error" in box.get_cve("CVE-NOPE")


def test_explain_path(box):
    r = box.explain_path("web", "CVE-T-1")
    assert r["exposed"] and r["vulnerable_version"] == "lib@1" and r["pulled_in_by"] == "app@1"
    assert box.explain_path("safe", "CVE-T-1")["exposed"] is False


def test_blast_radius_finds_callers_only(box):
    r = box.blast_radius("CVE-T-1")
    assert [c["service"] for c in r["upstream_callers"]] == ["gateway"]


def test_ranking_puts_critical_public_tier1_first(box):
    r = box.rank_services("CVE-T-1")
    assert [x["service"] for x in r["ranked"]] == ["web", "batch"]
    assert r["ranked"][0]["priority"] == "P1" and r["ranked"][0]["score"] > r["ranked"][1]["score"]
    assert "formula" in r


def test_owner(box):
    assert box.get_owner("batch")["team"] == "Data"
    assert "error" in box.get_owner("ghost")


def test_find_cves_for_package(box):
    ids = {c["cve"] for c in box.find_cves_for_package("lib")["cves"]}
    assert ids == {"CVE-T-0", "CVE-T-1"}


def test_recall_is_tenant_scoped(box):
    from backend.agent.tools import Toolbox
    acme = box.recall_decisions("CVE-T-1")
    assert "d-old" in [p["decision"] for p in acme["precedents"]]
    other = Toolbox(graph=box.g, tenant="globex").recall_decisions("CVE-T-1")
    assert other["precedents"] == []


def test_save_decision_validates_then_writes(box):
    assert "error" in box.save_decision("CVE-T-1", "web", "yolo", "x")
    assert "error" in box.save_decision("CVE-T-1", "ghost", "patched", "x")
    assert "error" in box.save_decision("CVE-T-1", "web", "patched", "  ")
    ok = box.save_decision("CVE-T-1", "web", "upgrade_planned", "needs app major bump")
    assert ok["saved"] and ok["tenant"] == "acme"
    # memory round trip: the new decision about CVE-T-1 is now precedent for CVE-T-0 (same package)
    prec = {p["decision"] for p in box.recall_decisions("CVE-T-0")["precedents"]}
    assert ok["decision_id"] in prec
    # and asking about the SAME cve now surfaces it first, flagged as same_cve
    first = box.recall_decisions("CVE-T-1")["precedents"][0]
    assert first["decision"] == ok["decision_id"] and first["same_cve"] is True


def test_draft_ticket(box):
    t = box.draft_ticket("web", "CVE-T-1", "internet-facing")
    assert t["priority"] == "P1" and t["assignee"] == "@platform-oncall"
    assert "web -> app@1 -> lib@1 -> CVE-T-1" in t["body"]
    assert "error" in box.draft_ticket("safe", "CVE-T-1")


def test_call_never_raises(box):
    assert "error" in box.call("nope", {})
    assert "error" in box.call("get_owner", {})              # missing argument
    assert "error" in box.call("get_owner", {"bogus": 1})    # unexpected argument


def test_queries_are_recorded_for_the_why_button(box):
    box.queries_used.clear()
    box.find_affected_services("CVE-T-1")
    names = [q["name"] for q in box.queries_used]
    assert "affected_services" in names and box.queries_used[-1]["cypher"].startswith("MATCH")


def test_new_decision_supersedes_old_and_recall_ignores_old(box):
    first = box.save_decision("CVE-T-0", "web", "accepted_risk", "first view")
    assert "supersedes" not in first
    second = box.save_decision("CVE-T-0", "web", "patched", "changed our mind")
    assert second["supersedes"] == first["decision_id"] and second["previous_action"] == "accepted_risk"
    current = {p["decision"] for p in box.recall_decisions("CVE-T-0")["precedents"]}
    assert second["decision_id"] in current and first["decision_id"] not in current
    hist = {d["id"]: d for d in box.list_decisions()}
    assert hist[first["decision_id"]]["superseded_by"] == second["decision_id"]
    assert hist[second["decision_id"]]["supersedes"] == first["decision_id"]


def test_supersede_is_per_tenant_and_per_service(box):
    from backend.agent.tools import Toolbox
    a = box.save_decision("CVE-T-1", "batch", "patched", "acme view")
    other_tenant = Toolbox(graph=box.g, tenant="globex").save_decision("CVE-T-1", "batch", "accepted_risk", "globex view")
    other_service = box.save_decision("CVE-T-1", "web", "patched", "different service")
    assert "supersedes" not in other_tenant or other_tenant["supersedes"] != a["decision_id"]
    assert other_service.get("supersedes") != a["decision_id"]
