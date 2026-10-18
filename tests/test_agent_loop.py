"""Tests the loop with a scripted fake model (no API key needed)."""
from types import SimpleNamespace as NS

from backend.agent.loop import run_agent


def tool_use(i, name, **inp):
    return NS(type="tool_use", id=f"t{i}", name=name, input=inp)


class FakeClient:
    """Plays back a fixed script of responses and records what it was sent."""
    def __init__(self, script):
        self.script, self.calls = list(script), []
        self.messages = NS(create=self._create)

    def _create(self, **kw):
        self.calls.append({**kw, "messages": list(kw["messages"])})  # snapshot, like a real request
        return self.script.pop(0)


def resp(blocks, stop):
    return NS(content=blocks, stop_reason=stop)


def test_loop_runs_tools_then_answers(box):
    client = FakeClient([
        resp([NS(type="text", text="Checking exposure."), tool_use(1, "find_affected_services", cve="CVE-T-1")], "tool_use"),
        resp([tool_use(2, "get_owner", service="web")], "tool_use"),
        resp([NS(type="text", text="web and batch are exposed; web is owned by Platform.")], "end_turn"),
    ])
    events = []
    res = run_agent("who is exposed to CVE-T-1?", toolbox=box, client=client, on_event=events.append)

    assert res.answer.startswith("web and batch") and res.steps == 3 and not res.stopped_early
    assert [t["tool"] for t in res.trace] == ["find_affected_services", "get_owner"]
    assert res.trace[0]["queries"], "Cypher must be captured for the Why? button"
    assert [e["type"] for e in events] == ["thought", "tool_call", "tool_result", "tool_call", "tool_result", "final"]
    # the tool result went back to the model as a tool_result block tied to the right id
    last_user = client.calls[1]["messages"][-1]
    assert last_user["role"] == "user" and last_user["content"][0]["tool_use_id"] == "t1"
    assert "web" in last_user["content"][0]["content"] and last_user["content"][0]["is_error"] is False


def test_tool_errors_are_returned_to_the_model_not_raised(box):
    client = FakeClient([
        resp([tool_use(1, "get_cve", cve="CVE-NOPE")], "tool_use"),
        resp([NS(type="text", text="That CVE is not in the graph.")], "end_turn"),
    ])
    res = run_agent("tell me about CVE-NOPE", toolbox=box, client=client)
    assert res.trace[0]["error"] is True
    assert client.calls[1]["messages"][-1]["content"][0]["is_error"] is True
    assert res.answer == "That CVE is not in the graph."


def test_loop_stops_after_max_steps(box):
    forever = [resp([tool_use(i, "get_owner", service="web")], "tool_use") for i in range(5)]
    res = run_agent("loop", toolbox=box, client=FakeClient(forever), max_steps=3)
    assert res.stopped_early and res.steps == 3


def test_history_lets_followups_continue(box):
    c1 = FakeClient([resp([NS(type="text", text="first")], "end_turn")])
    r1 = run_agent("hello", toolbox=box, client=c1)
    c2 = FakeClient([resp([NS(type="text", text="second")], "end_turn")])
    run_agent("and then?", toolbox=box, client=c2, history=r1.messages)
    assert len(c2.calls[0]["messages"]) == 3  # user, assistant, new user
