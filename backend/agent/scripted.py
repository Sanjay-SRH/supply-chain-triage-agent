"""A deterministic, NO-LLM triage flow with the same event stream as the Claude agent.

Why it exists: (1) the UI and API can be developed and tested without an API key, (2) it is a clearly labelled
fallback for demos if the LLM is unreachable. The UI shows a "scripted" badge whenever it is used.
It runs the same tools the Claude agent would; only the choice of which tool to call is hard-coded.
"""
import re
from typing import Callable

from backend.agent.loop import AgentResult
from backend.agent.tools import Toolbox

CVE_RE = re.compile(r"\b(CVE(?:-[0-9A-Z]+)+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b", re.I)  # the graph lookup decides validity
PKG_RE = re.compile(r"\b(?:in|for|of|about)\s+(?:the\s+)?([@a-z0-9][a-z0-9@/._-]{1,60})\b", re.I)


def run_scripted(question: str, toolbox: Toolbox, on_event: Callable[[dict], None] | None = None) -> AgentResult:
    emit = on_event or (lambda e: None)
    trace: list = []

    def call(tool: str, **args):
        emit({"type": "tool_call", "tool": tool, "input": args})
        toolbox.queries_used.clear()
        out = toolbox.call(tool, args)
        entry = {"tool": tool, "input": args, "output": out, "queries": list(toolbox.queries_used), "error": "error" in out}
        trace.append(entry)
        emit({"type": "tool_result", **entry})
        return out

    def finish(text: str) -> AgentResult:
        emit({"type": "final", "text": text})
        return AgentResult(text, [], trace, len(trace))

    m = CVE_RE.search(question)
    cve = m.group(1) if m else None

    if not cve:
        # try "in <package>" style questions, otherwise fall back to the most exposed CVE
        for pm in PKG_RE.finditer(question):
            found = call("find_cves_for_package", package=pm.group(1).lower())
            if found.get("cves"):
                cve = found["cves"][0]["cve"]
                break
    if not cve:
        top = call("most_exposed_cves", limit=5)
        if not top.get("cves"):
            return finish("(Scripted mode) I found no exposed vulnerabilities in the graph.")
        cve = top["cves"][0]["cve"]
        emit({"type": "thought", "text": f"No CVE named, so I am triaging the most exposed one: {cve}."})

    aff = call("find_affected_services", cve=cve)
    if "error" in aff:
        return finish(f"(Scripted mode) {aff['error']}")
    if not aff["services"]:
        return finish(f"(Scripted mode) {aff['cve']} does not reach any of our services. Nothing to do.")

    rank = call("rank_services", cve=aff["cve"], limit=25)
    top = rank["ranked"][0]
    call("explain_path", service=top["service"], cve=aff["cve"])
    owner = call("get_owner", service=top["service"])
    recall = call("recall_decisions", cve=aff["cve"])
    blast = call("blast_radius", cve=aff["cve"])

    lines = [
        f"(Scripted triage, no LLM) {aff['cve']} is {aff['severity']} (CVSS approx. {aff['cvss']}) and reaches "
        f"{aff['total_services']} service(s). {aff['summary']}",
        "", "Riskiest services:",
    ]
    for r in rank["ranked"][:3]:
        lines.append(f"- **{r['service']}** {r['priority']} (score {r['score']}, tier {r['tier']}, {r['exposure']}, {r['hops']} hops)")
    lines += ["", "Why the top one is exposed:", "`" + " -> ".join(top["chain"]) + "`",
              "", f"Owner: {owner.get('team', 'unknown')} ({owner.get('oncall', 'n/a')})."]
    prec = recall.get("precedents") or []
    if prec:
        p = prec[0]
        lines.append(f"Precedent: {p['past_cve']} on {p['service']} was handled as '{p['action']}': {p['reasoning']}")
    else:
        lines.append("Precedent: none recorded for this tenant.")
    if blast.get("total"):
        lines.append(f"Blast radius: {blast['total']} more service(s) call an exposed service.")
    return finish("\n".join(lines))
