"""The agent loop: Claude decides which graph tool to call, we run it, feed the result back, repeat.

`run_agent` reports every step through an `on_event` callback so the CLI (and, on Day 3, the web UI)
can show the tool calls and the Cypher behind them live.
"""
import json
from dataclasses import dataclass, field
from typing import Callable

from backend import config
from backend.agent.prompts import SYSTEM_PROMPT
from backend.agent.tools import TOOL_SPECS, Toolbox


@dataclass
class AgentResult:
    answer: str
    messages: list                      # full conversation, pass back as `history` for a follow-up turn
    trace: list = field(default_factory=list)   # every tool call with its Cypher and result
    steps: int = 0
    stopped_early: bool = False


def run_agent(question: str, tenant: str | None = None, history: list | None = None,
              on_event: Callable[[dict], None] | None = None, client=None, model: str | None = None,
              max_steps: int | None = None, toolbox: Toolbox | None = None) -> AgentResult:
    emit = on_event or (lambda e: None)
    if client is None:
        import anthropic
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    box = toolbox or Toolbox(tenant=tenant or config.DEFAULT_TENANT)
    messages = list(history or []) + [{"role": "user", "content": question}]
    trace: list = []
    max_steps = max_steps or config.MAX_AGENT_STEPS

    for step in range(1, max_steps + 1):
        resp = client.messages.create(
            model=model or config.ANTHROPIC_MODEL, max_tokens=2048,
            system=SYSTEM_PROMPT, tools=TOOL_SPECS, messages=messages,
        )
        messages.append({"role": "assistant", "content": resp.content})
        text = "".join(b.text for b in resp.content if b.type == "text").strip()

        if resp.stop_reason != "tool_use":
            emit({"type": "final", "text": text})
            return AgentResult(text, messages, trace, step)

        if text:
            emit({"type": "thought", "text": text})
        results = []
        for block in (b for b in resp.content if b.type == "tool_use"):
            emit({"type": "tool_call", "tool": block.name, "input": block.input})
            box.queries_used.clear()
            output = box.call(block.name, block.input)
            entry = {"tool": block.name, "input": block.input, "output": output,
                     "queries": list(box.queries_used), "error": "error" in output}
            trace.append(entry)
            emit({"type": "tool_result", **entry})
            results.append({"type": "tool_result", "tool_use_id": block.id,
                            "content": json.dumps(output, default=str), "is_error": "error" in output})
        messages.append({"role": "user", "content": results})

    msg = f"Stopped after {max_steps} steps without a final answer."
    emit({"type": "final", "text": msg})
    return AgentResult(msg, messages, trace, max_steps, stopped_early=True)
