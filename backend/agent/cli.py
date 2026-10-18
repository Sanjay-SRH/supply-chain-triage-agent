"""Talk to the agent from the terminal.

  python -m backend.agent.cli "Which services are exposed to CVE-2021-23337?"
  python -m backend.agent.cli                      # interactive chat
  python -m backend.agent.cli --tenant globex ...  # different tenant = different memory
In interactive mode: /tenant NAME switches tenant, /quit exits.
"""
import argparse
import json
import os
import sys

from backend import config
from backend.agent.loop import run_agent

DIM, CYAN, YELLOW, RED, RESET = "\033[2m", "\033[36m", "\033[33m", "\033[31m", "\033[0m"


def show(event: dict):
    t = event["type"]
    if t == "thought":
        print(f"{DIM}{event['text']}{RESET}")
    elif t == "tool_call":
        print(f"{CYAN}> {event['tool']}({json.dumps(event['input'])}){RESET}")
    elif t == "tool_result":
        colour = RED if event["error"] else DIM
        summary = json.dumps(event["output"], default=str)
        print(f"{colour}  = {summary[:200]}{'...' if len(summary) > 200 else ''}{RESET}")
        for qy in event["queries"]:
            print(f"{YELLOW}    cypher[{qy['name']}]{RESET}{DIM} params={qy['params']}{RESET}")
    elif t == "final":
        print(f"\n{event['text']}\n")


def main():
    ap = argparse.ArgumentParser(description="Supply-chain triage agent")
    ap.add_argument("question", nargs="*", help="omit for interactive mode")
    ap.add_argument("--tenant", default=config.DEFAULT_TENANT)
    args = ap.parse_args()

    if not os.getenv("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set. Add it to your .env file (see .env.example).")

    tenant, history = args.tenant, None
    if args.question:
        run_agent(" ".join(args.question), tenant=tenant, on_event=show)
        return
    print(f"Triage agent (tenant: {tenant}). /tenant NAME to switch, /quit to exit.\n")
    while True:
        try:
            line = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line in ("/quit", "/exit"):
            break
        if line.startswith("/tenant "):
            tenant, history = line.split(None, 1)[1].strip(), None
            print(f"Switched to tenant '{tenant}' (conversation reset).")
            continue
        history = run_agent(line, tenant=tenant, history=history, on_event=show).messages


if __name__ == "__main__":
    main()
