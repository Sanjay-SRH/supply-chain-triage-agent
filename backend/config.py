"""Central configuration, read from environment variables (or a .env file)."""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", ROOT / "data"))

FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
FALKORDB_PASSWORD = os.getenv("FALKORDB_PASSWORD") or None
FALKORDB_SSL = os.getenv("FALKORDB_SSL", "false").lower() == "true"
GRAPH_NAME = os.getenv("GRAPH_NAME", "triage")

# Optional: run an embedded FalkorDB (no Docker). Linux/macOS only, needs `pip install falkordblite`.
EMBEDDED_PATH = os.getenv("FALKORDB_EMBEDDED_PATH") or None

MAX_DEPTH = int(os.getenv("MAX_DEPTH", "3"))
MAX_VERSIONS = int(os.getenv("MAX_VERSIONS", "900"))
SEED = 42  # fixed seed so the synthetic company is reproducible

# Agent (Day 2)
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
DEFAULT_TENANT = os.getenv("TRIAGE_TENANT", "acme")
MAX_AGENT_STEPS = int(os.getenv("MAX_AGENT_STEPS", "12"))
