"""STEP 1 - Crawl the public npm registry to build the dependency graph.

For every seed package we take the newest release of each of its last few major versions
(old majors are where real vulnerabilities live), then follow `dependencies` to the versions
npm would pick (highest version satisfying the range), up to MAX_DEPTH levels deep.

Output: data/graph_deps.json
Run:    python -m backend.ingest.npm_deps
"""
import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from semantic_version import NpmSpec, Version

from backend.config import DATA_DIR, MAX_DEPTH, MAX_VERSIONS
from backend.ingest.seeds import SEED_PACKAGES

REGISTRY = "https://registry.npmjs.org"
# The "abbreviated" document is much smaller than the full one and still lists dependencies.
HEADERS = {"Accept": "application/vnd.npm.install-v1+json"}
RELEASE_LINES = 4  # newest release of each of the last N major versions
CACHE = DATA_DIR / "npm"
OUT = DATA_DIR / "graph_deps.json"

_stable_cache: dict[str, list[Version]] = {}


def _cache_path(name: str):
    return CACHE / (name.replace("/", "__") + ".json")


def fetch_packument(client: httpx.Client, name: str):
    """Return {"name","latest","versions":{ver: {dep: range}}} or None. Cached on disk."""
    path = _cache_path(name)
    if path.exists():
        return json.loads(path.read_text())
    url = f"{REGISTRY}/{name.replace('/', '%2f')}"
    for attempt in range(4):
        try:
            r = client.get(url, headers=HEADERS, timeout=30)
            if r.status_code == 404:
                data = {"name": name, "latest": None, "versions": {}}
            else:
                r.raise_for_status()
                raw = r.json()
                data = {
                    "name": name,
                    "latest": raw.get("dist-tags", {}).get("latest"),
                    "versions": {v: (m.get("dependencies") or {}) for v, m in raw.get("versions", {}).items()},
                }
            CACHE.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data))
            return data
        except httpx.HTTPError:
            time.sleep(1.5 * (attempt + 1))
    print(f"  ! could not fetch {name}")
    return None


def parse_version(v: str):
    try:
        return Version(v)
    except ValueError:
        return None


def stable_versions(pk) -> list[Version]:
    """All non-prerelease, parseable versions of a package, ascending."""
    name = pk["name"]
    if name not in _stable_cache:
        vs = [parse_version(v) for v in pk["versions"]]
        _stable_cache[name] = sorted(v for v in vs if v and not v.prerelease)
    return _stable_cache[name]


def release_lines(pk, n: int = RELEASE_LINES) -> list[str]:
    """Newest stable release of each of the last n major lines (0.x lines split by minor)."""
    best: dict[tuple, Version] = {}
    for v in stable_versions(pk):
        key = (v.major,) if v.major > 0 else (0, v.minor)
        best[key] = v  # ascending order, so the last one wins
    keys = sorted(best)[-n:]
    return [str(best[k]) for k in keys]


def resolve(pk, rng: str):
    """Pick the highest version satisfying an npm range, like `npm install` would."""
    try:
        best = NpmSpec(rng).select(stable_versions(pk))
    except Exception:  # git urls, aliases, odd ranges: skip them
        return None
    return str(best) if best else None


def crawl():
    versions: set[tuple[str, str]] = set()
    edges: set[tuple[str, str]] = set()
    seed_versions: dict[str, list[str]] = {}
    packs: dict[str, dict | None] = {}

    with httpx.Client(follow_redirects=True) as client, ThreadPoolExecutor(8) as pool:

        def load(names):
            todo = [n for n in set(names) if n not in packs]
            for n, res in zip(todo, pool.map(lambda x: fetch_packument(client, x), todo)):
                packs[n] = res

        print(f"Fetching {len(SEED_PACKAGES)} seed packages...")
        load(SEED_PACKAGES)
        frontier = []
        for name in SEED_PACKAGES:
            pk = packs.get(name)
            if not pk or not pk["versions"]:
                print(f"  ! skipping seed {name}")
                continue
            seed_versions[name] = release_lines(pk)
            for v in seed_versions[name]:
                versions.add((name, v))
                frontier.append((name, v))

        depth = 0
        while frontier and depth < MAX_DEPTH:
            need = set()
            for name, v in frontier:
                need.update(packs[name]["versions"].get(v, {}).keys())
            print(f"Depth {depth + 1}: {len(frontier)} versions, fetching {len(need)} dependency packages...")
            load(need)
            nxt = []
            for name, v in frontier:
                for dep, rng in packs[name]["versions"].get(v, {}).items():
                    pk = packs.get(dep)
                    if not pk:
                        continue
                    rv = resolve(pk, rng)
                    if not rv:
                        continue
                    if (dep, rv) not in versions:
                        if len(versions) >= MAX_VERSIONS:
                            continue  # cap reached: drop the edge too, so no dangling nodes
                        versions.add((dep, rv))
                        nxt.append((dep, rv))
                    edges.add((f"{name}@{v}", f"{dep}@{rv}"))
            frontier = nxt
            depth += 1

    out = {
        "packages": sorted({n for n, _ in versions}),
        "versions": [{"id": f"{n}@{v}", "name": n, "version": v} for n, v in sorted(versions)],
        "edges": sorted([list(e) for e in edges]),
        "seed_versions": {n: [f"{n}@{v}" for v in vs] for n, vs in seed_versions.items()},
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1))
    print(f"Wrote {OUT}: {len(out['packages'])} packages, {len(out['versions'])} versions, {len(out['edges'])} dependency edges")


if __name__ == "__main__":
    crawl()
