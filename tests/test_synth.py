from backend.ingest.synth import generate

DEPS = {"seed_versions": {f"pkg{i}": [f"pkg{i}@1.0.0", f"pkg{i}@2.0.0"] for i in range(12)}}


def test_deterministic():
    assert generate(DEPS, seed=1) == generate(DEPS, seed=1)
    assert generate(DEPS, seed=1) != generate(DEPS, seed=2)


def test_shape_and_rules():
    c = generate(DEPS)
    names = [s["name"] for s in c["services"]]
    assert len(names) == 30 and len(set(names)) == 30
    assert all(a != b and names.index(a) < names.index(b) for a, b in c["calls"])  # calls only go downward
    assert {u[0] for u in c["uses"]} == set(names)
    assert len(c["owned_by"]) == 30
