from backend.ingest.osv_vulns import affected_versions, build, in_ranges, normalise

RANGE = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]


def test_in_range_basic():
    assert in_ranges("4.17.20", RANGE)
    assert not in_ranges("4.17.21", RANGE)
    assert in_ranges("0.1.0", RANGE)


def test_introduced_then_fixed_gap():
    r = [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.5.0"}]}]
    assert not in_ranges("1.9.9", r)
    assert in_ranges("2.4.9", r)
    assert not in_ranges("2.5.0", r)


def test_two_windows_and_last_affected():
    r = [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"},
                                         {"introduced": "3.0.0"}, {"last_affected": "3.1.0"}]}]
    assert in_ranges("1.1.0", r) and not in_ranges("1.5.0", r)
    assert in_ranges("3.1.0", r) and not in_ranges("3.1.1", r)


def test_git_ranges_ignored():
    assert not in_ranges("1.0.0", [{"type": "GIT", "events": [{"introduced": "0"}]}])


VULN = {"id": "GHSA-xxxx", "aliases": ["CVE-2021-0001"], "summary": "Prototype pollution",
        "published": "2021-02-01T00:00:00Z", "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}, "ranges": RANGE}]}


def test_affected_versions_only_matching_package():
    assert affected_versions(VULN, "lodash", ["4.17.20", "4.17.21"]) == ["4.17.20"]
    assert affected_versions(VULN, "other", ["1.0.0"]) == []


def test_normalise_prefers_cve_and_maps_severity():
    n = normalise(VULN)
    assert n["id"] == "CVE-2021-0001" and n["cvss"] == 7.5 and n["published"] == "2021-02-01"


def test_build_skips_withdrawn_and_unmatched():
    withdrawn = dict(VULN, id="GHSA-w", withdrawn="2022-01-01T00:00:00Z")
    cves, affects = build({"lodash": [VULN, withdrawn]}, {"lodash": ["4.17.20", "4.17.21"]})
    assert [c["id"] for c in cves] == ["CVE-2021-0001"]
    assert affects == [["CVE-2021-0001", "lodash@4.17.20"]]
