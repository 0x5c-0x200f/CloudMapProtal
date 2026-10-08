import io

import pytest

from cloudmap_portal.portal.app import create_app
from cloudmap_portal.scanners import demo
from cloudmap_portal.scanners.base import Emitter
from cloudmap_portal.schema import Inventory, SchemaError, diff
from cloudmap_portal.writer import write_inventory


def scan_to(tmp_path, scan_id="t1", extra=False):
    em = Emitter("aws", scan_id, scanned_at="2026-10-06T09:00:00Z")
    demo.scan(em)
    if extra:
        em.node("aws:s3:new-bucket", "storage.bucket", "new-bucket", "aws:acct:123456789012")
    return write_inventory(em, tmp_path)


def test_filename_and_roundtrip(tmp_path):
    p = scan_to(tmp_path)
    assert p.name == "aws-t1-2026-10-06.jsonci"
    inv = Inventory.load_path(p)
    assert inv.nodes and inv.edges and len(inv.errors) == 2 and not inv.warnings


def test_blast_radius(tmp_path):
    inv = Inventory.load_path(scan_to(tmp_path))
    inst = next(i for i, n in inv.nodes.items() if n["kind"] == "compute.instance")
    one = set(inv.blast(inst, hops=1)["nodes"])
    two = set(inv.blast(inst, hops=2)["nodes"])
    assert inst in one and one < two
    assert any(i.startswith("aws:sg:") for i in one)


def test_rejects_bad_files():
    for bad in (['{"type":"node","id":"x"}'],
                ['{"type":"node","id":"x","kind":"k","name":"n"}'],  # no meta first
                ['not json'], []):
        with pytest.raises(SchemaError):
            Inventory.load(bad)


def test_dangling_edge_and_parent_are_warnings():
    meta = '{"type":"meta","schema":"1.0","provider":"aws","scan_id":"x","scanned_at":"2026-01-01T00:00:00Z"}'
    node = '{"type":"node","id":"a","kind":"k","name":"a","parent":"missing"}'
    edge = '{"type":"edge","from":"a","to":"ghost","rel":"uses"}'
    inv = Inventory.load([meta, node, edge])
    assert len(inv.warnings) == 2 and inv.nodes["a"]["parent"] is None and not inv.edges


def test_diff(tmp_path):
    a = Inventory.load_path(scan_to(tmp_path / "a", "a"))
    b = Inventory.load_path(scan_to(tmp_path / "b", "b", extra=True))
    d = diff(a, b)
    assert d["added"] == ["aws:s3:new-bucket"] and not d["removed"]


def test_portal_import_and_blast(tmp_path):
    p = scan_to(tmp_path)
    c = create_app().test_client()
    r = c.post("/api/import", data={"file": (io.BytesIO(p.read_bytes()), p.name)})
    assert r.status_code == 200
    iid = r.get_json()["import_id"]
    g = c.get(f"/api/imports/{iid}/graph").get_json()
    inst = next(n["id"] for n in g["nodes"] if n["kind"] == "compute.instance")
    b = c.get(f"/api/imports/{iid}/blast", query_string={"node": inst, "hops": 2}).get_json()
    assert inst in b["nodes"]
    bad = c.post("/api/import", data={"file": (io.BytesIO(b"nope"), "x.jsonci")})
    assert bad.status_code == 422


# ---- insights, reports, portal routes ------------------------------------
def test_insights_findings_and_wording(tmp_path):
    from cloudmap_portal.insights import analyze
    ins = analyze(Inventory.load_path(scan_to(tmp_path)))
    ids = {f["id"] for f in ins["findings"]}
    assert {"exposed-ports", "single-az", "orphan-sg", "untagged", "scan-gaps", "shared-role-api-role"} <= ids
    top = ins["findings"][0]
    assert top["id"] == "exposed-ports" and top["severity"] == "high" and "22" in top["details"][0]
    single = next(f for f in ins["findings"] if f["id"] == "single-az")
    assert single["title"].startswith("1 database runs")           # singular agreement
    assert ins["hubs"] and ins["hubs"][0]["dependents"] >= 2
    assert sum(ins["stats"]["layers"].values()) == ins["stats"]["resources"]


def test_clean_inventory_has_no_urgent_findings():
    from cloudmap_portal.insights import analyze
    meta = '{"type":"meta","schema":"1.0","provider":"aws","scan_id":"x","scanned_at":"2026-01-01T00:00:00Z"}'
    node = '{"type":"node","id":"a","kind":"compute.instance","name":"a","parent":null,"tags":{"env":"p"}}'
    ins = analyze(Inventory.load([meta, node]))
    assert ins["findings"] == [] and "Nothing urgent" in ins["verdict"]


def test_reports_render_and_escape(tmp_path):
    from cloudmap_portal.insights import analyze
    from cloudmap_portal.report import render_html, render_markdown
    inv = Inventory.load_path(scan_to(tmp_path))
    inv.nodes["aws:s3:acme-assets"]["name"] = "<script>alert(1)</script>"
    ins = analyze(inv)
    page = render_html(inv, ins)
    assert "<script>alert(1)</script>" not in page and "CloudMap report" in page
    md = render_markdown(inv, ins)
    assert md.startswith("# CloudMap report") and "## Findings" in md and "## Structure" in md


def test_portal_demo_insights_and_reports():
    c = create_app().test_client()
    iid = c.post("/api/demo").get_json()["import_id"]
    ins = c.get(f"/api/imports/{iid}/insights").get_json()
    assert ins["findings"] and ins["headline"]
    html = c.get(f"/api/imports/{iid}/report.html?download=1")
    assert html.status_code == 200 and "attachment" in html.headers["Content-Disposition"]
    assert c.get(f"/api/imports/{iid}/report.md").mimetype == "text/markdown"
    assert c.get(f"/api/imports/{iid}/report.pdf").status_code == 404
    assert c.get("/api/imports/nope/insights").status_code == 404
    assert c.get("/static/app.js").status_code == 200 and c.get("/static/app.css").status_code == 200


def test_portal_demo_for_every_provider():
    c = create_app().test_client()
    for provider in ("aws", "azure", "gcp"):
        r = c.post(f"/api/demo?provider={provider}")
        assert r.status_code == 200 and r.get_json()["filename"].startswith(provider)
        g = c.get(f"/api/imports/{r.get_json()['import_id']}/graph").get_json()
        assert g["meta"]["provider"] == provider and g["summary"]["nodes"] > 25
    assert c.post("/api/demo?provider=oracle").status_code == 400
