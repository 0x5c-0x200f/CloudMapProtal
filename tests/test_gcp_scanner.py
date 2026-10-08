"""GCP: the asset->inventory mapping, plus the Cloud Asset fetch layer using real protobuf objects."""
import json

import pytest

from cloudmap_portal import cli
from cloudmap_portal.insights import analyze
from cloudmap_portal.scanners import demo_rows, gcp
from cloudmap_portal.scanners.base import Emitter
from cloudmap_portal.schema import Inventory


def build_demo(assets=None):
    em = Emitter("gcp", "t1", scanned_at="2026-10-06T09:00:00Z")
    gcp.build(em, assets or demo_rows.gcp_assets())
    return em, Inventory.load(json.dumps(r) for r in em.records())


def by_name(inv, name):
    return next(n for n in inv.nodes.values() if n["name"] == name)


def edges(inv):
    return {(e["from"], e["to"], e["rel"]) for e in inv.edges}


def test_hierarchy_org_folder_project_and_clean_import():
    _, inv = build_demo()
    assert not inv.warnings and not inv.errors
    org, folder, proj = by_name(inv, "example.com"), by_name(inv, "platform"), by_name(inv, "Shop Production")
    assert (org["kind"], folder["kind"], proj["kind"]) == ("organization", "folder", "account")
    assert proj["parent"] == folder["id"] and folder["parent"] == org["id"] and org["parent"] is None
    assert by_name(inv, "web-1")["parent"] == proj["id"]
    assert by_name(inv, "shop-assets")["parent"] == proj["id"]          # bucket: placed via ancestors only
    vpc = by_name(inv, "prod-vpc")
    assert by_name(inv, "web-eu")["parent"] == vpc["id"] and by_name(inv, "allow-web")["parent"] == vpc["id"]
    assert sum(1 for n in inv.nodes.values() if n["kind"] == "account") == 1   # number and id unified


def test_relationships():
    _, inv = build_demo()
    e = edges(inv)
    web1, bastion = by_name(inv, "web-1")["id"], by_name(inv, "bastion")["id"]
    assert (web1, by_name(inv, "web-eu")["id"], "attached_to") in e
    assert (web1, by_name(inv, "app-sa@shop-prod.iam.gserviceaccount.com")["id"], "assumes") in e
    ssh, web_fw, ftp = (by_name(inv, n)["id"] for n in ("allow-ssh-world", "allow-web", "allow-legacy-ftp"))
    assert all((by_name(inv, v)["id"], ssh, "uses") in e for v in ("web-1", "web-2", "worker-1", "bastion"))  # no target = all
    assert (web1, web_fw, "uses") in e and (bastion, web_fw, "uses") not in e        # target tag 'web'
    assert not any(t == ftp for _, t, _ in e)                                         # targets 'legacy': nothing has it
    fr, bs, ig = (by_name(inv, n)["id"] for n in ("web-fr", "web-bs", "web-ig"))
    assert (fr, bs, "routes_to") in e and (bs, ig, "routes_to") in e
    assert (by_name(inv, "reporting-db")["id"], by_name(inv, "prod-vpc")["id"], "attached_to") in e
    assert (by_name(inv, "gke-prod")["id"], by_name(inv, "web-eu")["id"], "attached_to") in e
    fn_sa = by_name(inv, "fn-sa@shop-prod.iam.gserviceaccount.com")["id"]
    assert (by_name(inv, "thumbnailer")["id"], fn_sa, "assumes") in e and (by_name(inv, "report-gen")["id"], fn_sa, "assumes") in e
    assert (by_name(inv, "api")["id"], by_name(inv, "app-sa@shop-prod.iam.gserviceaccount.com")["id"], "assumes") in e


def test_exposure():
    _, inv = build_demo()
    assert by_name(inv, "allow-ssh-world")["props"]["world_open_ports"] == ["22"]
    assert by_name(inv, "allow-web")["props"]["world_open_ports"] == ["80", "443"]
    assert "world_open_ports" not in by_name(inv, "allow-icmp").get("props", {})      # ICMP has no ports
    assert by_name(inv, "orders-db")["props"]["world_open_ports"] == ["5432"]         # 0.0.0.0/0 authorised network
    assert "world_open_ports" not in by_name(inv, "reporting-db").get("props", {})
    assert by_name(inv, "orders-db")["props"]["multi_az"] is False and by_name(inv, "reporting-db")["props"]["multi_az"] is True

    f = gcp.firewall_open_ports
    assert f({"sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "all"}]}) == ["all"]
    assert f({"sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp"}]}) == ["all"]
    assert f({"sourceRanges": ["10.0.0.0/8"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}) == []
    assert f({"sourceRanges": ["0.0.0.0/0"], "disabled": True, "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}) == []
    assert f({"sourceRanges": ["0.0.0.0/0"], "direction": "EGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}) == []
    assert f({"sourceRanges": ["::/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["8000-8100"]}]}) == ["8000-8100"]


def test_zones_become_regions_and_names_normalise():
    _, inv = build_demo()
    regions = analyze(inv)["stats"]["regions"]
    assert "europe-west1" in regions and not any(r.endswith(("-b", "-c", "-d")) for r in regions)
    assert gcp.region_of("europe-west1-b") == "europe-west1" and gcp.region_of("EU") == "EU" and gcp.region_of("global") is None
    assert gcp.norm("//compute.googleapis.com/projects/p/zones/z/instances/I") == "projects/p/zones/z/instances/i"
    assert gcp.norm("https://www.googleapis.com/compute/v1/projects/p/global/networks/N") == "projects/p/global/networks/n"
    assert gcp.norm("//storage.googleapis.com/my-bucket") == "my-bucket"


def test_secrets_are_never_collected():
    em, _ = build_demo()
    blob = "\n".join(json.dumps(r) for r in em.records())
    assert "DEMO-SECRET-NOT-COLLECTED" not in blob and "startup-script" not in blob and "API_KEY" not in blob


def test_project_scoped_scan_without_scope_assets():
    """Scanning --project may not return the Project/Folder/Org assets themselves."""
    only_resources = [a for a in demo_rows.gcp_assets() if not a["assetType"].startswith("cloudresourcemanager")]
    _, inv = build_demo(only_resources)
    assert not inv.warnings
    projects = [n for n in inv.nodes.values() if n["kind"] == "account"]
    assert [p["id"] for p in projects] == ["gcp:project:shop-prod"]            # id from paths, not the number
    assert by_name(inv, "shop-assets")["parent"] == "gcp:project:shop-prod"


def test_insights_for_gcp_demo():
    _, inv = build_demo()
    ins = analyze(inv)
    by = {f["id"]: f for f in ins["findings"]}
    assert by["exposed-ports"]["severity"] == "high" and by["exposed-ports"]["title"].startswith("2 resources let")
    assert any("orders-db: 5432" in d for d in by["exposed-ports"]["details"])
    assert {"single-az", "shared-role-app-sa-shop-prod-iam-gserviceaccount-com", "orphan-sg", "unused-roles"} <= set(by)
    assert "firewall rule" in by["orphan-sg"]["title"] and "labels" in by["untagged"]["title"]
    assert "1 project" in ins["headline"]


# ---- the SDK-facing layer, with real protobuf objects --------------------------------
def to_proto(asset_dict):
    from google.cloud import asset_v1
    from google.protobuf import json_format
    return asset_v1.Asset.wrap(json_format.ParseDict(asset_dict, asset_v1.Asset.pb(asset_v1.Asset())))


class FakeAssetClient:
    def __init__(self, assets, error=None):
        self.assets, self.error, self.request = assets, error, None

    def list_assets(self, request):
        self.request = request
        if self.error:
            raise self.error
        return iter([to_proto(a) for a in self.assets])


def test_fetch_converts_real_asset_objects_and_builds():
    pytest.importorskip("google.cloud.asset_v1")
    from google.cloud import asset_v1
    client = FakeAssetClient(demo_rows.gcp_assets())
    em = Emitter("gcp", "t")
    gcp.scan(em, "projects/shop-prod", client=client)
    req = client.request
    assert req.parent == "projects/shop-prod" and req.content_type == asset_v1.ContentType.RESOURCE
    assert list(req.asset_types) == gcp.ASSET_TYPES and req.page_size == 1000
    inv = Inventory.load(json.dumps(r) for r in em.records())
    assert not inv.warnings and len(inv.nodes) > 25
    assert by_name(inv, "orders-db")["props"]["world_open_ports"] == ["5432"]          # survived proto round trip


def test_fetch_failure_explains_what_to_do():
    pytest.importorskip("google.cloud.asset_v1")
    with pytest.raises(SystemExit) as e:
        gcp.scan(Emitter("gcp", "t"), "organizations/1", client=FakeAssetClient([], error=PermissionError("403")))
    msg = str(e.value)
    assert "cloudasset.viewer" in msg and "organizations/1" in msg


def test_cli_scopes_and_demo(tmp_path, capsys):
    assert cli.main(["scan", "--provider", "gcp", "--out", str(tmp_path)]) == 2          # no scope given
    assert "--project" in capsys.readouterr().err
    assert cli.main(["scan", "--provider", "gcp", "--demo", "--out", str(tmp_path), "--scan-id", "g1", "--quiet"]) == 0
    assert Inventory.load_path(next(tmp_path.glob("gcp-g1-*.jsonci"))).meta["provider"] == "gcp"
