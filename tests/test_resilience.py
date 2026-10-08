"""What happens when the real world is messier than the demo: missing packages, odd resources, old SDKs."""
import ast
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from cloudmap_portal.scanners import azure, demo_rows, gcp
from cloudmap_portal.scanners.base import Emitter
from cloudmap_portal.schema import Inventory

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 6, 9, 0, tzinfo=timezone.utc)


# ---- packaging: every optional import must be installable through an extra -----------------------
def extras():
    tomllib = pytest.importorskip("tomllib")                    # Python 3.11+
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]
    norm = lambda spec: re.split(r"[<>=!~\[ ]", spec, maxsplit=1)[0].lower().replace("_", "-")   # noqa: E731
    return {k: {norm(s) for s in v} for k, v in meta.items()}


# top-level import -> the pip package that provides it, per scanner
PROVIDES = {"boto3": "boto3", "azure.identity": "azure-identity", "azure.mgmt.resourcegraph": "azure-mgmt-resourcegraph",
            "azure.mgmt.keyvault": "azure-mgmt-keyvault", "azure.mgmt.web": "azure-mgmt-web",
            "google.cloud": "google-cloud-asset", "google.protobuf": "google-cloud-asset"}


@pytest.mark.parametrize("scanner,extra", [("aws.py", "aws"), ("azure.py", "azure"), ("gcp.py", "gcp")])
def test_every_optional_import_is_in_the_extra(scanner, extra):
    """The bug that reached a real user: the code imported azure.mgmt.keyvault, the extra did not install it."""
    tree = ast.parse((ROOT / "cloudmap_portal" / "scanners" / scanner).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    third_party = {m for m in imported if m.split(".")[0] in ("boto3", "azure", "google")}
    needed = set()
    for m in third_party:
        key = next((k for k in sorted(PROVIDES, key=len, reverse=True) if m == k or m.startswith(k + ".")), None)
        assert key, f"{scanner} imports {m}, which this test does not know how to map to a package: add it to PROVIDES"
        needed.add(PROVIDES[key])
    assert needed <= extras()[extra], f"extra [{extra}] is missing {needed - extras()[extra]}"
    assert needed <= extras()["all"] | extras()[extra]


def test_azure_scanner_declares_the_key_vault_packages_it_checks_for():
    assert set(azure.KEYVAULT_PACKAGES.values()) <= extras()["azure"]


# ---- a missing optional package must not throw away a scan ---------------------------------------
class FakeGraph:
    def __init__(self, rows, containers):
        self.pages = {("Resources", None): (rows, None), ("ResourceContainers", None): (containers, None),
                      ("AuthorizationResources", None): ([], None)}

    def resources(self, req):
        data, token = self.pages[(req.query.split("\n")[0], req.options.skip_token)]
        return SimpleNamespace(data=data, skip_token=token)


def test_missing_key_vault_sdk_finishes_the_scan_and_says_how_to_fix_it(monkeypatch):
    monkeypatch.setattr(azure, "_missing_keyvault_sdk", lambda: ["azure-mgmt-keyvault", "azure-mgmt-web"])
    containers, rows, _ = demo_rows.azure_data(NOW)
    em, said = Emitter("azure", "t"), []
    azure.scan(em, client=FakeGraph(rows, containers), progress=said.append)          # must not raise or exit
    inv = Inventory.load(json.dumps(r) for r in em.records())
    assert len(inv.nodes) == 35 and not inv.warnings                                  # everything except the 10 vault items was kept
    err = next(e for e in inv.errors if e["scope"] == "keyvault")
    assert "pip install azure-mgmt-keyvault azure-mgmt-web" in err["message"] and "--skip-keyvault" in err["message"]
    assert any("WARNING" in m and "azure-mgmt-keyvault" in m for m in said)             # said up front, not after minutes
    assert not any(n["kind"] in ("iam.secret", "iam.key") for n in inv.nodes.values())
    assert any(e["rel"] == "can_access" for e in inv.edges)                             # access policies need no extra package


def test_an_explicit_source_skips_the_package_check(monkeypatch):
    monkeypatch.setattr(azure, "_missing_keyvault_sdk", lambda: ["azure-mgmt-keyvault"])
    containers, rows, kv = demo_rows.azure_data(NOW)
    src = SimpleNamespace(secrets=lambda *a: [], keys=lambda *a: [], app_references=lambda *a: [])
    em = Emitter("azure", "t")
    azure.scan(em, client=FakeGraph(rows, containers), kv_source=src)
    assert not [e for e in em._errors if e["scope"] == "keyvault"]


def test_the_package_check_really_looks_at_the_environment():
    assert isinstance(azure._missing_keyvault_sdk(), list)


# ---- one odd resource must not take the scan down with it ----------------------------------------
def test_azure_resource_with_an_unexpected_shape_is_reported_not_fatal():
    containers, rows, kv = demo_rows.azure_data(NOW)
    vnet = next(r for r in rows if r["type"] == "microsoft.network/virtualnetworks")
    vnet["properties"]["subnets"] = [{"name": "no-id-here"}]                           # real data does this occasionally
    em = Emitter("azure", "t")
    azure.build(em, containers, rows, kv)
    inv = Inventory.load(json.dumps(r) for r in em.records())
    err = next(e for e in inv.errors if e["scope"] == "mapping/microsoft.network/virtualnetworks")
    assert "1 resource(s) could not be mapped" in err["message"] and "KeyError" in err["message"]
    assert any(n["name"] == "vm-web1" for n in inv.nodes.values())                     # the rest is intact


def test_gcp_asset_with_an_unexpected_shape_is_reported_not_fatal():
    assets = demo_rows.gcp_assets()
    next(a for a in assets if a["assetType"].endswith("/Instance"))["resource"]["data"].pop("name")
    em = Emitter("gcp", "t")
    gcp.build(em, assets)
    inv = Inventory.load(json.dumps(r) for r in em.records())
    assert any(e["scope"] == "mapping/compute.googleapis.com/Instance" for e in inv.errors)
    assert any(n["name"] == "web-2" for n in inv.nodes.values())


# ---- both SDK generations ---------------------------------------------------------------------------
def test_reference_reader_accepts_the_older_flattened_model_shape():
    old = SimpleNamespace(name="DB_CONN", vault_name="kv-prod", secret_name="db", secret_version="v1",
                          status="Resolved", identity_type="SystemAssigned")          # no .properties
    new = SimpleNamespace(name="DB_CONN", properties=SimpleNamespace(vault_name="kv-prod", secret_name="db",
                          secret_version="v1", status="Resolved", identity_type="SystemAssigned"))
    assert azure.reference_item("/app", old) == azure.reference_item("/app", new)
    assert azure.reference_item("/app", old)["vault"] == "kv-prod"
