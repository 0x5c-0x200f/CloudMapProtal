"""Azure: the row->inventory mapping, plus the Resource Graph fetch layer via an SDK-shaped fake."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from cloudmap_portal import cli
from cloudmap_portal.insights import analyze
from cloudmap_portal.scanners import azure, demo, demo_rows
from cloudmap_portal.scanners.base import Emitter
from cloudmap_portal.schema import Inventory


NOW = datetime(2026, 10, 6, 9, 0, tzinfo=timezone.utc)


def build_demo():
    em = Emitter("azure", "t1", scanned_at="2026-10-06T09:00:00Z")
    containers, rows, kv = demo_rows.azure_data(NOW)
    azure.build(em, containers, rows, kv)
    return em, Inventory.load(json.dumps(r) for r in em.records())


def by_name(inv, name, kind=None):
    return next(n for n in inv.nodes.values() if n["name"] == name and (kind is None or n["kind"] == kind))


def edges(inv):
    return {(e["from"], e["to"], e["rel"]) for e in inv.edges}


def test_hierarchy_and_clean_import():
    _, inv = build_demo()
    assert not inv.warnings and not inv.errors
    sub, rg = by_name(inv, "Contoso Production"), by_name(inv, "rg-web")
    mg, root = by_name(inv, "Production"), by_name(inv, "Tenant Root Group")
    assert sub["kind"] == "account" and sub["parent"] == mg["id"] and mg["parent"] == root["id"] and root["parent"] is None
    assert rg["kind"] == "resource_group" and rg["parent"] == sub["id"]
    assert by_name(inv, "vm-web1")["parent"] == rg["id"]
    vnet = by_name(inv, "vnet-prod")
    assert by_name(inv, "snet-web")["parent"] == vnet["id"]
    server = by_name(inv, "sql-prod")
    assert by_name(inv, "orders")["parent"] == server["id"]            # database lives inside its server
    assert not any(n["name"] == "master" for n in inv.nodes.values())  # system database skipped


def test_relationships_resolve_across_mixed_case_ids():
    _, inv = build_demo()
    e = edges(inv)
    vm, nic, snet = by_name(inv, "vm-web1")["id"], by_name(inv, "nic-web1")["id"], by_name(inv, "snet-web")["id"]
    assert (vm, nic, "uses") in e and (nic, snet, "attached_to") in e
    assert (snet, by_name(inv, "nsg-web")["id"], "uses") in e
    assert (vm, by_name(inv, "id-app")["id"], "assumes") in e           # identity key is UPPERCASE in the fixture
    lb = by_name(inv, "lb-web")["id"]
    assert (lb, vm, "routes_to") in e and (lb, by_name(inv, "vm-web2")["id"], "routes_to") in e   # via the NIC
    assert (lb, by_name(inv, "pip-lb")["id"], "uses") in e
    assert (by_name(inv, "app-api")["id"], by_name(inv, "plan-prod")["id"], "runs_on") in e
    assert (by_name(inv, "pg-analytics")["id"], by_name(inv, "snet-data")["id"], "attached_to") in e
    assert by_name(inv, "lb-web")["props"]["scheme"] == "internet-facing"
    assert by_name(inv, "func-etl")["kind"] == "compute.function" and by_name(inv, "app-api")["kind"] == "compute.app"


def test_nsg_exposure_and_precedence():
    _, inv = build_demo()
    assert by_name(inv, "nsg-web")["props"]["world_open_ports"] == ["22", "443"]
    assert "world_open_ports" not in by_name(inv, "nsg-app").get("props", {})   # VNet-only allow + internet deny

    def rule(prio, access, port="22", src="Internet"):
        return {"properties": {"direction": "Inbound", "access": access, "priority": prio,
                               "sourceAddressPrefix": src, "destinationPortRange": port}}
    assert azure.nsg_open_ports([rule(200, "Allow"), rule(100, "Deny")]) == []            # deny wins (lower number)
    assert azure.nsg_open_ports([rule(100, "Allow"), rule(200, "Deny")]) == ["22"]        # allow wins
    assert azure.nsg_open_ports([rule(100, "Allow", "*")]) == ["all"]
    assert azure.nsg_open_ports([{"properties": {"direction": "Inbound", "access": "Allow", "priority": 1,
                                                 "sourceAddressPrefixes": ["10.0.0.0/8", "0.0.0.0/0"],
                                                 "destinationPortRanges": ["3306", "5432"]}}]) == ["3306", "5432"]
    assert azure.nsg_open_ports([rule(100, "Allow", src="VirtualNetwork")]) == []


def test_secrets_are_never_collected():
    em, _ = build_demo()
    blob = "\n".join(json.dumps(r) for r in em.records())
    assert "DEMO-SECRET-NOT-COLLECTED" not in blob and "adminPassword" not in blob and "azureuser" not in blob


def test_unmapped_types_are_reported_not_hidden():
    em, inv = build_demo()
    assert inv.meta["scope"]["unmapped"] == {"microsoft.compute/disks": 3, "microsoft.insights/components": 1}
    ids = {f["id"] for f in analyze(inv)["findings"]}
    assert "unmapped-types" in ids
    containers, rows, _ = demo_rows.azure_data(NOW)    # extensions are noise: ignored, not "unmapped"
    rows.append({"id": rows[0]["id"] + "/extensions/x", "name": "x", "type": "microsoft.compute/virtualmachines/extensions",
                 "subscriptionId": rows[0]["subscriptionId"], "resourceGroup": "rg-web", "properties": {}})
    em2 = Emitter("azure", "t"); azure.build(em2, containers, rows)
    assert "microsoft.compute/virtualmachines/extensions" not in str(em2.scope.get("unmapped"))


def test_scope_is_synthesised_when_containers_are_unreadable():
    em = Emitter("azure", "t")
    _, rows, _ = demo_rows.azure_data(NOW)
    azure.build(em, [], rows)                           # no subscription/RG names available
    inv = Inventory.load(json.dumps(r) for r in em.records())
    assert not inv.warnings
    assert any(n["kind"] == "account" for n in inv.nodes.values()) and any(n["kind"] == "resource_group" for n in inv.nodes.values())


def test_insights_for_azure_demo():
    _, inv = build_demo()
    ins = analyze(inv)
    by = {f["id"]: f for f in ins["findings"]}
    assert by["exposed-ports"]["severity"] == "high" and by["exposed-ports"]["title"].startswith("1 network security group lets")
    assert {"public-blobs", "single-az", "shared-role-id-app", "orphan-sg"} <= set(by)
    assert "1 subscription" in ins["headline"] and "1 region" in ins["headline"]


# ---- the SDK-facing layer, with an SDK-shaped fake ----------------------------------
class FakeGraph:
    def __init__(self, pages=None, fail_on=None):
        self.pages, self.requests, self.fail_on = pages or {}, [], fail_on

    def resources(self, req):
        self.requests.append(req)
        if self.fail_on and self.fail_on in req.query:
            raise PermissionError("AuthorizationFailed")
        key = (req.query.split("\n")[0], req.options.skip_token)
        data, token = self.pages[key]
        return SimpleNamespace(data=data, skip_token=token)


def test_fetch_pages_through_resource_graph():
    pytest.importorskip("azure.mgmt.resourcegraph")
    from azure.mgmt.resourcegraph.models import QueryRequest
    containers, rows, _ = demo_rows.azure_data(NOW)
    client = FakeGraph({("Resources", None): (rows[:10], "tok1"), ("Resources", "tok1"): (rows[10:], None),
                        ("ResourceContainers", None): (containers, None)})
    em = Emitter("azure", "t")
    azure.scan(em, subscriptions=["sub-a"], client=client, keyvault=False)
    assert all(isinstance(r, QueryRequest) and r.subscriptions == ["sub-a"] and r.options.top == 1000 for r in client.requests)
    assert [r.options.skip_token for r in client.requests if r.query.startswith("Resources")] == [None, "tok1"]
    inv = Inventory.load(json.dumps(r) for r in em.records())
    assert len(inv.nodes) > 25 and not inv.warnings


def test_fetch_failures_are_clear_or_degrade():
    containers, rows, _ = demo_rows.azure_data(NOW)
    with pytest.raises(SystemExit) as e:                                 # can't read resources: stop, say why
        azure.scan(Emitter("azure", "t"), client=FakeGraph(fail_on="Resources\n"), keyvault=False)
    assert "Reader" in str(e.value)
    pages = {("Resources", None): (rows, None)}                          # can't read names: keep going
    em = Emitter("azure", "t")
    azure.scan(em, client=FakeGraph(pages, fail_on="ResourceContainers"), keyvault=False)
    inv = Inventory.load(json.dumps(r) for r in em.records())
    assert any(e["scope"] == "resourcecontainers" for e in inv.errors) and len(inv.nodes) > 25


def test_cli_demo_scan(tmp_path, capsys):
    assert cli.main(["scan", "--provider", "azure", "--demo", "--out", str(tmp_path), "--scan-id", "az1", "--quiet"]) == 0
    f = next(tmp_path.glob("azure-az1-*.jsonci"))
    assert Inventory.load_path(f).meta["provider"] == "azure"
