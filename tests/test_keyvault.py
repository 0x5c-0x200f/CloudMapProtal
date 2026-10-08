"""Key Vault: items, access, usage, findings, and the guarantee that values are never read."""
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
SUB = demo_rows.SUB
KVP = f"/subscriptions/{SUB}/resourceGroups/rg-web/providers/Microsoft.KeyVault/vaults/kv-prod"
KVS = f"/subscriptions/{SUB}/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-shared"


def build(kv="demo", mutate=None):
    containers, rows, demo_kv = demo_rows.azure_data(NOW)
    kv = demo_kv if kv == "demo" else kv
    if mutate:
        mutate(rows, kv)
    em = Emitter("azure", "t1", scanned_at="2026-10-06T09:00:00Z")
    azure.build(em, containers, rows, kv)
    return em, Inventory.load(json.dumps(r) for r in em.records())


def node(inv, name, kind=None):
    return next(n for n in inv.nodes.values() if n["name"] == name and (kind is None or n["kind"] == kind))


def edges(inv):
    return {(inv.nodes[e["from"]]["name"], inv.nodes[e["to"]]["name"], e["rel"]) for e in inv.edges}


def edge(inv, a, b, rel):
    return next(e for e in inv.edges if inv.nodes[e["from"]]["name"] == a and inv.nodes[e["to"]]["name"] == b and e["rel"] == rel)


# ---- items ------------------------------------------------------------------
def test_items_sit_inside_their_vault_with_status_only():
    _, inv = build()
    assert not inv.warnings
    vault = node(inv, "kv-prod", "iam.vault")
    kinds = {n["name"]: n["kind"] for n in inv.nodes.values() if n.get("parent") == vault["id"]}
    assert kinds == {"db-conn-string": "iam.secret", "api-key": "iam.secret", "stripe-key": "iam.secret", "old-token": "iam.secret",
                     "tls-cert": "iam.certificate", "cmk-storage": "iam.key", "cmk-sql": "iam.key", "legacy-password": "iam.secret"}
    assert node(inv, "shared-token")["parent"] == node(inv, "kv-shared")["id"]
    p = node(inv, "cmk-storage")["props"]
    assert p["key_type"] == "RSA" and p["key_size"] == 3072 and p["expires"].startswith("2027")
    assert node(inv, "tls-cert")["props"]["stored_as"] == "secret"          # a PKCS12 secret is shown as a certificate
    assert node(inv, "old-token")["props"]["enabled"] is False


def test_a_reference_to_a_secret_that_does_not_exist_is_shown_as_missing():
    _, inv = build()
    ghost = node(inv, "legacy-password")
    assert ghost["props"] == {"missing": True} and ghost["parent"] == node(inv, "kv-prod")["id"]
    assert edge(inv, "func-etl", "legacy-password", "reads_secret")["status"] == "SecretNotFound"


def test_but_not_if_we_could_not_list_the_vault():
    """Absence only means 'missing' when we actually listed the vault. Otherwise link to the vault, don't accuse."""
    def unlisted(rows, kv):
        kv["listed_secrets"] = [KVS]                                        # kv-prod could not be listed
        kv["items"] = [i for i in kv["items"] if i["vault_id"] == KVS]
    _, inv = build(mutate=unlisted)
    assert not any(n["name"] == "legacy-password" for n in inv.nodes.values())
    e = edge(inv, "func-etl", "kv-prod", "uses")
    assert "secret legacy-password" in e["label"] and "secret old-token" in e["label"]   # both reads, one link
    assert e["status"] == "SecretNotFound"                                               # and the failure is kept


# ---- usage ------------------------------------------------------------------
def test_apps_reading_secrets_and_their_status():
    _, inv = build()
    e = edge(inv, "app-api", "db-conn-string", "reads_secret")
    assert e["label"] == "DB_CONN" and e["status"] == "Resolved"
    assert edge(inv, "func-etl", "shared-token", "reads_secret")["status"] == "ForbiddenByFirewall"
    assert {n for n, _, r in edges(inv) if r == "reads_secret"} == {"app-api", "func-etl"}


def test_two_settings_reading_one_secret_merge_instead_of_overwrite():
    def twice(rows, kv):
        kv["refs"].append({"app_id": kv["refs"][0]["app_id"], "setting": "DB_CONN_BACKUP", "vault": "kv-prod", "secret": "db-conn-string", "status": "InitialFetchFailed"})
    _, inv = build(mutate=twice)
    e = edge(inv, "app-api", "db-conn-string", "reads_secret")
    assert "DB_CONN" in e["label"] and "DB_CONN_BACKUP" in e["label"]
    assert e["status"] == "InitialFetchFailed"                              # a failure is never hidden by a success


def test_customer_managed_keys_for_every_supported_resource():
    def more(rows, kv):
        key = lambda n: f"https://kv-prod.vault.azure.net/keys/{n}/v1"   # noqa: E731
        rg = lambda t, n: f"/subscriptions/{SUB}/resourceGroups/rg-data/providers/{t}/{n}"   # noqa: E731
        rows.append({"id": rg("Microsoft.Compute/diskEncryptionSets", "des-1"), "name": "des-1", "type": "microsoft.compute/diskencryptionsets",
                     "resourceGroup": "rg-data", "subscriptionId": SUB, "location": "westeurope", "properties": {"activeKey": {"keyUrl": key("cmk-sql")}}})
        aks = next(r for r in rows if r["name"] == "aks-prod")
        aks["properties"]["securityProfile"] = {"azureKeyVaultKms": {"enabled": True, "keyId": key("cmk-storage")}}
    _, inv = build(mutate=more)
    e = edges(inv)
    assert ("stassets", "cmk-storage", "encrypted_with") in e and ("pg-analytics", "cmk-sql", "encrypted_with") in e
    assert ("des-1", "cmk-sql", "encrypted_with") in e and ("aks-prod", "cmk-storage", "encrypted_with") in e
    assert node(inv, "des-1")["kind"] == "iam.encryption_set"


# ---- access -----------------------------------------------------------------
def test_access_policies_become_relationships_with_permissions():
    _, inv = build()
    e = edge(inv, "func-etl", "kv-prod", "can_access")
    assert e["access"] == ["secrets:delete", "secrets:get", "secrets:list", "secrets:set"] or set(e["access"]) == {"secrets:get", "secrets:list", "secrets:set", "secrets:delete"}
    assert edge(inv, "id-app", "kv-prod", "can_access")["label"] == "secrets: get, list"
    assert ("aks-prod", "kv-prod", "can_access") in edges(inv)              # system-assigned identity found via principal id
    assert node(inv, "kv-prod")["props"]["other_principals"] == 1           # a person, outside the scan


def test_rbac_assignments_reach_only_rbac_vaults_in_scope():
    _, inv = build()
    e = edge(inv, "id-app", "kv-shared", "can_access")
    assert e["label"] == "Key Vault Secrets User" and e["access"] == ["secrets:get"]
    assert node(inv, "kv-shared")["props"]["other_principals"] == 1         # the admin assigned at resource-group scope

    def wide(rows, kv):                                                     # same role, assigned for the whole subscription
        kv["assignments"] = [{"principalId": "p-func", "scope": f"/subscriptions/{SUB}", "roleDefinitionId": "/x/roleDefinitions/00482a5a-887f-4fb3-b363-3b7fe8e74483"},
                             {"principalId": "p-aks", "scope": KVS, "roleDefinitionId": "/x/roleDefinitions/not-a-keyvault-role"}]
    _, inv = build(mutate=wide)
    assert edge(inv, "func-etl", "kv-shared", "can_access")["label"] == "Key Vault Administrator"
    assert ("aks-prod", "kv-shared", "can_access") not in edges(inv)        # unknown role: ignored
    assert node(inv, "kv-prod")["props"]["other_principals"] == 1           # access-policy vault ignores RBAC assignments


def test_skipping_key_vault_keeps_the_access_relationships_that_live_on_the_vault():
    _, inv = build(kv=None)
    assert not any(n["kind"] in ("iam.secret", "iam.key", "iam.certificate") for n in inv.nodes.values())
    assert ("id-app", "kv-prod", "can_access") in edges(inv)
    assert not any(r == "reads_secret" for *_, r in edges(inv))


# ---- the guarantee ------------------------------------------------------------
PLANTED = "PLANTED-SECRET-VALUE-0xDEADBEEF"


def sdk_fakes():
    pytest.importorskip("azure.mgmt.keyvault")
    from azure.mgmt.keyvault.models import Key, Secret
    from azure.mgmt.web.models import ApiKVReference
    secret = lambda n, **p: Secret({"name": n, "properties": {"value": PLANTED, "contentType": "text/plain", "attributes": {"enabled": True, "exp": 1893456000}, **p}})  # noqa: E731
    key = lambda n: Key({"name": n, "properties": {"kty": "RSA", "keySize": 3072, "attributes": {"enabled": True}, "keyUri": f"https://x/keys/{n}"}})
    ref = lambda setting, vault, name, status: ApiKVReference({"name": setting, "properties": {   # noqa: E731
        "reference": f"@Microsoft.KeyVault(SecretUri=https://{vault}.vault.azure.net/secrets/{name}/)", "status": status,
        "vaultName": vault, "secretName": name, "secretVersion": "v1"}})
    kv = SimpleNamespace(secrets=SimpleNamespace(list=lambda rg, vault: [secret("db-conn-string"), secret("api-key")]),
                         keys=SimpleNamespace(list=lambda rg, vault: [key("cmk-storage")]))
    web = SimpleNamespace(web_apps=SimpleNamespace(get_app_settings_key_vault_references=lambda rg, app: [ref("DB_CONN", "kv-prod", "db-conn-string", "Resolved")]))
    return kv, web


class FakeGraph:
    def __init__(self, rows, containers, assignments=None, fail_assignments=False):
        self.pages = {("Resources", None): (rows, None), ("ResourceContainers", None): (containers, None),
                      ("AuthorizationResources", None): (assignments or [], None)}
        self.fail = fail_assignments

    def resources(self, req):
        if self.fail and req.query.startswith("AuthorizationResources"):
            raise PermissionError("AuthorizationFailed")
        data, token = self.pages[(req.query.split("\n")[0], req.options.skip_token)]
        return SimpleNamespace(data=data, skip_token=token)


def scan_with(source, *, fail_assignments=False, keyvault=True):
    containers, rows, kv = demo_rows.azure_data(NOW)
    em = Emitter("azure", "t1", scanned_at="2026-10-06T09:00:00Z")
    azure.scan(em, client=FakeGraph(rows, containers, kv["assignments"], fail_assignments), kv_source=source, keyvault=keyvault)
    return em, Inventory.load(json.dumps(r) for r in em.records())


def test_secret_values_never_reach_the_file_even_when_the_sdk_returns_them():
    kv, web = sdk_fakes()
    em, inv = scan_with(azure.SdkKeyVaultSource(kv_client=lambda sub: kv, web_client=lambda sub: web))
    blob = "\n".join(json.dumps(r) for r in em.records())
    assert PLANTED not in blob and "0xDEADBEEF" not in blob and '"value"' not in blob
    assert "@Microsoft.KeyVault" not in blob                                # not even the reference text, only its parts
    assert node(inv, "db-conn-string")["props"]["enabled"] is True          # ...but the metadata is there
    assert edge(inv, "app-api", "db-conn-string", "reads_secret")["label"] == "DB_CONN"


def test_normalisers_take_only_named_fields():
    kv, web = sdk_fakes()
    for item in (azure.secret_item("/v", kv.secrets.list("r", "v")[0]), azure.key_item("/v", kv.keys.list("r", "v")[0])):
        assert PLANTED not in json.dumps(item) and "value" not in item and "key_material" not in item
    assert azure.reference_item("/a", next(iter(web.web_apps.get_app_settings_key_vault_references("r", "a"))))["status"] == "Resolved"


# ---- failures ---------------------------------------------------------------
def test_permission_gaps_become_one_clear_error_each_not_a_flood():
    kv, web = sdk_fakes()

    def denied(rg, vault):
        raise PermissionError("AuthorizationFailed")
    listing = kv.secrets.list
    kv.secrets.list = lambda rg, vault: denied(rg, vault) if vault == "kv-shared" else listing(rg, vault)
    web.web_apps.get_app_settings_key_vault_references = lambda rg, app: denied(rg, app)
    em, inv = scan_with(azure.SdkKeyVaultSource(kv_client=lambda sub: kv, web_client=lambda sub: web), fail_assignments=True)
    by_scope = {e["scope"]: e["message"] for e in inv.errors}
    assert set(by_scope) == {"keyvault/secrets", "keyvault/app-references", "keyvault/role-assignments"}
    assert "1 of 2" in by_scope["keyvault/secrets"] and "2 of 2" in by_scope["keyvault/app-references"]
    assert "missing from the map" in by_scope["keyvault/app-references"]
    assert "keyvault/keys" not in by_scope                                  # keys listed fine
    assert len(inv.nodes) > 25 and not inv.warnings                         # the rest of the scan is intact


# ---- findings ---------------------------------------------------------------
def findings(inv):
    return {f["id"]: f for f in analyze(inv)["findings"]}


def test_findings_on_the_demo():
    _, inv = build()
    f = findings(inv)
    assert f["kv-expired"]["severity"] == "high" and "api-key in kv-prod: expired 12 days ago, used by app-api" in f["kv-expired"]["details"]
    assert f["kv-expiring"]["details"] == ["tls-cert in kv-prod: expires in 18 days"]
    assert f["kv-broken-refs"]["severity"] == "high" and len(f["kv-broken-refs"]["details"]) == 2
    assert f["kv-unusable"]["severity"] == "high" and f["kv-unusable"]["count"] >= 3    # old-token, legacy-password and func-etl
    assert set(f["kv-writers"]["details"]) == {"func-etl on kv-prod: secrets set, secrets delete",
                                               "mi-automation on kv-shared: secrets *"}              # a role that can write counts too
    assert {n.split(" in ")[0] for n in f["kv-no-expiry"]["details"]} == {"stripe-key", "cmk-sql", "legacy-service-key"}
    assert f["kv-purge"]["count"] == 1 and f["kv-public"]["count"] == 1                 # kv-shared only
    assert [x["severity"] for x in analyze(inv)["findings"]][0] == "high"


def test_an_expired_secret_nobody_uses_is_less_urgent():
    def unused(rows, kv):
        kv["refs"] = [r for r in kv["refs"] if r["secret"] != "api-key"]
    _, inv = build(mutate=unused)
    assert findings(inv)["kv-expired"]["severity"] == "medium"


def test_no_key_vault_findings_without_a_key_vault():
    em = Emitter("aws", "t"); demo.scan(em)
    inv = Inventory.load(json.dumps(r) for r in em.records())
    assert not [f for f in findings(inv) if f.startswith("kv-")]


def test_cli_and_policy_mention_key_vault(tmp_path, capsys):
    assert cli.main(["scan", "--provider", "azure", "--demo", "--skip-keyvault", "--out", str(tmp_path), "--scan-id", "k1", "--quiet"]) == 0
    capsys.readouterr()
    assert cli.main(["policy", "azure"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "secret values" in out["key_vault"]["never_reads"] and "--skip-keyvault" in out["key_vault"]["note"]
