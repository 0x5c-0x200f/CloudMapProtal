"""Synthetic Azure Resource Graph rows and GCP Cloud Asset assets, shaped like the real APIs.
They feed the real build() functions, so the demos exercise the actual mapping code.
Each contains deliberate issues (open SSH, a single-zone database, a shared identity...)."""
from __future__ import annotations

# =========================== Azure ===========================
SUB = "11111111-2222-3333-4444-555555555555"


def _rid(rg, rtype, *names):
    return f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/{rtype}/" + "/".join(names)


def _row(rg, rtype, name, props=None, loc="westeurope", tags=None, **extra):
    return {"id": _rid(rg, rtype, name), "name": name, "type": rtype.lower(), "location": loc,
            "resourceGroup": rg, "subscriptionId": SUB, "tags": tags, "properties": props or {}, **extra}


def azure_data(now=None):
    """-> (containers, rows, kv). `now` anchors expiry dates so the demo always has one expired,
    one expiring and one healthy secret, whenever it is run."""
    from datetime import datetime, timedelta, timezone
    now = now or datetime.now(timezone.utc)
    when = lambda days: (now + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    W, D = "rg-web", "rg-data"
    prod = {"env": "prod", "owner": "platform"}
    vnet = "vnet-prod"
    subnet = lambda s: _rid(W, "Microsoft.Network/virtualNetworks", vnet, "subnets", s)  # noqa: E731
    nsg_id = lambda n: _rid(W, "Microsoft.Network/networkSecurityGroups", n)             # noqa: E731
    identity = _rid(W, "Microsoft.ManagedIdentity/userAssignedIdentities", "id-app")
    ident = {"type": "UserAssigned", "userAssignedIdentities": {identity.upper(): {"principalId": "p-id-app"}}}  # case differs on purpose
    mi_auto = _rid(W, "Microsoft.ManagedIdentity/userAssignedIdentities", "mi-automation")
    func_ident = {"type": "SystemAssigned, UserAssigned", "principalId": "p-func",
                  "userAssignedIdentities": {identity.upper(): {"principalId": "p-id-app"}, mi_auto: {"principalId": "p-mi-auto"}}}
    batch_ident = {"type": "UserAssigned", "userAssignedIdentities": {mi_auto: {"principalId": "p-mi-auto"}}}

    rule = lambda n, prio, src, port, access="Allow": {"name": n, "properties": {                          # noqa: E731
        "direction": "Inbound", "access": access, "priority": prio, "sourceAddressPrefix": src,
        "destinationPortRange": port, "protocol": "Tcp"}}

    rows = [
        _row(W, "Microsoft.Network/virtualNetworks", vnet, tags=prod, props={
            "addressSpace": {"addressPrefixes": ["10.20.0.0/16"]},
            "subnets": [
                {"id": subnet("snet-web"), "name": "snet-web", "properties": {"addressPrefix": "10.20.1.0/24", "networkSecurityGroup": {"id": nsg_id("nsg-web")}}},
                {"id": subnet("snet-app"), "name": "snet-app", "properties": {"addressPrefix": "10.20.2.0/24", "networkSecurityGroup": {"id": nsg_id("nsg-app")}}},
                {"id": subnet("snet-data"), "name": "snet-data", "properties": {"addressPrefix": "10.20.3.0/24"}}]}),
        _row(W, "Microsoft.Network/networkSecurityGroups", "nsg-web", tags=prod, props={"securityRules": [
            rule("https", 100, "Internet", "443"), rule("ssh-anywhere", 110, "*", "22")]}),
        _row(W, "Microsoft.Network/networkSecurityGroups", "nsg-app", tags=prod, props={"securityRules": [
            rule("from-vnet", 100, "VirtualNetwork", "8080"), rule("deny-ssh", 200, "Internet", "22", "Deny")]}),
        _row(W, "Microsoft.Network/networkSecurityGroups", "nsg-legacy", props={"securityRules": []}),
        _row(W, "Microsoft.Network/publicIPAddresses", "pip-lb", tags=prod, props={"ipAddress": "20.50.1.10"}, sku={"name": "Standard"}),
    ]
    for n, s in (("web1", "snet-web"), ("web2", "snet-web"), ("app1", "snet-app")):
        rows.append(_row(W, "Microsoft.Network/networkInterfaces", f"nic-{n}", props={
            "ipConfigurations": [{"properties": {"subnet": {"id": subnet(s)}}}],
            "networkSecurityGroup": {"id": nsg_id("nsg-web" if s == "snet-web" else "nsg-app")}}))
        rows.append(_row(W, "Microsoft.Compute/virtualMachines", f"vm-{n}", tags=prod if n != "app1" else None, zones=["1"],
                         identity=ident, props={
            "hardwareProfile": {"vmSize": "Standard_D2s_v5"}, "storageProfile": {"osDisk": {"osType": "Linux"}},
            "osProfile": {"computerName": f"vm-{n}", "adminUsername": "azureuser", "adminPassword": "DEMO-SECRET-NOT-COLLECTED"},
            "networkProfile": {"networkInterfaces": [{"id": _rid(W, "Microsoft.Network/networkInterfaces", f"nic-{n}")}]}}))
    rows += [
        _row(W, "Microsoft.Network/loadBalancers", "lb-web", tags=prod, sku={"name": "Standard"}, props={
            "frontendIPConfigurations": [{"properties": {"publicIPAddress": {"id": _rid(W, "Microsoft.Network/publicIPAddresses", "pip-lb")}}}],
            "backendAddressPools": [{"properties": {"backendIPConfigurations": [
                {"id": _rid(W, "Microsoft.Network/networkInterfaces", "nic-web1") + "/ipConfigurations/ipconfig1"},
                {"id": _rid(W, "Microsoft.Network/networkInterfaces", "nic-web2") + "/ipConfigurations/ipconfig1"}]}}]}),
        _row(W, "Microsoft.ManagedIdentity/userAssignedIdentities", "id-app", tags=prod, props={"principalId": "p-id-app"}),
        _row(W, "Microsoft.ManagedIdentity/userAssignedIdentities", "mi-automation", tags=prod, props={"principalId": "p-mi-auto"}),
        _row(W, "Microsoft.Network/networkInterfaces", "nic-batch", props={
            "ipConfigurations": [{"properties": {"subnet": {"id": subnet("snet-app")}}}], "networkSecurityGroup": {"id": nsg_id("nsg-app")}}),
        _row(W, "Microsoft.Compute/virtualMachines", "vm-batch", tags=prod, identity=batch_ident, zones=["2"], props={
            "hardwareProfile": {"vmSize": "Standard_D4s_v5"}, "storageProfile": {"osDisk": {"osType": "Linux"}},
            "networkProfile": {"networkInterfaces": [{"id": _rid(W, "Microsoft.Network/networkInterfaces", "nic-batch")}]}}),
        _row(W, "Microsoft.Web/serverFarms", "plan-prod", tags=prod, sku={"name": "P1v3", "tier": "PremiumV3"}),
        _row(W, "Microsoft.Web/sites", "app-api", kind="app,linux", identity=ident, tags=prod, props={
            "state": "Running", "httpsOnly": True, "serverFarmId": _rid(W, "Microsoft.Web/serverFarms", "plan-prod"),
            "virtualNetworkSubnetId": subnet("snet-app")}),
        _row(W, "Microsoft.Web/sites", "func-etl", kind="functionapp,linux", identity=func_ident, props={
            "state": "Running", "serverFarmId": _rid(W, "Microsoft.Web/serverFarms", "plan-prod")}),
        _row(W, "Microsoft.KeyVault/vaults", "kv-prod", tags=prod, props={
            "sku": {"name": "standard"}, "enablePurgeProtection": True, "networkAcls": {"defaultAction": "Deny"},
            "accessPolicies": [
                {"objectId": "p-id-app", "permissions": {"secrets": ["Get", "List"]}},
                {"objectId": "p-aks", "permissions": {"secrets": ["Get"]}},
                {"objectId": "p-mi-auto", "permissions": {"secrets": ["Get", "List"], "keys": ["Get"]}},
                {"objectId": "p-func", "permissions": {"secrets": ["Get", "List", "Set", "Delete"]}},    # a workload that can write
                {"objectId": "00000000-aaaa-bbbb-cccc-111111111111", "permissions": {"keys": ["All"], "secrets": ["All"]}}]}),  # a person
        _row(D, "Microsoft.KeyVault/vaults", "kv-shared", props={
            "sku": {"name": "standard"}, "enableRbacAuthorization": True, "networkAcls": {"defaultAction": "Allow"}}),
        _row(W, "Microsoft.ContainerService/managedClusters", "aks-prod", tags=prod, identity={"type": "SystemAssigned", "principalId": "p-aks"}, props={
            "kubernetesVersion": "1.29.4", "agentPoolProfiles": [{"count": 3, "vnetSubnetID": subnet("snet-app")}]}),
        _row(D, "Microsoft.Storage/storageAccounts", "stlogs", props={"supportsHttpsTrafficOnly": True, "allowBlobPublicAccess": True}, sku={"name": "Standard_LRS"}),
        _row(D, "Microsoft.Storage/storageAccounts", "stassets", tags=prod, props={"supportsHttpsTrafficOnly": True, "allowBlobPublicAccess": False,
            "encryption": {"keyvaultproperties": {"keyvaulturi": "https://kv-prod.vault.azure.net/", "keyname": "cmk-storage"}}},
            sku={"name": "Standard_ZRS"}),
        _row(D, "Microsoft.Sql/servers", "sql-prod", tags=prod, props={"version": "12.0", "publicNetworkAccess": "Disabled"}),
        _row(D, "Microsoft.Sql/servers/databases", "orders", tags=prod, sku={"name": "GP_Gen5_4"}, props={"zoneRedundant": False})
        | {"id": _rid(D, "Microsoft.Sql/servers", "sql-prod", "databases", "orders")},
        _row(D, "Microsoft.Sql/servers/databases", "master", props={})
        | {"id": _rid(D, "Microsoft.Sql/servers", "sql-prod", "databases", "master")},
        _row(D, "Microsoft.DBforPostgreSQL/flexibleServers", "pg-analytics", tags=prod, props={
            "dataEncryption": {"primaryKeyURI": "https://kv-prod.vault.azure.net/keys/cmk-sql/0a1b2c3d"},
            "version": "16", "highAvailability": {"mode": "ZoneRedundant"},
            "network": {"delegatedSubnetResourceId": subnet("snet-data"), "publicNetworkAccess": "Disabled"}}),
    ]
    rows += [_row(W, "Microsoft.Compute/disks", f"disk-{i}") for i in range(3)]
    rows.append(_row(W, "Microsoft.Insights/components", "appi-prod"))

    containers = [
        {"id": f"/subscriptions/{SUB}", "name": "Contoso Production", "type": "microsoft.resources/subscriptions",
         "subscriptionId": SUB, "properties": {"managementGroupAncestorsChain": [
             {"name": "mg-prod", "displayName": "Production"}, {"name": "tenant-root", "displayName": "Tenant Root Group"}]}},
        {"id": f"/subscriptions/{SUB}/resourceGroups/{W}", "name": W, "type": "microsoft.resources/subscriptions/resourcegroups",
         "subscriptionId": SUB, "location": "westeurope", "tags": {"env": "prod"}},
        {"id": f"/subscriptions/{SUB}/resourceGroups/{D}", "name": D, "type": "microsoft.resources/subscriptions/resourcegroups",
         "subscriptionId": SUB, "location": "westeurope", "tags": None},
    ]

    kvp, kvs = _rid(W, "Microsoft.KeyVault/vaults", "kv-prod"), _rid(D, "Microsoft.KeyVault/vaults", "kv-shared")
    item = lambda vault, kind, name, **kw: {"vault_id": vault, "type": kind, "name": name, "created": when(-200), **kw}  # noqa: E731
    app_api, func_etl = _rid(W, "Microsoft.Web/sites", "app-api"), _rid(W, "Microsoft.Web/sites", "func-etl")
    ref = lambda app, setting, vault, secret, status="Resolved": {"app_id": app, "setting": setting, "vault": vault,  # noqa: E731
                                                                  "secret": secret, "status": status}
    role = lambda guid: f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{guid}"  # noqa: E731
    kv = {
        "listed_secrets": [kvp, kvs], "listed_keys": [kvp, kvs],
        "items": [
            item(kvp, "secret", "db-conn-string", enabled=True, expires=when(120), content_type="text/plain"),
            item(kvp, "secret", "api-key", enabled=True, expires=when(-12)),                       # expired, and an app reads it
            item(kvp, "secret", "stripe-key", enabled=True),                                       # never expires
            item(kvp, "secret", "old-token", enabled=False, expires=when(200)),                    # disabled, and an app reads it
            item(kvp, "secret", "tls-cert", enabled=True, expires=when(18), content_type="application/x-pkcs12"),
            item(kvp, "key", "cmk-storage", enabled=True, expires=when(300), key_type="RSA", key_size=3072),
            item(kvp, "key", "cmk-sql", enabled=True, key_type="RSA", key_size=2048),
            item(kvs, "secret", "shared-token", enabled=True, expires=when(45)),
            item(kvs, "secret", "legacy-service-key", enabled=True),
        ],
        "refs": [
            ref(app_api, "DB_CONN", "kv-prod", "db-conn-string"), ref(app_api, "PAYMENT_KEY", "kv-prod", "stripe-key"),
            ref(app_api, "API_KEY", "kv-prod", "api-key"),
            ref(func_etl, "SOURCE_TOKEN", "kv-prod", "old-token"),
            ref(func_etl, "LEGACY_PW", "kv-prod", "legacy-password", "SecretNotFound"),            # secret does not exist
            ref(func_etl, "SHARED_TOKEN", "kv-shared", "shared-token", "ForbiddenByFirewall"),     # reference cannot resolve
        ],
        "assignments": [
            {"principalId": "p-id-app", "roleDefinitionId": role("4633458b-17de-408a-b874-0445c86b69e6"), "scope": kvs, "principalType": "ServicePrincipal"},
            {"principalId": "p-mi-auto", "roleDefinitionId": role("b86a8fe4-44ce-4948-aee5-eccb2c155cd7"), "scope": kvs, "principalType": "ServicePrincipal"},
            {"principalId": "00000000-aaaa-bbbb-cccc-222222222222", "roleDefinitionId": role("00482a5a-887f-4fb3-b363-3b7fe8e74483"),
             "scope": f"/subscriptions/{SUB}/resourceGroups/{D}", "principalType": "User"},
        ],
    }
    return containers, rows, kv


# =========================== GCP ===========================
PROJECT, NUMBER = "shop-prod", "5550001"
ANC = [f"projects/{NUMBER}", "folders/111", "organizations/999"]
C = "https://www.googleapis.com/compute/v1/projects/shop-prod"


def _asset(atype, path, data, loc=None, anc=ANC):
    svc = atype.split("/")[0]
    res = {"data": data}
    if loc:
        res["location"] = loc
    return {"name": f"//{svc}/{path}", "assetType": atype, "resource": res, "ancestors": anc}


def gcp_assets():
    net = f"{C}/global/networks/prod-vpc"
    sub = lambda r, s: f"{C}/regions/{r}/subnetworks/{s}"          # noqa: E731
    sa = lambda n: f"{n}@{PROJECT}.iam.gserviceaccount.com"        # noqa: E731
    P = f"projects/{PROJECT}"
    fw = lambda name, **kw: _asset("compute.googleapis.com/Firewall", f"{P}/global/firewalls/{name}",   # noqa: E731
                                   {"name": name, "network": net, "direction": "INGRESS", **kw})
    vm = lambda name, zone, subnet, sa_name, tags=(), labels=None, external=True, **extra: _asset(      # noqa: E731
        "compute.googleapis.com/Instance", f"{P}/zones/{zone}/instances/{name}", {
            "name": name, "status": "RUNNING", "zone": f"{C}/zones/{zone}", "machineType": f"{C}/zones/{zone}/machineTypes/e2-medium",
            "networkInterfaces": [{"network": net, "subnetwork": sub(zone[:-2], subnet),
                                   **({"accessConfigs": [{"type": "ONE_TO_ONE_NAT", "natIP": "34.77.0.1"}]} if external else {})}],
            "serviceAccounts": [{"email": sa(sa_name), "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
            "tags": {"items": list(tags)}, "labels": labels or {}, **extra}, loc=zone)
    return [
        _asset("cloudresourcemanager.googleapis.com/Organization", "organizations/999", {"displayName": "example.com"}, anc=["organizations/999"]),
        _asset("cloudresourcemanager.googleapis.com/Folder", "folders/111", {"displayName": "platform"}, anc=["folders/111", "organizations/999"]),
        _asset("cloudresourcemanager.googleapis.com/Project", f"projects/{NUMBER}",
               {"projectId": PROJECT, "projectNumber": NUMBER, "name": "Shop Production", "labels": {"env": "prod"}}),
        _asset("compute.googleapis.com/Network", f"{P}/global/networks/prod-vpc", {"name": "prod-vpc", "autoCreateSubnetworks": False}),
        _asset("compute.googleapis.com/Subnetwork", f"{P}/regions/europe-west1/subnetworks/web-eu",
               {"name": "web-eu", "network": net, "ipCidrRange": "10.10.0.0/24", "region": f"{C}/regions/europe-west1", "privateIpGoogleAccess": True}, loc="europe-west1"),
        _asset("compute.googleapis.com/Subnetwork", f"{P}/regions/us-central1/subnetworks/data-us",
               {"name": "data-us", "network": net, "ipCidrRange": "10.20.0.0/24", "region": f"{C}/regions/us-central1"}, loc="us-central1"),
        fw("allow-ssh-world", sourceRanges=["0.0.0.0/0"], allowed=[{"IPProtocol": "tcp", "ports": ["22"]}]),
        fw("allow-web", sourceRanges=["0.0.0.0/0"], targetTags=["web"], allowed=[{"IPProtocol": "tcp", "ports": ["80", "443"]}]),
        fw("allow-icmp", sourceRanges=["0.0.0.0/0"], allowed=[{"IPProtocol": "icmp"}]),
        fw("allow-legacy-ftp", sourceRanges=["10.0.0.0/8"], targetTags=["legacy"], allowed=[{"IPProtocol": "tcp", "ports": ["21"]}]),
        vm("web-1", "europe-west1-b", "web-eu", "app-sa", tags=["web"], labels={"env": "prod"},
           metadata={"items": [{"key": "startup-script", "value": "export TOKEN=DEMO-SECRET-NOT-COLLECTED"}]}),
        vm("web-2", "europe-west1-c", "web-eu", "app-sa", tags=["web"], labels={"env": "prod"}),
        vm("worker-1", "europe-west1-b", "web-eu", "app-sa", external=False),
        vm("bastion", "europe-west1-d", "web-eu", "ops-sa", tags=["bastion"], labels={"env": "prod"}),
        _asset("compute.googleapis.com/InstanceGroup", f"{P}/zones/europe-west1-b/instanceGroups/web-ig", {"name": "web-ig", "size": 2}, loc="europe-west1-b"),
        _asset("compute.googleapis.com/BackendService", f"{P}/global/backendServices/web-bs",
               {"name": "web-bs", "protocol": "HTTPS", "backends": [{"group": f"{C}/zones/europe-west1-b/instanceGroups/web-ig"}]}),
        _asset("compute.googleapis.com/ForwardingRule", f"{P}/global/forwardingRules/web-fr",
               {"name": "web-fr", "loadBalancingScheme": "EXTERNAL_MANAGED", "portRange": "443-443", "backendService": f"{C}/global/backendServices/web-bs"}),
        _asset("sqladmin.googleapis.com/Instance", f"{P}/instances/orders-db", {
            "name": "orders-db", "databaseVersion": "POSTGRES_15", "region": "europe-west1",
            "settings": {"tier": "db-custom-2-8192", "availabilityType": "ZONAL", "userLabels": {"env": "prod"},
                         "ipConfiguration": {"ipv4Enabled": True, "authorizedNetworks": [{"name": "everyone", "value": "0.0.0.0/0"}]}}}),
        _asset("sqladmin.googleapis.com/Instance", f"{P}/instances/reporting-db", {
            "name": "reporting-db", "databaseVersion": "MYSQL_8_0", "region": "us-central1",
            "settings": {"tier": "db-n1-standard-2", "availabilityType": "REGIONAL", "userLabels": {"env": "prod"},
                         "ipConfiguration": {"ipv4Enabled": False, "privateNetwork": net}}}),
        _asset("storage.googleapis.com/Bucket", "shop-assets", {"name": "shop-assets", "location": "EU", "storageClass": "STANDARD", "labels": {"env": "prod"}}),
        _asset("storage.googleapis.com/Bucket", "shop-logs", {"name": "shop-logs", "location": "EU", "storageClass": "NEARLINE"}),
        *[_asset("iam.googleapis.com/ServiceAccount", f"{P}/serviceAccounts/{100 + i}", {"email": sa(n), "displayName": n})
          for i, n in enumerate(("app-sa", "ops-sa", "fn-sa", "unused-sa"))],
        _asset("cloudfunctions.googleapis.com/Function", f"{P}/locations/europe-west1/functions/thumbnailer", {
            "name": f"{P}/locations/europe-west1/functions/thumbnailer", "state": "ACTIVE",
            "buildConfig": {"runtime": "python312"}, "serviceConfig": {"serviceAccountEmail": sa("fn-sa"),
                                                                       "environmentVariables": {"API_KEY": "DEMO-SECRET-NOT-COLLECTED"}}}, loc="europe-west1"),
        _asset("cloudfunctions.googleapis.com/CloudFunction", f"{P}/locations/europe-west1/functions/report-gen", {
            "name": f"{P}/locations/europe-west1/functions/report-gen", "runtime": "python311", "status": "ACTIVE",
            "serviceAccountEmail": sa("fn-sa"), "labels": {"env": "prod"}}, loc="europe-west1"),
        _asset("run.googleapis.com/Service", f"{P}/locations/europe-west1/services/api", {
            "metadata": {"name": "api", "labels": {"env": "prod"}, "annotations": {"run.googleapis.com/ingress": "all"}},
            "spec": {"template": {"spec": {"serviceAccountName": sa("app-sa")}}}}, loc="europe-west1"),
        _asset("container.googleapis.com/Cluster", f"{P}/locations/europe-west1/clusters/gke-prod", {
            "name": "gke-prod", "location": "europe-west1", "currentMasterVersion": "1.29.4-gke.1", "currentNodeCount": 6,
            "network": "prod-vpc", "subnetwork": "web-eu", "resourceLabels": {"env": "prod"}}, loc="europe-west1"),
    ]
