# CloudMap (MVP)

Scan a cloud locally -> get `{provider}-{scan_id}-{date}.jsonci` -> import it into the portal.
Nothing is uploaded anywhere; the portal binds to 127.0.0.1 by default.

## The name
This project installs as **`cloudmap-portal`**, imports as `cloudmap_portal` and runs as `cloudmap-portal`. A different,
unrelated project on PyPI is called `cloudmap` (it has `trace`, `capture`, `scrub`, `ask`). Installing that one used to
overwrite this tool's files and its command. They can now coexist. Never run `pip install cloudmap` for this tool; install
from this folder, as below.

## Install and upgrade
    pip uninstall -y cloudmap                # once, if an older version or the other `cloudmap` project is installed
    pip install --upgrade ".[azure]"        # from this folder (note the dot). Also: [aws], [gcp], [all]
    cloudmap-portal --help
Check what you have, and that it is this project:

    python -m pip show cloudmap-portal      # Version: 0.9.0 or newer
    python -m cloudmap_portal --help        # lists scan, policy, validate, diff, serve; works even if Scripts is not on PATH
    grep '^name' pyproject.toml             # in the folder you install from: name = "cloudmap-portal"

Use `--upgrade` (or `-e .` while developing) when you unpack a newer version over an older one: pip skips a package
whose version it already has. The extras install everything a scanner needs, including the Key Vault packages.

| You see | Cause and fix |
|---|---|
| `WARNING: Key Vault details will be skipped because ... not installed` | Run the `pip install` line it prints and scan again. The scan still completes, without Key Vault contents. |
| `Could not read Azure Resource Graph (ClientAuthenticationError ...)` | Not signed in: `az login`, or set the `AZURE_*` variables. Needs the Reader role: `cloudmap-portal policy azure`. |
| `N resource(s) could not be mapped` under unreadable areas | A resource had a shape the scanner didn't expect. The rest of the scan is intact; send the type named in the message. |
| `ModuleNotFoundError: No module named 'cloudmap'` from `cloudmap.exe` | A leftover launcher for the old name, whose package is gone. Delete `Scripts\cloudmap.exe` from your Python folder and use `cloudmap-portal` instead. |
| `cloudmap-portal` not found on Windows | Use `python -m cloudmap_portal_portal ...`, or add Python's `Scripts` folder to PATH. |

## Quick start (no cloud account needed)
    pip install -e ".[aws,dev]"
    cloudmap-portal scan --provider aws --demo --out samples      # also: --provider azure / gcp
    cloudmap-portal serve                                         # http://127.0.0.1:8080
    # drag a sample into the page, or press AWS / Azure / GCP demo on the first screen

## What the portal gives you
- **Structure view (default)**: nested boxes (account > region > network > subnet), laid out for you. Five or more
  resources of one kind in one place become a single tile ("12 instances"); big containers fold into a summary bar.
  Relationship lines are drawn only for what you select, or aggregated on request ("Show all relationships").
  A rendering budget decides what starts open, so 800+ resources still open instantly. No resource-count ceiling.
- **Tree graph**: hierarchy and relationships in one diagram. The organisation tree runs left to right like an org chart
  (management group, subscription, resource group, resource on Azure; organization, folder, project on GCP; account, region,
  network, subnet on AWS), with columns labelled by what is in them. Relationships are drawn over it by default as curved
  arrows behind the boxes (thicker means more); a key explains the lines. Quiet mode keeps shared roles and groups out of the
  overview until you select one. Select a resource and its own relationships appear and the route through the hierarchy to
  everything related lights up. +/- on a node (or Left/Right arrow) folds it; the folded state is shared with the Structure
  view. Same-kind resources group into one node ("12 instances"). Search and findings work here too, and the Share menu
  exports the tree as a self-contained SVG.
- **Network graph**: the topology view, with quiet mode (lines into shared roles and security groups appear only
  when you select something). Switch with the toggle at the top right of the map.
- **Search is a filter for the whole map** (press `/`): type a name, tag (`env=prod`) or type and the map shows the matches
  *and everything connected to them*, with every relationship among them drawn and labelled. Choose how far the
  relationships reach (1, 2, 3 steps or all connected). A match that holds things (a vault, a network) brings its contents.
  The filter stays while you select, switch between Structure and Network graph, resize panels or open findings, and
  it is in the link, so a shared link opens the same filtered view. Esc or the clear button removes it.
- **Briefing**: plain-language findings (shared roles, single-AZ databases, unattached security groups,
  tag gaps, unreadable scan areas), most depended-on resources, click a finding to light it up on the map.
- **Resource view**: details, tags, depends-on / used-by, findings that mention it, "show everything within N steps".
- **Share**: standalone HTML report, Markdown report, map PNG, findings JSON, deep link to a resource.
  Links only work on the server that holds the import. `serve --host 0.0.0.0` has no authentication,
  so prefer the HTML report for sharing outside your machine.

## The Agent (Intel)

Open the **Agent** tab after importing a scan. It reviews the inventory like a team of specialists
(AWS, Azure, GCP, DevSecOps and Integration engineers) and reports:

| Section | What it does |
|---|---|
| Security | Open admin/database ports, public storage, public data services, shared identities, internet-facing workloads that can change secrets, plus **routes from the internet to data and secrets** |
| Misconfig | End-of-life runtimes, old Kubernetes, single-zone databases, broken or unverifiable Key Vault references, credentials that expire while workloads depend on them, prod linked to non-prod, tag gaps |
| Unused | Orphan network groups, unattached IPs and NICs, empty plans and load balancers, idle identities, stopped machines, dead secrets |
| Hardening | A "fix now / this sprint / backlog" plan from the findings, plus baseline controls for what you run (marked *not visible to the scan*) |
| Ask | Question answering over the map: "what breaks if I rotate kv-prod?", "what is exposed to the internet?", "who can access X?" |

Every finding names its resources, how sure the agent is (high / likely / check manually), why it matters, the fix, and a
ready-to-run `aws` / `az` / `gcloud` command. Click one to light up the affected resources on the map. `GET /api/imports/<id>/agent.md` downloads the report.

**The built-in agent is deterministic and offline**: same scan, same answers, nothing leaves your machine.

### AI Chat (Ollama)

Press **✦ AI Chat** (top bar, or the floating button). It is a streaming conversation, grounded in the loaded scan, that
remembers the last several turns, with an *Expert* selector (AWS / Azure / GCP / DevSecOps / Integration).

**Ollama is the default engine.** If Ollama runs on this machine (`http://localhost:11434`, or `OLLAMA_HOST`), the portal
finds it, lists every installed model (including your own), and uses a model named `cloudmap*` if you have one.
Everything stays on your machine.

```
ollama pull llama3.1          # any chat model works; 8B+ recommended for good answers
cloudmap-portal serve         # open the portal, press AI Chat
```

Click **⚙** in the chat to:
- point at another Ollama server on your network (private addresses only unless `CLOUDMAP_ALLOW_REMOTE_LLM=1`);
- pick the model per session, or choose *Built-in analysis* (no model);
- **create a custom CloudMap model**: choose a base model, an expertise and optional extra instructions, and the portal
  builds it on your Ollama server (`ollama run cloudmap-azure` works afterwards). The exact Modelfile is shown so you can version it.

Without a model, chat still answers from the built-in analysis. Other engines: `ANTHROPIC_API_KEY` (hosted) or
`CLOUDMAP_LLM_BASE_URL` (any OpenAI-compatible server). Hosted engines ask for consent once per session. `CLOUDMAP_LLM=off` disables all models.

What a model receives: finding titles, the relevant resources with their scanned properties and relationships, recent
turns, and your question, with secret-shaped strings redacted. Never the raw scan file. Names and tags are fenced as untrusted data.
Reasoning (`<think>`) output from local models is hidden. The agent only sees configuration and relationships, not live
traffic or IAM policy text, and says so when that limits a conclusion.

## The scanners
| | Reads through | Sign in with | Permission | Scope flag |
|---|---|---|---|---|
| AWS | one boto3 collector per service | `--profile` or env credentials | `cloudmap-portal policy aws` (read-only IAM policy) | `--regions` |
| Azure | Azure Resource Graph | `az login` or `AZURE_*` env | built-in **Reader** role | `--subscription` (default: all you can read) |
| GCP | Cloud Asset Inventory | `gcloud auth application-default login` | `roles/cloudasset.viewer` + Cloud Asset API enabled | `--project`, `--folder` or `--organization` |

    pip install -e ".[aws]"      # or [azure], [gcp], [all]
    cloudmap-portal policy azure                                   # what each cloud needs, as JSON
    cloudmap-portal scan --provider aws   --profile prod --regions eu-west-1,us-east-1 --out scans
    cloudmap-portal scan --provider azure --subscription <id> --out scans
    cloudmap-portal scan --provider gcp   --project my-project --out scans
    cloudmap-portal scan --provider gcp   --organization 123456789 --out scans

All three write the same `.jsonci` format, so the portal needs no provider-specific code beyond labels.
Hierarchies: AWS account > region > VPC > subnet; Azure management group > subscription > resource group
(VNet > subnet, SQL server > database); GCP organization > folder > project (VPC > subnet / firewall rule).

Every scanner copies only fields it names, so secrets can't leak in: no Lambda env vars, EC2 user-data, VM
admin passwords, instance metadata or function environment variables. Azure and GCP also record resource
types they found but don't map yet (shown in the briefing as "aren't on the map"), so nothing is silently
missing. Unreadable areas are listed instead of failing the scan.

### Key Vault (Azure)
Each vault is a box holding its secrets, keys and certificates **by name, with status** (enabled, expiry, "expires in 18d",
"missing"). The relationships:
- **Who can access a vault**: access policies and Key Vault RBAC roles, with the permissions each grants. Principals outside
  the scan (people, groups) are counted, not named.
- **Which app reads which secret**: Key Vault references in app settings, with their resolution status
  (`Resolved`, `ForbiddenByFirewall`, `SecretNotFound`...). A reference to a secret that doesn't exist shows as *missing*.
- **What is encrypted with which key**: customer-managed keys on storage accounts, PostgreSQL/MySQL flexible servers,
  AKS (KMS) and disk encryption sets.

Findings: expired or expiring items (urgent if something uses them), broken or dangling references, workloads that can
change or delete secrets, items that never expire, vaults without purge protection or open to any network.

**Secret values, key material and certificate contents are never read.** The normalisers take only named fields and
`value` is not one of them; a test plants a value in real SDK objects and checks it can't reach the file. The portal says
"Not collected, by design" on every secret. Reader access lists names and metadata; the app reference status may need
more and, if denied, is reported as one unreadable area. Use `--skip-keyvault` to skip all of it.
Not covered: certificate details beyond secrets stored as PKCS12/PEM, Managed HSM, Key Vault diagnostic logs
(who actually *used* a secret), and references written as Key Vault URIs inside values other than app settings.

Verification: AWS collectors run against a mocked AWS (moto). Azure and GCP mapping runs on API-shaped data,
and their SDK layers run against SDK-shaped fakes (real protobuf objects for GCP). None of the three has been
run against a real account yet.

Known limits: Azure NSG and GCP firewall exposure is an approximation (no route tables, subnet-level NSGs,
hierarchical firewall policies or service-tag expansion). GCP reads 14 asset types (see `ASSET_TYPES` in
`scanners/gcp.py`); Azure maps 16 resource types. Not covered anywhere yet: multi-cloud merge, Azure
Application Gateway / Front Door, GCP load balancers beyond forwarding rule > backend service > instance group.

## Other commands
    cloudmap-portal validate scans/aws-xxxx-2026-10-06.jsonci
    cloudmap-portal diff old.jsonci new.jsonci
    pytest

## Layout
    cloudmap_portal/schema.py        .jsonci spec, streaming reader, blast radius, diff
    cloudmap_portal/scanners/        base.Emitter, aws.py, azure.py, gcp.py, demo.py + demo_rows.py, policies/
    cloudmap_portal/insights.py      findings + stats engine (plain-language, inferred from the scan only)
    cloudmap_portal/report.py        standalone HTML / Markdown reports
    cloudmap_portal/portal/          Flask API + static UI (index.html, app.css, app.js; Cytoscape.js)
    cloudmap_portal/cli.py           scan | validate | diff | serve

## Format (JSON Lines)
    {"type":"meta","schema":"1.0","provider":"aws","scan_id":"..","scanned_at":"..","scope":{}}
    {"type":"node","id":"aws:vpc:vpc-1","kind":"network.vpc","name":"main","parent":"aws:region:..","props":{},"tags":{}}
    {"type":"edge","from":"aws:ec2:i-1","to":"aws:sg:sg-1","rel":"uses"}
    {"type":"error","scope":"eu-west-1/collect_rds","message":"AccessDenied"}
`parent` = containment (tree), `edge` = reference (graph). IDs are `provider:type:native-id`.

## Not built yet

- Agent rules are driven by what the scanners collect today; deeper checks (IAM policy text, encryption flags, S3 public-access settings) need the broader "scan any resource" collection.
Multi-cloud merge (several files in one map), scan diff in the portal (the `cloudmap-portal diff` CLI exists),
persistent storage, authentication, and the collectors listed under "Known limits" above.
The portal keeps imports in memory.
