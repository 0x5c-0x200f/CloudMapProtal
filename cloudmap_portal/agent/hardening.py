"""Hardening plan = (a) fixes derived from findings, ordered by urgency; (b) baseline controls
the scan cannot verify but that apply to what is deployed. Baselines are labelled as such."""
from __future__ import annotations

BASELINE = {
    "aws": [
        ("compute.instance", "Require IMDSv2 on every EC2 instance", "Stops SSRF bugs from stealing instance-role credentials.", "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled"),
        ("compute.instance", "Use SSM Session Manager instead of SSH", "Removes the need for open admin ports and key management.", None),
        ("storage.bucket", "Turn on S3 Block Public Access for the whole account", "One setting that prevents most public-bucket incidents.", "aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"),
        ("data.database", "Encrypt RDS, enable backups, deletion protection and IAM auth", "Protects data at rest and from accidental deletion.", None),
        ("iam.role", "Review each role with IAM Access Analyzer and remove unused permissions", "Shrinks blast radius from stolen credentials.", None),
        ("*", "Enable CloudTrail (all regions, log validation), GuardDuty and Security Hub", "Detection and audit trail for everything above.", None),
        ("network.vpc", "Enable VPC Flow Logs", "Needed to see what actually talked to what.", None),
    ],
    "azure": [
        ("*", "Enable Defender for Cloud plans for the resource types you run and assign the Microsoft cloud security benchmark initiative", "Continuous posture checks plus threat detection.", None),
        ("storage.account", "Disable shared-key access and use Entra ID auth; add private endpoints", "Removes long-lived account keys, the commonest storage breach path.", "az storage account update -n <name> -g <rg> --allow-shared-key-access false"),
        ("iam.vault", "Use RBAC authorization, purge protection, firewall + private endpoint", "Vaults hold the keys to everything else.", None),
        ("compute.instance", "Use Azure Bastion or just-in-time access instead of public RDP/SSH", "Removes standing admin exposure.", None),
        ("compute.app", "Use managed identity and Key Vault references instead of connection strings in settings", "Eliminates secrets in configuration.", None),
        ("data.server", "Turn on auditing, Entra-only authentication and private endpoints for SQL", "Closes password and public-network attack paths.", None),
        ("network.security_group", "Enable NSG flow logs and send diagnostics to Log Analytics", "Visibility for incident response.", None),
        ("iam.identity", "Put privileged role assignments behind Entra PIM", "Time-boxed admin access.", None),
    ],
    "gcp": [
        ("*", "Apply organization policies: no service-account key creation, restrict external IPs, domain-restricted sharing, uniform bucket-level access", "Prevents entire classes of misconfiguration across all projects.", None),
        ("iam.identity", "Replace service-account keys with Workload Identity / attached service accounts, and use dedicated accounts per workload", "Keys are the most-leaked GCP credential.", None),
        ("compute.instance", "Enable Shielded VM and OS Login, and use IAP TCP forwarding for admin access", "No public SSH, per-user audit trail.", None),
        ("compute.cluster", "Use private GKE nodes, Workload Identity and Binary Authorization", "Limits what a compromised pod can reach.", None),
        ("data.database", "Use private IP for Cloud SQL, require SSL, enable backups and CMEK where required", "Closes public paths and protects data at rest.", None),
        ("storage.bucket", "Enable public access prevention and uniform bucket-level access", "Stops accidental public buckets.", None),
        ("*", "Turn on Cloud Audit Logs (Data Access) and Security Command Center", "Detection and audit trail.", None),
        ("*", "Consider VPC Service Controls around sensitive projects", "Blocks data exfiltration even with valid credentials.", None),
    ],
}

PHASES = [("now", "Fix now", {"high"}), ("soon", "Plan this sprint", {"medium"}), ("later", "Backlog", {"low", "note"})]


def plan(c, findings):
    """findings: security/misconfig/unused/hardening findings already computed."""
    steps = []
    for key, label, sevs in PHASES:
        items = [f for f in findings if f["severity"] in sevs and f["category"] in ("security", "misconfig")]
        if key == "later":
            items += [f for f in findings if f["category"] == "unused" and f["severity"] in ("medium", "low")]
        steps.append({"phase": key, "label": label, "items": [
            {"finding": f["id"], "title": f["title"], "count": f["count"], "severity": f["severity"],
             "cli": f.get("cli", [])[:3]} for f in items]})
    present = {n["kind"] for n in c.things}
    baseline = []
    for kind, title, why, cli in BASELINE.get(c.provider, []):
        if kind == "*" or kind in present:
            baseline.append({"title": title, "why": why, "cli": cli, "verified": False,
                             "applies_to": 0 if kind == "*" else len(c.by_kind.get(kind, []))})
    return {"phases": steps, "baseline": baseline}
