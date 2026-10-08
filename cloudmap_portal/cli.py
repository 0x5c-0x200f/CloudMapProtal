from __future__ import annotations

import argparse
import json
import sys
import uuid

from .schema import Inventory, SchemaError, diff
from .scanners.base import Emitter
from .writer import write_inventory


def cmd_scan(a) -> int:
    em = Emitter(a.provider, a.scan_id or uuid.uuid4().hex[:8])
    split = lambda v: [x.strip() for x in v.split(",") if x.strip()] if v else None  # noqa: E731
    progress = None if a.quiet else (lambda m: print(m, file=sys.stderr))
    if a.demo:
        from .scanners import demo
        demo.scan_provider(a.provider, em)
    elif a.provider == "aws":
        from .scanners import aws
        aws.scan(em, profile=a.profile, regions=split(a.regions), progress=progress)
    elif a.provider == "azure":
        from .scanners import azure
        azure.scan(em, subscriptions=split(a.subscription), progress=progress, keyvault=not a.skip_keyvault)
    else:
        parent = (f"projects/{a.project}" if a.project else f"folders/{a.folder}" if a.folder
                  else f"organizations/{a.organization}" if a.organization else None)
        if not parent:
            print("error: GCP needs a scope. Pass one of --project, --folder or --organization.", file=sys.stderr)
            return 2
        from .scanners import gcp
        gcp.scan(em, parent, progress=progress)
    path = write_inventory(em, a.out)
    inv = Inventory.load_path(path)  # self-check: our own output must validate
    s = inv.summary()
    print(f"wrote {path}\n  {s['nodes']} nodes, {s['edges']} edges, {s['errors']} scan errors")
    if inv.errors:
        print(f"\n{len(inv.errors)} area(s) could not be read, so they are missing from the map:",
              file=sys.stderr)
        for e in inv.errors[:5]:
            print(f"  {e['scope']}: {e['message']}", file=sys.stderr)
        print("Grant read access (see: cloudmap-portal policy aws) and scan again.", file=sys.stderr)
    return 0


def cmd_policy(a) -> int:
    from pathlib import Path
    f = Path(__file__).parent / "scanners" / "policies" / f"{a.provider}.json"
    if not f.exists():
        print(f"error: no policy for '{a.provider}' yet", file=sys.stderr)
        return 2
    print(f.read_text())
    return 0


def cmd_validate(a) -> int:
    try:
        inv = Inventory.load_path(a.file)
    except SchemaError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    print(json.dumps(inv.summary(), indent=2))
    for w in inv.warnings[:20]:
        print("warning:", w)
    return 0


def cmd_diff(a) -> int:
    d = diff(Inventory.load_path(a.old), Inventory.load_path(a.new))
    print(json.dumps(d, indent=2))
    return 0


def cmd_serve(a) -> int:
    from .portal.app import create_app
    create_app().run(host=a.host, port=a.port)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cloudmap-portal")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a cloud and write a .jsonci inventory")
    s.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    s.add_argument("--profile", help="AWS named profile")
    s.add_argument("--regions", help="AWS: comma-separated, e.g. eu-west-1,us-east-1")
    s.add_argument("--subscription", help="Azure: subscription IDs, comma-separated (default: all you can read)")
    s.add_argument("--skip-keyvault", action="store_true",
                   help="Azure: do not read Key Vault item names, role assignments or app secret references")
    s.add_argument("--project", help="GCP: project ID to scan")
    s.add_argument("--folder", help="GCP: folder number to scan, including everything below it")
    s.add_argument("--organization", help="GCP: organization number to scan")
    s.add_argument("--out", default=".", help="output directory")
    s.add_argument("--scan-id", help="default: random 8 hex chars")
    s.add_argument("--quiet", action="store_true", help="no progress output")
    s.add_argument("--demo", action="store_true", help="synthetic data, no credentials needed")
    s.set_defaults(fn=cmd_scan)

    pol = sub.add_parser("policy", help="print the minimal read-only permissions a scan needs")
    pol.add_argument("provider", choices=["aws", "azure", "gcp"])
    pol.set_defaults(fn=cmd_policy)

    v = sub.add_parser("validate", help="validate a .jsonci file")
    v.add_argument("file")
    v.set_defaults(fn=cmd_validate)

    d = sub.add_parser("diff", help="compare two scans (old new)")
    d.add_argument("old")
    d.add_argument("new")
    d.set_defaults(fn=cmd_diff)

    w = sub.add_parser("serve", help="run the CloudMap portal")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8080)
    w.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
