from __future__ import annotations

import json
import os
from pathlib import Path

from .scanners.base import Emitter
from .schema import filename_for


def write_inventory(em: Emitter, outdir) -> Path:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / filename_for(em.meta)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for rec in em.records():
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    os.replace(tmp, path)  # atomic: never leave a half-written inventory
    return path
