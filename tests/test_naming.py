"""PyPI already has an unrelated project called `cloudmap` that installs a `cloudmap` command and a `cloudmap`
Python package. Installing it over ours silently replaced our CLI. Never share those names again."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TAKEN = "cloudmap"                       # the other project's distribution, command and import name


def project():
    tomllib = pytest.importorskip("tomllib")
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]


def test_distribution_command_and_import_package_are_all_unique():
    p = project()
    assert p["name"] != TAKEN
    assert TAKEN not in p["scripts"], "a console command called `cloudmap` would collide with the other project's"
    assert not (ROOT / "cloudmap").exists(), "a top-level `cloudmap` package would overwrite the other project's files"
    assert (ROOT / "cloudmap_portal" / "__init__.py").exists()


def test_the_console_script_points_at_our_package():
    assert project()["scripts"]["cloudmap-portal"] == "cloudmap_portal.cli:main"


def test_no_message_or_doc_names_the_old_command_or_tells_people_to_install_it():
    bad = [re.compile(r'pip install[^\n]*["\' ]cloudmap(\[|["\' ])'),                       # would fetch the other project
           re.compile(r'(?<![\w-])cloudmap (scan|serve|policy|diff|validate)\b'),           # a command that is not ours
           re.compile(r'python -m cloudmap(?!_portal)\b')]
    offenders = []
    for f in list(ROOT.glob("cloudmap_portal/**/*")) + [ROOT / "README.md"]:
        if f.suffix in (".py", ".md", ".js", ".html", ".json") and f.is_file():
            for n, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if any(b.search(line) for b in bad):
                    offenders.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()[:80]}")
    assert not offenders, "\n".join(offenders)


def test_cli_reports_its_own_name(capsys):
    from cloudmap_portal import cli
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "usage: cloudmap-portal" in capsys.readouterr().out
