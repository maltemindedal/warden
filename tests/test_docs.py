"""The reference docs state facts the code and `uv.lock` already hold, and these tests hold them
to it. Each failure names the doc file and the text to write there."""

from __future__ import annotations

import re
import tomllib
import typing
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest
from semgrep.semgrep_interfaces.semgrep_output_v1 import MatchSeverity

from warden import aggregate, cli, config
from warden._models import DEFAULT_FAIL_ON_SEVERITIES
from warden._parsers import SEVERITY_ALIASES, SEVERITY_RANK, ZAP_RISK_MAP, normalize_severity
from warden._scanners import CATEGORY_ORDER, SCANNERS

ROOT = Path(__file__).resolve().parents[1]
CLI_DOC = Path("docs/reference/cli.md")
CONFIG_DOC = Path("docs/reference/configuration.md")
REPORT_DOC = Path("docs/reference/report-format.md")

# A version followed by one of these words is a range or a minimum, not a claim about the lock.
_NOT_THE_LOCK = re.compile(r"\s*(?:through|to|or newer|or older|or later|and later|and older)\b")


def _text(doc: Path) -> str:
    return (ROOT / doc).read_text(encoding="utf-8")


def _require(doc: Path, expected: str) -> None:
    if expected not in _text(doc):
        pytest.fail(f"{doc} no longer matches the code. Write this there:\n\n{expected}")


def _table(header: str, rows: Sequence[tuple[str, ...]]) -> str:
    columns = header.count("|") - 1
    lines = [header, "|" + " --- |" * columns]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def _code(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values)


def _markdown_files() -> Iterator[Path]:
    for path in sorted(ROOT.rglob("*.md")):
        relative = path.relative_to(ROOT)
        if not any(part.startswith(".") for part in relative.parts):
            yield relative


def test_the_severity_tables_in_the_report_format_reference_match_the_parser_maps() -> None:
    """AGENTS.md says `_parsers.py` severity maps are mirrored in report-format.md."""
    sources = [
        (
            _code([alias for alias, target in SEVERITY_ALIASES.items() if target == severity]),
            f"`{severity}`",
        )
        for severity in SEVERITY_RANK
        if severity != "UNKNOWN"  # the prose under the table covers it: anything else is UNKNOWN
    ]
    _require(REPORT_DOC, _table("| Source value | Becomes |", sources))
    risk = [(f"`{code}`", f"`{severity}`") for code, severity in ZAP_RISK_MAP.items()]
    _require(REPORT_DOC, _table("| `riskcode` | Becomes |", risk))


def test_the_report_format_reference_lists_each_scanners_report_file_and_category() -> None:
    """A scanner added to `SCANNERS` must show up where users look up its file and category."""
    files = [(scanner.label, f"`{scanner.report_file}`") for scanner in SCANNERS]
    _require(REPORT_DOC, _table("| Tool | Filename |", files))
    labels = {scanner.category: scanner.label for scanner in SCANNERS}
    categories = [(f"`{category}`", labels[category]) for category in CATEGORY_ORDER]
    _require(REPORT_DOC, _table("| Category | Tool |", categories))


def test_the_report_format_reference_names_every_semgrep_severity_that_fails_the_build() -> None:
    """report-format.md said Semgrep reports only ERROR and WARNING after Semgrep also wrote HIGH
    and MEDIUM (fixed in 08371f1). The vocabulary comes from the locked Semgrep itself."""
    variants = typing.get_args(typing.get_type_hints(MatchSeverity)["value"])
    failing = [
        name
        for name in (variant.to_json() for variant in variants)
        if normalize_severity(name) in DEFAULT_FAIL_ON_SEVERITIES
    ]
    bullet = next(
        line for line in _text(REPORT_DOC).split("\n- ") if line.startswith("**Semgrep**")
    )
    missing = [name for name in failing if f"`{name}`" not in bullet]
    assert not missing, (
        f"{REPORT_DOC}: the **Semgrep** bullet must name every Semgrep severity that fails the "
        f"build ({_code(failing)}); it does not name {_code(missing)}."
    )


@pytest.mark.parametrize("main", [cli.main, config.main, aggregate.main])
def test_the_cli_reference_shows_each_commands_usage_as_argparse_prints_it(
    main: Callable[[list[str]], int], capsys: pytest.CaptureFixture[str]
) -> None:
    """AGENTS.md says `cli.py` usage and flags are mirrored in cli.md. Line wrapping depends on
    the terminal width, so whitespace is compared collapsed."""
    with pytest.raises(SystemExit):
        main(["--help"])
    usage = capsys.readouterr().out.split("\n\n")[0]
    blocks = re.findall(r"```\n(usage: .*?)```", _text(CLI_DOC), flags=re.DOTALL)
    assert " ".join(usage.split()) in [" ".join(block.split()) for block in blocks], (
        f"{CLI_DOC} no longer matches the code. Write this usage block there:\n\n{usage}"
    )


def test_the_configuration_reference_has_a_section_or_alias_for_each_config_key() -> None:
    """AGENTS.md says `config.py` is mirrored in configuration.md; a key it reads must be there."""
    text = _text(CONFIG_DOC)
    documented = set(re.findall(r"^### `(\w+)`", text, flags=re.MULTILINE))
    documented |= set(re.findall(r"^\| Alias \| `(\w+)` \|", text, flags=re.MULTILINE))
    assert documented == config.KNOWN_KEYS, (
        f"{CONFIG_DOC}: add a `### `key`` section for {sorted(config.KNOWN_KEYS - documented)}, "
        f"remove the one for {sorted(documented - config.KNOWN_KEYS)}."
    )


def test_a_version_the_docs_name_for_a_locked_package_is_the_locked_version() -> None:
    """AGENTS.md named Semgrep 1.179 and ruff 0.16 for months of Dependabot bumps (fixed in
    08371f1). A closed range (`1.146.0 through 1.172.0`) or a minimum (`0.37 or newer`) is not a
    claim about the lock and is skipped. An open one (`From Semgrep 1.173 the pin is`) is not
    skipped: it stops being true when the lock moves on, as that sentence in CONTRIBUTING.md did."""
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked = {
        package["name"]: package["version"] for package in lock["package"] if "version" in package
    }
    names = "|".join(re.escape(name) for name in sorted(locked, key=len, reverse=True))
    mention = re.compile(
        rf"\b(?P<name>{names})\b[*`]*(?:'s)?\s+(?:at\s+)?v?(?P<version>\d+\.\d+(?:\.\d+)?)\b",
        flags=re.IGNORECASE,
    )
    wrong = [
        f"{doc}:{number}: write `{found['name']} {locked[found['name'].lower()]}` "
        f"in place of `{found['name']} {found['version']}`"
        for doc in _markdown_files()
        for number, line in enumerate(_text(doc).splitlines(), start=1)
        for found in mention.finditer(line)
        if not _NOT_THE_LOCK.match(line, found.end())
        and not f"{locked[found['name'].lower()]}.".startswith(f"{found['version']}.")
    ]
    assert not wrong, "uv.lock moved but the docs did not:\n" + "\n".join(wrong)


def test_no_doc_ships_a_todo_marker() -> None:
    """running-with-docker.md shipped a TODO(verify) over version numbers it admitted were made
    up (fixed in b4698a1). A doc states what was checked or says nothing."""
    markers = [
        f"{doc}:{number}: {line.strip()}"
        for doc in _markdown_files()
        for number, line in enumerate(_text(doc).splitlines(), start=1)
        if re.search(r"\b(?:TODO|FIXME)\b", line)
    ]
    assert not markers, "Resolve these before the doc ships:\n" + "\n".join(markers)
