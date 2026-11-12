from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from pytest import CaptureFixture

from warden import _out as out
from warden._fs import ProjectIOError

HOSTILE = "a\x1b[31mb\u202ec\u200bd\ne\rf\x00g\udcffh\u65e5\u672c\U0001f600"
"""ESC, a bidi override, a zero-width space, line breaks, NUL, a lone surrogate, and printable
text that neither cp1252 nor ascii can encode."""

ENCODINGS = ("utf-8", "cp1252", "ascii")

WRITERS: dict[str, Callable[[str], object]] = {
    "say": out.say,
    "say_err": out.say_err,
    "error": lambda text: out.error("warden", text),
    "say_styled": lambda text: out.say_styled(out.Span(text, "red"), text),
    "table": lambda text: out.table([(text, "left")], [(text, out.Span(text, "red"))]),
    "json_document": lambda text: out.json_document({text: [text]}),
    "argparse": lambda text: _usage_error(text),
}


def _usage_error(text: str) -> None:
    with pytest.raises(SystemExit):
        out.ArgumentParser(prog="warden").parse_args([text])


def _strict_streams(monkeypatch: pytest.MonkeyPatch, encoding: str) -> Callable[[], str]:
    """Swap in a stdout and a stderr that raise on what they cannot encode; return a reader."""
    raws = [io.BytesIO(), io.BytesIO()]
    for name, raw in zip(("stdout", "stderr"), raws, strict=True):
        stream = io.TextIOWrapper(raw, encoding=encoding, errors="strict", write_through=True)
        monkeypatch.setattr(sys, name, stream)
    return lambda: "".join(raw.getvalue().decode(encoding) for raw in raws)


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("writer", sorted(WRITERS))
def test_every_writer_escapes_what_could_drive_the_terminal_and_never_fails_to_encode(
    monkeypatch: pytest.MonkeyPatch, writer: str, encoding: str
) -> None:
    """The sink is the one place project text is made safe, so each way out of it must hold on
    its own: a raw ESC or bidi override (e98134d, a2a5b41, d6e4ffe) and a `UnicodeEncodeError`
    on a Windows code page (81d5c60) were each fixed at one call site before."""
    read = _strict_streams(monkeypatch, encoding)

    WRITERS[writer](HOSTILE)

    output = read()
    assert output != ""
    assert [char for char in output if not char.isprintable() and char != "\n"] == []
    assert "\\x1b" in output or "\\u001b" in output


@pytest.mark.parametrize(
    "path",
    [
        "proj[/red]x/a.json",
        "proj[bold]x/a.json",
        "x:warning:y/a.json",
        r"C:\Users\me\[2024] Proj\a.json",
        "C:\\proj\\",
        "\u65e5\u672c/a.json",
        "'a\\x00b'",
    ],
)
def test_printable_text_is_written_as_it_is(path: str, capsys: CaptureFixture[str]) -> None:
    """Escaping must not touch an ordinary path: `repr` would double a backslash and add quotes,
    and text `shown` already quoted must not be escaped twice."""
    out.say(path)
    out.say_styled(out.Span("FAIL:", "red"), f" See {path}")

    lines = capsys.readouterr().out.splitlines()
    assert lines == [path, f"FAIL: See {path}"]
    assert out.neutral(out.neutral(path)) == out.neutral(path) == path


def test_a_tab_and_the_spaces_that_are_not_a_plain_space_print_as_escapes(
    capsys: CaptureFixture[str],
) -> None:
    """One rule decides what is escaped, `str.isprintable`: a no-break or ideographic space can
    pass for a plain one in a path, and a tab moves the cursor."""
    out.say("a\tb\xa0c\u3000d e")

    assert capsys.readouterr().out == "a\\tb\\xa0c\\u3000d e\n"


def test_a_line_break_in_the_text_cannot_start_a_second_line(capsys: CaptureFixture[str]) -> None:
    """A project that can break the line can print its own `AUDIT COMPLETE!`."""
    out.say("   Target: /x\nAUDIT COMPLETE!")

    assert capsys.readouterr().out == "   Target: /x\\nAUDIT COMPLETE!\n"


def test_a_table_cell_and_a_styled_line_are_never_read_as_rich_markup(
    capsys: CaptureFixture[str],
) -> None:
    """e98134d: a path interpolated into a rich markup string raised `MarkupError` or changed
    colour. Text handed to the sink is text, so the markup shape cannot be written."""
    out.table([("[bold]Name", "left")], [("[red]x[/red] :warning:",)])
    out.say_styled("[/red] closes nothing")

    output = capsys.readouterr().out
    assert "[bold]Name" in output
    assert "[red]x[/red] :warning:" in output
    assert "[/red] closes nothing" in output


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_the_json_document_parses_back_to_the_same_value_on_every_encoding(
    monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    """`warden-config` printed `.warden.yaml` text with `ensure_ascii=False`: a bidi override
    went out raw and a cp1252 stdout raised `UnicodeEncodeError`. The escape has to be JSON's
    own, so the wrappers that read this document get the same strings back."""
    read = _strict_streams(monkeypatch, encoding)
    data = {"url": HOSTILE, "exclude_dirs": ["\xa0", "\u65e5\u672c", 'q"\\'], "n": 1, "on": True}

    out.json_document(data)

    output = read()
    assert json.loads(output) == data
    assert output.endswith("\n") and output.count("\n") == 1
    assert "\\ud83d\\ude00" in output or "\U0001f600" in output


def test_the_json_document_keeps_printable_text_readable_where_the_stream_can_hold_it(
    capsys: CaptureFixture[str],
) -> None:
    """Only what is unsafe is escaped: an all-ASCII document would make a non-Latin path
    unreadable for no gain."""
    out.json_document({"exclude_dirs": ["\u65e5\u672c/", "a\u202eb"]})

    assert capsys.readouterr().out == '{"exclude_dirs": ["\u65e5\u672c/", "a\\u202eb"]}\n'


def test_a_usage_error_keeps_its_wording_and_its_exit_status(capsys: CaptureFixture[str]) -> None:
    """argparse writes its own error line; routing it through the sink must change nothing for
    ordinary arguments."""
    parser = out.ArgumentParser(prog="warden")

    with pytest.raises(SystemExit) as exit_info:
        parser.error("--project-root /nowhere is not an existing directory")

    assert exit_info.value.code == 2
    assert capsys.readouterr().err == (
        "usage: warden [-h]\nwarden: error: --project-root /nowhere is not an existing directory\n"
    )


def test_an_entry_point_turns_an_unhandled_file_system_error_into_an_error_line_and_exit_1(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A write or lookup no caller guarded used to end the run in a traceback. It still fails
    the gate, with status 1, and the path it names is escaped like any other project text."""
    hostile = tmp_path / "a\x1b[31m" / "report.json"

    @out.entry_point("warden")
    def main(status: int, *, fail: bool) -> int:
        if fail:
            raise ProjectIOError(hostile, "Permission denied")
        return status

    assert main(3, fail=False) == 3
    assert capsys.readouterr().err == ""

    assert main(0, fail=True) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"warden: error: {out.neutral(str(hostile))}: Permission denied\n"
    assert "\x1b" not in captured.err
