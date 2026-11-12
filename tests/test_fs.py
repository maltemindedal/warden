"""`warden._fs` on the names a hostile project can plant: no read raises, and everything else
raises `ProjectIOError` alone."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from fakes import symlink_or_skip
from warden import _fs as fs

needs_named_pipes = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")

EVERY_ACCEPT = list(fs.Accept)


@pytest.mark.parametrize("accept", EVERY_ACCEPT, ids=lambda accept: accept.name)
def test_a_regular_file_is_read_as_path_read_text_reads_it(
    tmp_path: Path, accept: fs.Accept
) -> None:
    """The boundary replaced `Path.read_text`, so a BOM is dropped under `utf-8-sig` and a
    Windows line ending is read as `\\n`, as before."""
    path = tmp_path / ".warden.yaml"
    path.write_bytes(b"\xef\xbb\xbfurl: x\r\ntools:\r\n")

    assert fs.read_text(path, accept=accept, max_bytes=None, encoding="utf-8-sig") == fs.Text(
        "url: x\ntools:\n"
    )


@pytest.mark.parametrize("accept", EVERY_ACCEPT, ids=lambda accept: accept.name)
def test_a_name_nothing_has_is_absent(tmp_path: Path, accept: fs.Accept) -> None:
    assert fs.read_bytes(tmp_path / "missing", accept=accept, max_bytes=None) == fs.Absent()
    assert (
        fs.read_bytes(tmp_path / "missing" / "below", accept=accept, max_bytes=None) == fs.Absent()
    )


@pytest.mark.parametrize("accept", EVERY_ACCEPT, ids=lambda accept: accept.name)
def test_a_path_too_long_to_look_up_is_unlocatable_not_absent(
    tmp_path: Path, accept: fs.Accept
) -> None:
    """`Path.exists()` raises ENAMETOOLONG before Python 3.14, which was a traceback (2825ae7).
    It must not read as "no file" either: a report in this state may hold findings."""
    outcome = fs.read_text(tmp_path / ("a" * 300), accept=accept, max_bytes=None, encoding="utf-8")

    assert isinstance(outcome, fs.Unlocatable)
    assert outcome.reason != ""
    assert str(tmp_path) not in outcome.reason


def test_a_symlink_is_followed_only_where_the_caller_accepts_one(tmp_path: Path) -> None:
    """A symlinked `.warden.yaml` had its target's lines quoted in warnings, and appending to a
    symlinked `.gitignore` would write through the link to a file elsewhere."""
    target = tmp_path / "target"
    target.write_text("secret", encoding="utf-8")
    link = tmp_path / "link"
    symlink_or_skip(link, target)

    refused = fs.read_bytes(link, accept=fs.Accept.REGULAR_NO_LINK, max_bytes=None)

    assert refused == fs.NotRegular("a symbolic link")
    assert fs.read_bytes(
        link, accept=fs.Accept.USER_GIVEN_OR_WARDEN_OWNED, max_bytes=None
    ) == fs.Bytes(b"secret")


def test_a_dangling_symlink_is_not_mistaken_for_no_file_at_a_project_path(tmp_path: Path) -> None:
    """A `.warden.yaml` that points nowhere is a config the user wrote and Warden ignores, so it
    has to be told apart from no config. A path the user typed that leads nowhere does not exist."""
    link = tmp_path / ".warden.yaml"
    symlink_or_skip(link, tmp_path / "nowhere")

    assert fs.read_bytes(link, accept=fs.Accept.REGULAR_NO_LINK, max_bytes=None) == fs.NotRegular(
        "a symbolic link"
    )
    assert (
        fs.read_bytes(link, accept=fs.Accept.USER_GIVEN_OR_WARDEN_OWNED, max_bytes=None)
        == fs.Absent()
    )


@needs_named_pipes
def test_a_named_pipe_is_refused_without_being_opened(tmp_path: Path) -> None:
    """Reading a pipe nobody writes to blocks forever. Run in a subprocess so a regression fails
    on the timeout instead of hanging the suite."""
    os.mkfifo(tmp_path / "pipe")
    script = (
        "import sys; from pathlib import Path; from warden import _fs as fs; "
        "print(fs.read_bytes(Path(sys.argv[1]), accept=fs.Accept.REGULAR_NO_LINK, max_bytes=None))"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "pipe")],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )

    assert completed.stdout.strip() == "NotRegular(kind='a named pipe')"


def test_a_directory_is_not_regular_or_is_unreadable_and_never_raises(tmp_path: Path) -> None:
    """`--config <directory>` reads whatever is there, and the read then fails with the reason
    the warning has always printed."""
    refused = fs.read_bytes(tmp_path, accept=fs.Accept.REGULAR_NO_LINK, max_bytes=None)

    assert refused == fs.NotRegular("a directory")
    anything = fs.read_bytes(tmp_path, accept=fs.Accept.USER_GIVEN_OR_WARDEN_OWNED, max_bytes=None)

    assert isinstance(anything, fs.Unreadable)
    assert anything.reason != ""
    assert str(tmp_path) not in anything.reason


def test_bytes_that_are_not_the_encoding_are_unreadable_with_the_codec_message(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.yaml"
    path.write_bytes(b"# caf\xe9\n")

    outcome = fs.read_text(path, accept=fs.Accept.REGULAR_NO_LINK, max_bytes=None, encoding="utf-8")

    assert isinstance(outcome, fs.Unreadable)
    assert "codec can't decode byte 0xe9" in outcome.reason


def test_a_file_longer_than_the_caller_will_hold_is_unreadable_and_read_no_further(
    tmp_path: Path,
) -> None:
    """An 18 MB `.warden.yaml` took ten seconds to parse. `/dev/zero` never ends, so a read of
    it that returns at all shows that reading stops just past the limit."""
    path = tmp_path / "config"
    path.write_bytes(b"a" * 11)
    at_the_limit = fs.read_bytes(path, accept=fs.Accept.REGULAR_NO_LINK, max_bytes=11)
    over_it = fs.read_bytes(path, accept=fs.Accept.REGULAR_NO_LINK, max_bytes=10)

    assert at_the_limit == fs.Bytes(b"a" * 11)
    assert over_it == fs.Unreadable("larger than 10 bytes")
    if Path("/dev/zero").exists():
        endless = fs.read_bytes(
            Path("/dev/zero"), accept=fs.Accept.USER_GIVEN_OR_WARDEN_OWNED, max_bytes=10
        )
        assert endless == fs.Unreadable("larger than 10 bytes")


def test_append_line_adds_the_line_once_and_the_newline_the_last_line_lacks(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".gitignore"
    path.write_bytes(b"# caf\xe9\n*.log")

    first = fs.append_line(path, ".security_reports/")
    second = fs.append_line(path, ".security_reports/")

    assert (first, second) == (fs.Appended(), fs.AlreadyThere())
    assert path.read_bytes() == b"# caf\xe9\n*.log\n.security_reports/\n"


def test_append_line_writes_nothing_where_there_is_no_text_file_of_the_projects_own(
    tmp_path: Path,
) -> None:
    """A missing file is not created, a symlink is not written through, and a UTF-16 file, which
    appending ASCII to would corrupt, is left as it is."""
    victim = tmp_path / "victim"
    victim.write_text("keep\n", encoding="utf-8")
    link = tmp_path / "link"
    symlink_or_skip(link, victim)
    utf16 = tmp_path / "utf16"
    utf16.write_bytes("*.log\n".encode("utf-16"))

    assert fs.append_line(tmp_path / "missing", "x") == fs.Absent()
    assert fs.append_line(link, "x") == fs.NotRegular("a symbolic link")
    assert fs.append_line(utf16, "x") == fs.Unreadable("not a text file")
    assert not (tmp_path / "missing").exists()
    assert victim.read_text(encoding="utf-8") == "keep\n"
    assert utf16.read_bytes() == "*.log\n".encode("utf-16")


@needs_named_pipes
def test_the_append_neither_blocks_on_nor_writes_into_a_pipe_swapped_in_after_the_read(
    tmp_path: Path,
) -> None:
    """`append_line` reads `.gitignore` as a regular file and then opens the name again to write.
    A project that swaps a named pipe in between had the write open block for ever with no
    reader, and had the line written into the pipe with one. The second half is run on its own
    here, in a thread, because the swap is a race no test can time."""
    pipe = tmp_path / ".gitignore"
    os.mkfifo(pipe)
    outcomes: list[object] = []

    def append() -> None:
        outcomes.append(fs._append(pipe, b".security_reports/\n"))

    no_reader = threading.Thread(target=append, daemon=True)
    no_reader.start()
    no_reader.join(timeout=10)
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with_reader = threading.Thread(target=append, daemon=True)
        with_reader.start()
        with_reader.join(timeout=10)
        written = os.read(reader, 100)
    finally:
        os.close(reader)

    assert not no_reader.is_alive() and not with_reader.is_alive()
    assert isinstance(outcomes[0], fs.Unwritable)
    assert outcomes[1] == fs.NotRegular("a named pipe")
    assert written == b""


def test_an_owned_file_replaces_a_symlink_and_a_taken_as_given_one_writes_through_it(
    tmp_path: Path,
) -> None:
    """A project can ship `security_audit.json` as a symlink to a file elsewhere. A path the user
    typed, or a report a scanner wrote, is written where it leads."""
    target = tmp_path / "target"
    target.write_text("untouched", encoding="utf-8")
    owned = tmp_path / "owned.json"
    given = tmp_path / "given.json"
    symlink_or_skip(owned, target)
    symlink_or_skip(given, target)

    fs.owned_file(owned).write("new")

    assert not owned.is_symlink()
    assert owned.read_text(encoding="utf-8") == "new"
    assert target.read_text(encoding="utf-8") == "untouched"

    fs.as_given(given).write("through")

    assert given.is_symlink()
    assert target.read_text(encoding="utf-8") == "through"


@needs_named_pipes
def test_an_owned_file_replaces_a_named_pipe_instead_of_blocking_on_it(tmp_path: Path) -> None:
    """Opening a pipe for writing blocks forever. Run in a subprocess so a regression fails on
    the timeout."""
    os.mkfifo(tmp_path / "security_audit.json")
    script = (
        "import sys; from pathlib import Path; from warden import _fs as fs; "
        "fs.owned_file(Path(sys.argv[1])).write('{}')"
    )

    subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "security_audit.json")],
        timeout=30,
        check=True,
    )

    assert (tmp_path / "security_audit.json").read_text(encoding="utf-8") == "{}"


def test_make_way_removes_a_symlink_without_touching_its_target(tmp_path: Path) -> None:
    """A project can ship `security_audit.json -> ~/.bashrc`; the report must not land there."""
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    output_file = tmp_path / "security_audit.json"
    symlink_or_skip(output_file, victim)

    fs.owned_file(output_file).make_way()

    assert not output_file.exists() and not output_file.is_symlink()
    assert victim.read_text(encoding="utf-8") == "keep me"


def test_make_way_removes_a_dangling_symlink_without_creating_its_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "does-not-exist.txt"
    output_file = tmp_path / "security_audit.json"
    symlink_or_skip(output_file, target)

    fs.owned_file(output_file).make_way()

    assert not output_file.is_symlink()
    assert not target.exists()


@needs_named_pipes
def test_make_way_removes_a_named_pipe(tmp_path: Path) -> None:
    """Opening a pipe for writing blocks forever, so the report could never be written."""
    output_file = tmp_path / "security_audit.json"
    os.mkfifo(output_file)

    fs.owned_file(output_file).make_way()

    assert not output_file.exists()


def test_make_way_leaves_a_regular_file_and_a_missing_path_alone(tmp_path: Path) -> None:
    existing = tmp_path / "security_audit.json"
    existing.write_text("old report", encoding="utf-8")

    fs.owned_file(existing).make_way()
    fs.owned_file(tmp_path / "missing.json").make_way()

    assert existing.read_text(encoding="utf-8") == "old report"


def test_make_way_fails_on_a_name_it_cannot_look_up_instead_of_leaving_it_to_the_write(
    tmp_path: Path,
) -> None:
    """A failed lookup was read as "nothing to clear", and the error came back only from the
    write, after every scanner had run."""
    with pytest.raises(fs.ProjectIOError):
        fs.owned_file(tmp_path / ("a" * 300)).make_way()


def test_write_makes_missing_parents_and_escapes_a_lone_surrogate(tmp_path: Path) -> None:
    """A lone surrogate has no UTF-8 encoding: writing one as is raised after the file was
    opened and left it empty (bf9bbd8)."""
    path = tmp_path / "a" / "b" / "report.json"

    fs.as_given(path).write('"\udcff"')

    assert path.read_text(encoding="utf-8") == '"\\udcff"'


def test_a_write_the_file_system_refuses_raises_project_io_error_naming_path_and_reason(
    tmp_path: Path,
) -> None:
    """`warden-aggregate <dir> <a directory>` was an IsADirectoryError traceback."""
    with pytest.raises(fs.ProjectIOError) as raised:
        fs.as_given(tmp_path).write("{}")

    assert raised.value.path == tmp_path
    assert raised.value.reason != ""
    assert str(raised.value) == f"{tmp_path}: {raised.value.reason}"


def test_present_fails_rather_than_report_a_file_it_cannot_look_up_as_missing(
    tmp_path: Path,
) -> None:
    """ "No report" concluded from a failed lookup would let a scanner count as not having run."""
    report = tmp_path / "trivy.json"
    report.write_text("{}", encoding="utf-8")

    assert fs.as_given(report).present()
    assert not fs.as_given(tmp_path / "missing.json").present()
    with pytest.raises(fs.ProjectIOError):
        fs.as_given(tmp_path / ("a" * 300)).present()


def test_remove_unlinks_a_symlink_not_its_target_and_accepts_a_missing_name(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "trivy.json"
    symlink_or_skip(link, target)

    fs.owned_file(link).remove()
    fs.owned_file(link).remove()

    assert not link.is_symlink()
    assert target.read_text(encoding="utf-8") == "keep"


def test_owned_dir_replaces_a_symlink_with_a_real_directory_and_can_run_twice(
    tmp_path: Path,
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "notes.txt").write_text("keep", encoding="utf-8")
    link = tmp_path / "project" / ".security_reports"
    link.parent.mkdir()
    symlink_or_skip(link, elsewhere)

    assert fs.owned_dir(link) == link
    assert fs.owned_dir(link) == link

    assert link.is_dir()
    assert not link.is_symlink()
    assert (elsewhere / "notes.txt").read_text(encoding="utf-8") == "keep"


def test_owned_dir_raises_project_io_error_when_a_file_has_the_name(tmp_path: Path) -> None:
    (tmp_path / ".security_reports").write_text("", encoding="utf-8")

    with pytest.raises(fs.ProjectIOError, match=r"\.security_reports: "):
        fs.owned_dir(tmp_path / ".security_reports")


def test_a_symlink_loop_never_escapes_as_runtime_error(tmp_path: Path) -> None:
    """`Path.resolve()` raises RuntimeError for a loop before Python 3.13 and returns the path
    from then on. Either way the loop is not a directory and holds no file."""
    loop = tmp_path / "a"
    symlink_or_skip(loop, tmp_path / "b")
    symlink_or_skip(tmp_path / "b", loop)

    try:
        fs.resolved(loop)
    except fs.ProjectIOError as error:
        assert error.reason == "symbolic link loop"

    assert not fs.is_dir(loop)
    assert (
        fs.read_bytes(loop, accept=fs.Accept.USER_GIVEN_OR_WARDEN_OWNED, max_bytes=None)
        == fs.Absent()
    )
    assert fs.read_bytes(loop, accept=fs.Accept.REGULAR_NO_LINK, max_bytes=None) == fs.NotRegular(
        "a symbolic link"
    )


def test_is_dir_fails_rather_than_call_a_path_it_cannot_look_up_not_a_directory(
    tmp_path: Path,
) -> None:
    """`is_dir` answered `False` when the lookup failed, so `--project-root` on a directory that
    could not be looked up (EACCES, a name too long) was reported as "not an existing directory".
    `present()` already refused to conclude absence from an error."""
    assert fs.is_dir(tmp_path)
    assert not fs.is_dir(tmp_path / "missing")
    with pytest.raises(fs.ProjectIOError) as raised:
        fs.is_dir(tmp_path / ("a" * 300))
    assert raised.value.reason == os.strerror(errno.ENAMETOOLONG)
