"""Every spelling a caller can type, and what the binding makes of it.

The property this file exists for is that a path survives the crossing: the
characters a caller wrote are the characters the filesystem is asked about, with no
lossy intermediate and no quiet normalisation nobody agreed to. It is checked from
both ends.

* the caller's end: `str`, `pathlib.Path` and a hand-made `os.PathLike` reach the
  same project, and the shapes Rust cannot give a meaning to — `bytes`, an `int`, a
  `__fspath__` that returns one — are refused before any filesystem call;
* the filesystem's end: a root whose name carries spaces, non-ASCII or shell
  metacharacters completes a whole protect/verify/scan cycle; a *file inside* the
  tree with those characters in its name is still the same site afterwards; and a
  root past Windows' `MAX_PATH` is reached, because the conversion lands in Rust's
  path layer rather than in Python's `os` calls.

Two further families carry the rest. A path the binding reports back is either what
the caller typed (a candidate) or the store's own forward-slashed spelling (anything
under `.swp/`), and a trailing separator, a doubled separator or a `.` segment does
not change which project a string names.

One gap is marked rather than papered over: a *relative* scan candidate is handed to
Rust exactly as typed, and `swp-detection`'s walk then reads it as relative to
itself. See `test_a_relative_scan_candidate_is_walked`.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

import swp
from conftest import SOURCE_TREE, _purge, _write_tree

#: The Windows verbatim prefix: the only spelling that reaches a past-`MAX_PATH`
#: tree through Python's own filesystem calls.
VERBATIM = "\\\\?\\"

WINDOWS = sys.platform == "win32"

NAMES = [
    "with spaces",
    "проект-ünïcode-漢字",
    "a b'c(d)#e%20f",
    "dotted.name",
]

ODD_TREE = {
    "src/app.js": SOURCE_TREE["src/app.js"],
    "src/my app (1).js": SOURCE_TREE["src/app.js"],
    "src/ünïcode 漢字.py": SOURCE_TREE["src/util.py"],
    "src/sub-dir/one-more.ts": SOURCE_TREE["src/main.ts"],
}


class PathLike:
    """The smallest thing `os.PathLike` describes: a `__fspath__` that returns `str`."""

    def __init__(self, path) -> None:
        self.path = path

    def __fspath__(self) -> str:
        return self.path


class NotAPath:
    """Something whose `str()` looks like a path and which has no `__fspath__` at all."""

    def __str__(self) -> str:
        return "src"


@pytest.fixture
def named_root():
    """Build a project directory whose name is exactly the string a test supplies.

    `make_project` sanitises its label into the temp prefix, which is right for a
    test name and useless for a test *about* names: here the characters under
    examination have to be the ones on disk.
    """
    bases: list[Path] = []

    def factory(name: str, files: dict[str, str] | None = None) -> Path:
        base = Path(tempfile.mkdtemp(prefix="swp-py-name-"))
        bases.append(base)
        return _write_tree(base / name, SOURCE_TREE if files is None else files)

    yield factory
    for base in bases:
        _purge(base)


def _plain(path: str) -> str:
    """Drop the verbatim prefix the store adds on Windows.

    `project_root` reports the store's canonical spelling, so comparing that string
    with a caller's would test two path printers against each other.
    """
    return path[4:] if path.startswith(VERBATIM) else path


def _cycle(root: Path, label: str):
    """Run the whole documented lifecycle in `root` and hand the answers back."""
    opened = swp.Session.init(str(root), options=swp.InitOptions(name=label))
    summary = opened.session.protect_summary(swp.ProtectOptions(swp.Mode.Release))
    return opened, summary, opened.session.verify(), opened.session.scan(root)


# -- a root whose name is not a plain word -----------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_a_root_with_an_awkward_name_completes_a_whole_cycle(named_root, name):
    """Spaces, non-ASCII, quoting characters and dots are path data, not errors.

    Each operation the binding offers runs against this root: the identity is written
    and read back with the label intact, protection lands on the tree's three sites,
    verification recovers them, and a scan of the same directory finds the
    provenance. A character lost anywhere in the path layer costs one of those four.
    """
    root = named_root(name)
    opened, summary, outcome, scanned = _cycle(root, name)

    assert opened.result.project_id.startswith("swp1-")
    assert opened.session.identity.display_name == name
    assert summary.sites_embedded == 3
    assert outcome.verdict == "INTACT"
    assert outcome.sites_confirmed == outcome.sites_expected
    assert scanned.report.result == "PROVENANCE_DETECTED"
    assert scanned.report.candidate.files_scanned == 3


@pytest.mark.parametrize("name", NAMES)
def test_the_root_the_store_reports_is_the_root_that_exists(named_root, name):
    """The characters survive the store's canonicalisation as well as the call."""
    root = named_root(name)
    opened = swp.Session.init(str(root), options=swp.InitOptions(name=name))
    reported = _plain(opened.session.project_root)
    assert Path(reported).name == name
    assert Path(reported).is_dir()
    assert Path(reported).samefile(root)


@pytest.mark.parametrize("name", NAMES)
def test_a_missing_path_is_refused_naming_the_characters_it_was_given(named_root, name):
    """The refusal quotes the caller's spelling instead of a normalisation of it."""
    root = named_root("quoted")
    away = str(root / name)
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(away)
    assert caught.value.code == "PATH_REJECTED"
    assert name in caught.value.message


def test_a_file_named_as_the_project_is_refused_as_not_a_project(project):
    """`NOT_PROTECTED`, not a made-up identity: the path exists and has no store."""
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(str(project.child("src", "app.js")))
    assert caught.value.code == "NOT_PROTECTED"


# -- the forms Python hands a path around in --------------------------------


def test_str_path_and_fspath_object_open_the_same_project(project):
    """Three spellings of one directory, one session.

    `os.PathLike` is asked for its `__fspath__` rather than `str()`-ed: on some
    objects those two disagree, and the filesystem follows `__fspath__`.
    """
    as_text = str(project.root)
    spellings = [as_text, Path(as_text), PathLike(as_text)]
    roots = {swp.Session.open(s).project_root for s in spellings}
    assert len(roots) == 1, roots
    assert roots == {project.session.project_root}


def test_init_and_discover_take_the_same_forms(named_root):
    root = named_root("takes-pathlike")
    session = swp.Session.init(Path(root)).session
    assert session.identity.display_name == "takes-pathlike"
    for spelling in (Path(root / "src"), PathLike(str(root / "src"))):
        assert swp.Session.discover(spelling).project_root == session.project_root


@pytest.mark.parametrize(
    "given, kind, why",
    [
        (b"src", "bytes", "a bytes path"),
        (PathLike(b"src"), "PathLike", "a __fspath__ that is not str"),
        (PathLike(Path("src")), "PathLike", "a __fspath__ that is not str"),
        (NotAPath(), "NotAPath", "none"),
        (123, "int", "none"),
        (None, "NoneType", "none"),
        (["src"], "list", "none"),
        (PathLike(3), "PathLike", "a __fspath__ that is not str"),
    ],
)
def test_a_path_rust_cannot_be_handed_is_refused_not_guessed(given, kind, why):
    """`bytes` has no meaning as a path on Windows and an `int` has none anywhere.

    A binding that decoded the bytes, or `str()`-ed the number, would invent a
    directory and then report that no project is there — a confident answer to a
    question the caller never asked. The refusal is `USAGE`, before any I/O.
    """
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(given)
    assert caught.value.code == "USAGE"
    assert caught.value.message == (
        f"expected a str or os.PathLike path, got {kind} returning {why}"
    )
    assert caught.value.next_step == "Re-run with --help to see accepted arguments."


def test_the_same_refusal_guards_init_discover_and_scan(project):
    for call in (
        lambda: swp.Session.init(5),
        lambda: swp.Session.discover(5),
        lambda: swp.Session.init(b"src"),
        lambda: project.session.scan(b"src"),
        lambda: project.session.scan(None),
    ):
        with pytest.raises(swp.Error) as caught:
            call()
        assert caught.value.code == "USAGE"


def test_a_refused_path_never_reaches_the_filesystem(named_root):
    """Nothing is created, and no directory is read, on the way to a `USAGE`."""
    root = named_root("untouched")
    before = sorted(p.name for p in root.iterdir())
    with pytest.raises(swp.Error):
        swp.Session.open(PathLike(str(root).encode()))
    assert sorted(p.name for p in root.iterdir()) == before


def test_an_empty_path_names_the_working_directory_not_a_made_up_one(project, monkeypatch):
    """`""` is a real Python spelling of "here", and stays one.

    Refusing it would be the binding inventing a rule its caller does not have;
    passing it through lets the operating system resolve it, so the answer is about
    the working directory rather than about a path nobody typed. A lone space is the
    same string with two platform answers: Win32 strips trailing spaces from a name,
    so " " resolves like "", while POSIX reads it as a directory literally called
    " " — one that does not exist here, and the refusal is what says so.
    """
    monkeypatch.chdir(project.root)
    assert swp.Session.open("").project_root == project.session.project_root
    if WINDOWS:
        assert swp.Session.open(" ").project_root == project.session.project_root
    else:
        with pytest.raises(swp.Error) as caught:
            swp.Session.open(" ")
        assert caught.value.code == "PATH_REJECTED"
    monkeypatch.chdir(project.root.parent)
    with pytest.raises(swp.Error) as caught:
        swp.Session.open("")
    assert caught.value.code == "NOT_PROTECTED"


# -- the spellings a caller types, and what comes back ----------------------


def test_a_candidate_is_described_in_the_report_as_it_was_named(protected):
    """Forward slashes and a trailing separator are kept, not rewritten.

    The scan resolves the path it was handed; it does not first re-print the
    caller's string, so the document says what the command said.
    """
    typed = str(protected.root).replace("\\", "/") + "/"
    outcome = protected.scan(typed)
    assert outcome.report.candidate.described == typed
    assert outcome.report.result == "PROVENANCE_DETECTED"
    assert outcome.report.candidate.files_scanned == 3


def test_the_candidate_root_is_part_of_the_path_the_binding_passes(protected):
    """The document locates a site from the candidate's root, so that root matters.

    Scanning `src` instead of the project hands the same three files one level
    higher than the release recorded them, and `swp-evidence` says so — every site
    `moved`, the fingerprint `no-match`, an inconclusive scan rather than a strong
    one over a tree whose shape it had misread. Nothing here smooths that over to
    make the answer look better.
    """
    whole = protected.scan(str(protected.root))
    part = protected.scan(str(protected.root / "src"))
    assert whole.report.candidate.described == str(protected.root)
    assert part.report.candidate.described == str(protected.root / "src")
    assert whole.report.releases[0].moved == 0
    assert part.report.releases[0].moved == part.report.releases[0].sites
    assert part.report.candidate.files_scanned == 3
    assert part.report.releases[0].fingerprint == "no-match"


@pytest.mark.parametrize("suffix", ["", os.sep, "/", "/.", "/src/.."])
def test_extra_separators_and_dot_segments_do_not_change_the_project(project, suffix):
    assert swp.Session.open(str(project.root) + suffix).project_root == project.session.project_root


@pytest.mark.skipif(
    not WINDOWS,
    reason=(
        "Win32 strips a trailing separator and trailing spaces from a directory name; "
        "POSIX reads both as part of a name that no entry carries"
    ),
)
@pytest.mark.parametrize("suffix", ["\\\\", "  "])
def test_the_windows_trailing_spellings_of_a_directory_name_the_same_project(project, suffix):
    assert swp.Session.open(str(project.root) + suffix).project_root == project.session.project_root


def test_a_parent_traversal_is_honoured_rather_than_normalised_away(project):
    """`..` is resolved by the filesystem, so it names the directory above.

    Cancelling it textually would be wrong when a component in between is a
    symlink, so the binding leaves it alone — and the refusal proves the traversal
    actually happened, because the parent is not a project.
    """
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(str(project.root) + os.sep + "..")
    assert caught.value.code == "NOT_PROTECTED"
    named = _plain(caught.value.message.split(" in ", 1)[1])
    assert Path(named).samefile(project.root.parent)


@pytest.mark.skipif(not WINDOWS, reason="the verbatim spelling is a Windows path form")
def test_the_verbatim_spelling_opens_the_same_project_as_the_plain_one(project):
    given = VERBATIM + str(project.root.resolve())
    assert swp.Session.open(given).project_root == project.session.project_root


@pytest.mark.parametrize("suffix", ["", os.sep, "/"])
def test_a_candidate_with_extra_separators_is_still_read(protected, suffix):
    outcome = protected.scan(str(protected.root) + suffix)
    assert outcome.report.candidate.files_scanned == 3
    assert outcome.report.result == "PROVENANCE_DETECTED"


def test_a_relative_root_is_resolved_where_the_process_stands(project, monkeypatch):
    """Relative means the process working directory, not the session's root.

    The binding passes the path on without re-anchoring it, so `.` and a bare child
    name mean what they mean to any other Python program run from the same place.
    """
    monkeypatch.chdir(project.root)
    assert swp.Session.open(".").project_root == project.session.project_root
    assert swp.Session.open(Path(".")).project_root == project.session.project_root
    monkeypatch.chdir(project.child("src"))
    assert swp.Session.discover(".").project_root == project.session.project_root
    assert swp.Session.discover("..").project_root == project.session.project_root


@pytest.mark.xfail(
    strict=True,
    reason=(
        "a relative scan candidate is handed to Rust as typed, and swp-detection's "
        "walk then joins it to itself: 'src' becomes 'src/src/app.js' "
        "(read_source, crates/swp-detection/src/find.rs:959). The CLI never reaches "
        "this because ctx::resolve makes every typed path absolute first. Passing the "
        "path through unchanged is the binding's contract, so this is a Rust-side "
        "defect found by the binding work; it is reported, not worked around here."
    ),
)
def test_a_relative_scan_candidate_is_walked(protected, monkeypatch):
    """`scan("src")` should examine `src` exactly as the absolute spelling does."""
    monkeypatch.chdir(protected.root)
    from_here = protected.session.scan("src")
    assert from_here.report.candidate.files_scanned == 3
    assert from_here.report.result == "PROVENANCE_DETECTED"


# -- names inside the tree ---------------------------------------------------


@pytest.fixture
def odd_tree(named_root) -> Path:
    """A tree whose file names carry spaces, brackets, non-ASCII and a subdirectory."""
    return named_root("odd-tree", ODD_TREE)


def test_sites_in_files_with_awkward_names_are_protected_and_recovered(odd_tree):
    """Four odd-named files, four sites, and verification back to INTACT.

    Recovery means reading each file at exactly the name it was written under, so a
    mangled name costs a site rather than passing quietly.
    """
    opened, summary, outcome, scanned = _cycle(odd_tree, "odd-tree")
    assert summary.sites_embedded == 4
    assert {f.file for f in summary.files_changed} == set(ODD_TREE)
    assert {r.file for r in summary.sites} == set(ODD_TREE)
    assert outcome.verdict == "INTACT"
    assert {r.file for r in outcome.sites} == set(ODD_TREE)
    assert scanned.report.candidate.files_scanned == 4
    assert opened.session.identity.display_name == "odd-tree"


def test_a_site_row_names_a_file_that_is_really_there(odd_tree):
    """`file` is store-relative and forward-slashed; joining it to the root opens it."""
    opened, _, _, _ = _cycle(odd_tree, "odd-tree")
    for row in opened.session.verify().sites:
        assert "\\" not in row.file
        assert row.file in ODD_TREE
        assert (odd_tree / Path(*row.file.split("/"))).is_file
        if row.found_in is not None:
            assert "\\" not in row.found_in
            assert (odd_tree / Path(*row.found_in.split("/"))).is_file


def test_the_protected_bytes_are_written_back_under_the_same_name(odd_tree):
    """A rewrite of a non-ASCII path is a rewrite of the same file, not a new one."""
    before = {rel: (odd_tree / Path(*rel.split("/"))).read_bytes() for rel in ODD_TREE}
    _cycle(odd_tree, "odd-tree")
    after = {rel: (odd_tree / Path(*rel.split("/"))).read_bytes() for rel in ODD_TREE}
    assert set(after) == set(before)
    assert any(after[rel] != before[rel] for rel in before), "protection rewrote nothing"
    assert all((odd_tree / Path(*rel.split("/"))).is_file for rel in ODD_TREE)


def test_one_file_with_a_space_and_brackets_in_its_name_is_a_candidate(odd_tree):
    """A candidate may be a single file, and its name may carry the awkward characters.

    The rows keep the store's per-site addresses, and `found_in` for a staged single
    file is that file's own name — the spaces and brackets arrive unharmed, which is
    what a caller matching a row against the tree has to be able to do.
    """
    opened, summary, _, _ = _cycle(odd_tree, "odd-tree")
    target = odd_tree / "src" / "my app (1).js"
    outcome = opened.session.scan(target)
    candidate = outcome.report.candidate
    assert candidate.kind == "file"
    assert candidate.files_scanned == 1
    assert candidate.described == str(target)
    assert len(outcome.sites) == summary.sites_embedded
    names = {row.found_in for row in outcome.sites}
    assert names - {None} == {"my app (1).js"}
    tally = outcome.report.releases[0]
    assert tally.sites == summary.sites_embedded
    assert tally.fragments + tally.stripped + tally.absent == tally.sites
    assert any(row.status in ("exact-rendering", "tag-confirmed") for row in outcome.sites)
    assert outcome.report.exit_code() in (0, 1, 10)


def test_a_missing_candidate_file_is_an_io_error_with_the_name_given(odd_tree):
    opened, _, _, _ = _cycle(odd_tree, "odd-tree")
    with pytest.raises(swp.Error) as caught:
        opened.session.scan(odd_tree / "src" / "проект не существует.js")
    assert caught.value.code == "IO_ERROR"
    assert "проект не существует.js" in caught.value.message


# -- past MAX_PATH ----------------------------------------------------------


def _mkdir_long(deep: Path) -> Path:
    """Create a past-`MAX_PATH` tree with one source file in it."""
    text = SOURCE_TREE["src/app.js"]
    if WINDOWS:
        for leaf in (os.path.join(VERBATIM + str(deep), "src"),):
            os.makedirs(leaf, exist_ok=True)
            with open(os.path.join(leaf, "deep.js"), "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
    else:
        _write_tree(deep, {"src/deep.js": text})
    return deep


@pytest.fixture
def long_root():
    """A project root of roughly 340 characters, built through the long-path APIs.

    Python's own calls need the verbatim prefix to create it, which is the point: the
    limit is in the caller's path layer, not in the binding's. Teardown uses the same
    prefix for the same reason.
    """
    base = Path(tempfile.mkdtemp(prefix="swp-py-long-"))
    deep = base
    for step in range(9):
        deep = deep / f"directory-number-{step}-with-a-long-name"
    try:
        yield _mkdir_long(deep)
    finally:
        shutil.rmtree(VERBATIM + str(base) if WINDOWS else str(base), ignore_errors=True)
        if base.exists():
            _purge(base)


@pytest.mark.skipif(not WINDOWS, reason="MAX_PATH is a Windows limit")
def test_a_tree_python_cannot_walk_is_still_a_project(long_root):
    """The path is beyond the plain-path limit and the whole lifecycle runs on it.

    `init` seals its store, `protect` rewrites the source, `verify` reads it back and
    `scan` finds the provenance — every one of them a filesystem call the caller's own
    `os` module would refuse at this length.
    """
    assert len(str(long_root)) > 260
    opened, summary, outcome, scanned = _cycle(long_root, "deep")
    assert summary.sites_embedded == 1
    assert [f.file for f in summary.files_changed] == ["src/deep.js"]
    assert outcome.verdict == "INTACT"
    assert outcome.sites[0].file == "src/deep.js"
    assert scanned.report.candidate.files_scanned == 1
    assert len(opened.session.project_root) > 260
    assert swp.Session.discover(str(long_root / "src")).project_root == opened.session.project_root
    assert swp.Session.open(str(long_root)).identity.display_name == "deep"


# -- the paths the store reports back ---------------------------------------


def test_no_store_relative_path_ever_carries_a_backslash(protected):
    """`.swp/…` names keep the store's spelling on every platform.

    These strings appear in saved documents, in listings and in exception text, and
    the same project directory is read on another operating system. A Windows
    separator leaking into one of them makes the artifact unfindable there, so the
    sweep covers everything this project produced rather than one field.
    """
    summary = protected.protect(swp.Mode.Release)
    outcome = protected.verify(save=True)
    stored = protected.session.read_report(Path(outcome.report_saved).name)
    values = [
        *[f.file for f in summary.files_changed],
        *[r.file for r in summary.sites],
        *[r.file for r in outcome.sites],
        *[r.found_in for r in outcome.sites if r.found_in is not None],
        outcome.report_saved,
        stored.path,
        *protected.init.created,
        *protected.session.reports(),
    ]
    assert values, "the sweep ran over nothing"
    for value in values:
        assert "\\" not in value, value


def test_every_spelling_of_a_saved_report_names_that_report(protected):
    """Stem, name, store-relative path, backslashes and padding all normalise.

    `report_stem` is the SDK's own function, so this is parity with the Rust unit test
    at `crates/swp-sdk/src/report.rs:116` rather than a rule the binding adds.
    """
    protected.protect(swp.Mode.Release)
    saved = protected.verify(save=True).report_saved
    name = Path(saved).name
    stem = name[: -len(".json")]
    session = swp.Session.open(str(protected.root))
    for spelling in (name, stem, saved, saved.replace("/", "\\")):
        assert session.read_report(spelling).path == saved, spelling
    for prefix in (f"reports\\{name}", f"/{name}", f"  {name}  "):
        assert session.read_report(prefix).path == saved, prefix
    assert swp.report_stem(saved.replace("/", "\\")) == stem
    with pytest.raises(swp.Error) as caught:
        session.read_report("")
    assert caught.value.code == "PATH_REJECTED"
