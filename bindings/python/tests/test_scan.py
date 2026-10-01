"""Looking for your provenance in somebody else's artifact.

`Session.scan` is the operation that runs against a tree or archive this project
does not own, so these cases are built around a copy of the protected sources with
no store beside it — an artifact the way a reviewer receives one. What is asserted
is the shape of the answer and the arithmetic the detector already did: the row per
expected site, the release or releases it was graded against, the candidate's own
description, and the refusal when the candidate cannot be read.

The verdict, the evidence level and the exit code are read out of the
`SWP-1-report-v2` document (see `test_reports.py` for that document's own fields);
nothing here decides whether a finding is a finding.
"""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest

import swp
from conftest import SOURCE_TREE

SITE_STATUSES = {"absent", "location-only", "tag-confirmed", "exact-rendering"}

SITE_ROW_KEYS = {
    "release_id",
    "site",
    "status",
    "probes",
    "distinct_codes",
    "found_tokens",
    "found_in",
    "found_line",
    "found_excerpt",
}


@pytest.fixture
def artifact(protected, tmp_path):
    """A protected project, and a copy of its sources holding no store."""
    staged = tmp_path / "artifact"
    shutil.copytree(protected.child("src"), staged / "src")
    return protected, staged


def _as_zip(source: Path, dest: Path) -> Path:
    """The same files as a zip, with the paths a reviewer's archive would carry."""
    archive = dest / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as writer:
        for path in sorted((source / "src").rglob("*")):
            if path.is_file():
                writer.write(path, f"src/{path.name}")
    return archive


def test_a_copy_of_the_sources_is_detected(artifact):
    made, staged = artifact
    outcome = made.scan(staged)
    report = outcome.report

    assert report.result == "PROVENANCE_DETECTED"
    assert report.exit_code() == 1
    assert report.evidence_level in {
        "WEAK",
        "MODERATE",
        "STRONG",
        "VERY_STRONG",
    }
    assert report.candidate.kind == "directory"
    assert report.candidate.files_scanned == len(SOURCE_TREE)
    assert report.candidate.bytes_scanned > 0
    assert report.candidate.partial is False
    assert outcome.saved is None, "a scan saves only when the caller asks"
    # The candidate is described by where it was, not by anything keyed.
    assert Path(report.candidate.described).resolve() == staged.resolve()


def test_every_expected_site_gets_a_row(artifact):
    """One row per site of the release, and nothing about the site is keyed.

    The row says that a span confirmed and how much work reaching it took. The
    addresses a match was decided against stay inside Rust, so a caller cannot use
    these rows to test a guess against a site the candidate never presented.
    """
    made, staged = artifact
    published = made.session.releases(swp.ReleaseSelection.all())
    outcome = made.scan(staged)
    rows = outcome.sites
    assert len(rows) == outcome.report.releases[0].sites
    seen = set()
    for row in rows:
        assert row.release_id in published
        assert (row.release_id, row.site) not in seen
        seen.add((row.release_id, row.site))
        assert row.status in SITE_STATUSES
        assert set(row.to_dict()) == SITE_ROW_KEYS
        assert row.probes >= 0 and row.distinct_codes >= 0
        assert (row.found_in is None) == (row.found_line is None)
        if row.status == "absent":
            assert row.probes == 0 and row.found_in is None
        if row.found_in is not None:
            assert row.found_in.startswith("src/")
            assert "\\" not in row.found_in, "candidate-relative and forward-slashed"
    # A confirmed row names the file and line it was found at; an absent one says nothing.
    confirmed = [r for r in rows if r.status != "absent"]
    assert all(r.found_in is not None for r in confirmed)
    assert json.dumps([r.to_dict() for r in rows])


def test_the_rows_are_the_report_summed(artifact):
    """The per-site rows and the report's tally are two views of one detection run."""
    made, staged = artifact
    outcome = made.scan(staged)
    tally = outcome.report.releases[0]
    rows = [r for r in outcome.sites if r.release_id == tally.release_id]
    assert tally.sites == len(rows)
    assert tally.fragments == sum(1 for r in rows if r.status in {"tag-confirmed", "exact-rendering"})
    assert tally.absent == sum(1 for r in rows if r.status == "absent")
    assert tally.probes == sum(r.probes for r in rows)
    assert tally.draws == sum(r.distinct_codes for r in rows)
    assert tally.bits == tally.fragments * tally.tag_bits


def test_an_archive_is_a_candidate_like_any_other(artifact, tmp_path):
    made, staged = artifact
    archive = _as_zip(staged, tmp_path)
    outcome = made.scan(archive)
    assert outcome.report.candidate.kind == "zip"
    assert outcome.report.candidate.files_scanned == len(SOURCE_TREE)
    assert outcome.report.result == "PROVENANCE_DETECTED"
    assert [r.status for r in outcome.sites] == ["exact-rendering"] * len(outcome.sites)
    assert all(r.found_in.startswith("src/") for r in outcome.sites)


def test_scanning_the_project_itself_prunes_the_store(artifact):
    """`.swp/` is not source: the walk declines it rather than matching against it."""
    made, _ = artifact
    outcome = made.scan(made.root)
    assert outcome.report.candidate.files_scanned == len(SOURCE_TREE)
    assert outcome.report.result == "PROVENANCE_DETECTED"
    assert all(".swp" not in row.found_in for row in outcome.sites if row.found_in)


def test_a_tree_that_is_nobody_else_is_graded_as_such(protected, foreign_tree):
    outcome = protected.scan(foreign_tree)
    assert outcome.report.result == "NO_PROVENANCE_DETECTED"
    assert outcome.report.evidence_level == "NONE"
    assert outcome.report.exit_code() == 0
    assert outcome.saved is None
    for row in outcome.sites:
        assert row.status == "absent"
        assert row.probes == 0 and row.distinct_codes == 0
        assert row.found_in is None and row.found_excerpt is None
    assert outcome.report.releases[0].fragments == 0
    assert outcome.report.releases[0].coincidence_probability <= 1.0


def test_a_candidate_with_nothing_readable_is_inconclusive(protected, tmp_path):
    """Not-finding and not-looking are different answers, and the document says which.

    A tree with no file this protocol can read confirms nothing and excludes
    nothing, so the verdict is `INCONCLUSIVE` and the exit code is the one the CLI
    uses for "this run could not have said either way".
    """
    bare = tmp_path / "prose-only"
    (bare / "docs").mkdir(parents=True)
    (bare / "docs" / "notes.md").write_text("# nothing a parser reads\n", encoding="utf-8")
    outcome = protected.scan(bare)
    assert outcome.report.result == "INCONCLUSIVE"
    assert outcome.report.evidence_level == "NONE"
    assert outcome.report.exit_code() == 10
    assert outcome.report.candidate.files_scanned == 0
    assert any("no source this protocol can read" in note for note in outcome.report.notes)
    assert all(row.status == "absent" for row in outcome.sites)


def test_a_candidate_that_cannot_be_read_is_an_io_error(protected, tmp_path):
    with pytest.raises(swp.Error) as caught:
        protected.scan(tmp_path / "never-written")
    assert caught.value.code == "IO_ERROR"
    assert "never-written" in caught.value.message


def test_a_selection_limits_which_releases_are_graded(make_project, tmp_path):
    """`releases=` is `--release`: the grading covers exactly what it names.

    The copy is made after the first release, so that release's constellation is
    what the artifact carries and the second one is not.
    """
    made = make_project("scan-selection")
    first = made.protect(swp.Mode.Release)
    staged = tmp_path / "artifact"
    shutil.copytree(made.child("src"), staged / "src")
    second = made.protect(swp.Mode.Release)
    assert second.release_id != first.release_id

    one = made.scan(staged, releases=swp.ReleaseSelection.ids([first.release_id]))
    assert [t.release_id for t in one.report.releases] == [first.release_id]
    assert len(one.sites) == first.sites_embedded
    assert all(r.release_id == first.release_id for r in one.sites)
    assert {e.release_id for e in one.report.evidence} == {first.release_id}

    both = made.scan(staged, releases=swp.ReleaseSelection.all())
    assert {t.release_id for t in both.report.releases} == {
        first.release_id,
        second.release_id,
    }
    assert len(both.sites) == len(one.sites) + second.sites_embedded
    fragments = [t.fragments for t in both.report.releases]
    assert fragments == sorted(fragments, reverse=True), "the strongest tally comes first"
    assert {e.release_id for e in both.report.evidence} <= {first.release_id, second.release_id}


def test_a_release_id_this_project_never_published_is_refused(protected, artifact):
    _, staged = artifact
    missing = "rel-" + "z" * 13
    with pytest.raises(swp.Error) as caught:
        protected.scan(staged, releases=swp.ReleaseSelection.ids([missing]))
    assert caught.value.code == "NOT_PROTECTED"
    assert missing in caught.value.message


def test_save_writes_the_document_and_names_the_copy_it_wrote(artifact):
    made, staged = artifact
    outcome = made.scan(staged, save=True)
    saved = outcome.saved
    assert saved is not None
    assert saved.name in made.session.reports()
    assert saved.path == f".swp/private/reports/{saved.name}.json"
    on_disk = made.root / Path(*saved.path.split("/"))
    assert on_disk.is_file()
    assert "\\" not in saved.path
    assert saved.name.startswith("scan-")
    # The name and path are the store's; the document beside them is verbatim.
    stored = made.session.read_report(saved.name)
    assert stored.report.to_json() == outcome.report.to_json()


def test_the_outcome_repr_gives_the_three_values_a_caller_reads_first(artifact):
    made, staged = artifact
    outcome = made.scan(staged)
    assert repr(outcome) == (
        f"ScanOutcome(result='{outcome.report.result}', "
        f"evidence_level='{outcome.report.evidence_level}', "
        f"sites={len(outcome.sites)})"
    )
    row = outcome.sites[0]
    assert repr(row) == (
        f"ScannedSite(release_id='{row.release_id}', site={row.site}, "
        f"status='{row.status}')"
    )
    assert repr(outcome.saved) == "None"


def test_a_saved_copy_is_the_only_place_scan_writes(make_project, tmp_path):
    """A scan of somebody else's tree must not leave a mark on it."""
    made = make_project("scan-purity")
    made.protect(swp.Mode.Release)
    staged = tmp_path / "artifact"
    shutil.copytree(made.child("src"), staged / "src")
    before = sorted(p.relative_to(staged).as_posix() for p in staged.rglob("*"))
    made.scan(staged)
    assert sorted(p.relative_to(staged).as_posix() for p in staged.rglob("*")) == before
