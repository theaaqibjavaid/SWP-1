"""Grading your own tree: what `Session.verify` hands back.

Every case here runs against a release the fixture published, and the assertions
are about the document `swp-evidence` graded — not about arithmetic this suite
performs. Three kinds of claim are made, and they are deliberately different:

* **the document's own words** — the verdict, the fingerprint, the exit code, the
  advice. The binding only reads them off; a test that recomputed a verdict would
  pass on a binding that ignored the SDK's judgement and drew its own conclusion.
* **internal consistency** — the site counts equal the rows, the statuses are the
  detector's vocabulary, `to_json()` agrees with `to_dict()` and with every getter.
  A copy of a document can drift from its own fields; these cases are why this
  binding holds one value rather than a dozen copies of it.
* **the same site in two documents** — the plan rows `protect_summary` returned and
  the verify rows this call returns describe the same locations, so a binding that
  renumbered or re-derived them is caught here.

The tamper cases damage the protected tree afterwards, which is the only way to
see a grade that is not `INTACT` without inventing a release. What a damaged site
becomes (`absent`, `location-only` or `tag-confirmed`) depends on the code the
drawn key gave it, so those cases assert the invariants that hold either way.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

import pytest

import swp
from conftest import SOURCE_TREE

#: The document's site statuses, as `swp-detection` spells them.
SITE_STATUSES = {"absent", "location-only", "tag-confirmed", "exact-rendering"}

#: The watermark grades: a site carrying its code, at one radius or the recorded one.
CONFIRMED_STATUSES = {"tag-confirmed", "exact-rendering"}

#: The 32 fields of `SWP-1-verify-v1`, as this binding projects them.
OUTCOME_KEYS = {
    "schema",
    "protocol",
    "project_id",
    "display_name",
    "tree",
    "release_id",
    "release_created_at",
    "revision",
    "manifest_authenticated",
    "sites_expected",
    "sites_confirmed",
    "sites_exact",
    "sites_stripped",
    "sites_absent",
    "sites_moved",
    "sites_refactored",
    "tag_bits",
    "confirmed_bits",
    "files_scanned",
    "bytes_scanned",
    "fingerprint",
    "fingerprint_expected",
    "verdict",
    "partial",
    "sites",
    "omitted_rows",
    "omissions",
    "notes",
    "report_saved",
    "limitations",
    "next",
    "exit_code",
}

ROW_KEYS = {
    "site",
    "file",
    "line_hint",
    "language",
    "adapter",
    "class",
    "family",
    "width",
    "status",
    "confirmed",
    "slots",
    "found_in",
    "found_line",
    "refactored",
    "moved",
}

#: The four keyed radii a confirming span can be reproduced by.
SLOTS = {
    "statement+identifiers",
    "statement+names",
    "scope+identifiers",
    "scope+names",
}

SCENARIOS = ["intact", "deleted", "edited", "moved"]


def _release(make_project, label: str):
    """A project and the summary of the one release it published."""
    made = make_project(label)
    return made, made.protect(swp.Mode.Release)


def _relocated(row) -> str:
    """Where `_damage` moves a site's file to, keeping the extension it parses by."""
    return f"src/relocated{Path(row.file).suffix}"


def _damage(root: Path, row, scenario: str) -> None:
    """Damage the protected tree the way one of the four scenarios says."""
    path = root / row.file
    lines = path.read_text(encoding="utf-8").splitlines()
    assert 0 < row.line_hint <= len(lines), (row.line_hint, lines)
    if scenario == "deleted":
        path.unlink()
    elif scenario == "moved":
        # Byte-for-byte the same file under a new name, and the same extension: the
        # adapter selects on the suffix, so a move that changed the file type would
        # be a rewrite of the source in a different language rather than a move.
        (root / _relocated(row)).write_bytes(path.read_bytes())
        path.unlink()
    elif scenario == "edited":
        lines[row.line_hint - 1] = re.sub(
            r"\d+", "999999", lines[row.line_hint - 1], count=1
        )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:  # pragma: no cover - a typo in SCENARIOS, not a product path
        raise AssertionError(f"unknown scenario {scenario}")


@pytest.fixture
def graded(make_project, request):
    """One release, verified before and after one of four things happened to it."""
    made, summary = _release(make_project, f"verify-{request.param}")
    first = made.verify()
    if request.param != "intact":
        _damage(made.root, first.sites[0], request.param)
    return made, summary, first, made.verify()


@pytest.mark.parametrize("graded", SCENARIOS, indirect=True)
def test_the_document_is_internally_consistent(graded):
    """The counts are the rows, and the exit code is the verdict's own.

    A binding that kept a copy could report `sites_confirmed` from one place and the
    rows from another; that is what this case rules out.
    """
    _, summary, _, outcome = graded
    rows = outcome.sites
    document = outcome.to_dict()

    assert outcome.sites_expected == len(rows) == summary.sites_embedded
    assert outcome.sites_confirmed == sum(1 for r in rows if r.confirmed)
    assert outcome.sites_exact == sum(1 for r in rows if r.status == "exact-rendering")
    assert outcome.sites_stripped == sum(1 for r in rows if r.status == "location-only")
    assert outcome.sites_absent == sum(1 for r in rows if r.status == "absent")
    assert outcome.sites_moved == sum(1 for r in rows if r.moved)
    assert outcome.sites_refactored == sum(1 for r in rows if r.refactored)
    assert all(r.status in SITE_STATUSES for r in rows)
    assert all(r.confirmed == (r.status in CONFIRMED_STATUSES) for r in rows)
    # A site is watermark evidence, an address without a code, or missing.
    assert (
        outcome.sites_confirmed + outcome.sites_stripped + outcome.sites_absent
        == outcome.sites_expected
    )
    assert outcome.sites_exact <= outcome.sites_confirmed <= outcome.sites_expected
    assert document["sites_confirmed"] == outcome.sites_confirmed
    # The keyed evidence is the width of every site that is carrying its code.
    assert outcome.confirmed_bits == sum(r.width for r in rows if r.confirmed)

    assert outcome.verdict in {"INTACT", "INCOMPLETE", "INCONCLUSIVE"}
    assert outcome.exit_code == {
        "INTACT": 0,
        "INCOMPLETE": 5,
        "INCONCLUSIVE": 10,
    }[outcome.verdict]
    assert (outcome.sites_confirmed == outcome.sites_expected) == (
        outcome.verdict == "INTACT"
    ), "every site carrying its code is exactly what INTACT claims"
    assert (outcome.verdict == "INCONCLUSIVE") == outcome.partial

    assert outcome.schema == "SWP-1-verify-v1"
    assert outcome.protocol == "SWP-1"
    assert outcome.manifest_authenticated is True
    assert json.loads(outcome.to_json())["exit_code"] == outcome.exit_code


@pytest.mark.parametrize("graded", ["intact", "deleted"], indirect=True)
def test_an_untouched_tree_is_intact_and_a_missing_file_is_not(graded):
    made, summary, _, outcome = graded
    assert Path(outcome.tree).resolve() == made.root.resolve()
    assert outcome.display_name == made.session.identity.display_name
    if outcome.verdict == "INTACT":
        assert outcome.exit_code == 0
        assert outcome.fingerprint == "match"
        assert outcome.sites_absent == outcome.sites_moved == 0
        assert outcome.files_scanned == len(SOURCE_TREE)
        # The protected tree is larger than the sources that went into it.
        assert outcome.bytes_scanned > sum(len(t.encode()) for t in SOURCE_TREE.values())
        assert all(r.status == "exact-rendering" for r in outcome.sites)
    else:
        assert outcome.verdict == "INCOMPLETE"
        assert outcome.exit_code == 5
        assert outcome.fingerprint == "no-match"
        assert outcome.sites_absent == 1
        assert outcome.files_scanned == len(SOURCE_TREE) - 1
        lost = {r.site: r for r in outcome.sites}[0]
        assert lost.file == summary.sites[0].file
        assert lost.status == "absent" and lost.confirmed is False


@pytest.mark.parametrize("graded", ["edited"], indirect=True)
def test_a_damaged_literal_cannot_claim_the_rendering_it_recorded(graded):
    """The tree fingerprint goes stale the moment a byte moves; the grade may follow.

    Whether the edited site is still `tag-confirmed` at one of the four radii is the
    drawn key's business — measured both ways across runs — so this case stops at
    what cannot vary: the recorded rendering is gone, and the other sites are not.
    """
    _, summary, _, outcome = graded
    damaged = {r.site: r for r in outcome.sites}[0]
    assert outcome.fingerprint == "no-match"
    assert outcome.sites_expected == summary.sites_embedded
    assert damaged.status in SITE_STATUSES - {"exact-rendering"}
    assert outcome.sites_exact == outcome.sites_expected - 1
    assert all(
        r.status == "exact-rendering" for r in outcome.sites if r.site != damaged.site
    )


@pytest.mark.parametrize("graded", ["moved"], indirect=True)
def test_a_moved_site_is_the_same_site_found_somewhere_else(graded):
    """`file` stays where the release put it; `found_in` says where the mark is now.

    A move is reported beside the row rather than as a new site or a lost one: the
    index, the line hint and the shape are still the plan's, and every site of the
    release is still carrying its code — so the verdict is INTACT even though the
    tree no longer hashes to the published fingerprint.
    """
    _, summary, _, outcome = graded
    moved = [r for r in outcome.sites if r.moved]
    assert len(moved) == outcome.sites_moved == 1
    row = moved[0]
    assert row.site == 0
    assert row.file == summary.sites[0].file
    assert row.found_in == f"src/relocated{Path(row.file).suffix}"
    assert row.found_line == row.line_hint
    assert row.status == "exact-rendering" and row.confirmed is True
    assert row.refactored is False
    assert outcome.sites_absent == 0
    assert outcome.verdict == "INTACT" and outcome.exit_code == 0
    assert outcome.fingerprint == "no-match"


@pytest.mark.parametrize("graded", SCENARIOS, indirect=True)
def test_the_rows_are_the_plan_sites_with_a_grade_added(graded):
    """Same index, same location, same shape — a verify row is a plan row.

    The plan's `primary` slot selector and the document's `slots` list are two
    spellings of one fact, and this is also where the binding's rename of `class`
    to `class_` is checked against the document's own key.
    """
    _, summary, _, outcome = graded
    planned = dict(enumerate(summary.sites))
    seen = set()
    for row in outcome.sites:
        assert row.site not in seen, "a site index keys the release, it is not a counter"
        seen.add(row.site)
        site = planned[row.site]
        assert (
            row.file,
            row.line_hint,
            row.language,
            row.adapter,
            row.class_,
            row.family,
            row.width,
        ) == (
            site.file,
            site.line_hint,
            site.language,
            site.adapter,
            site.class_,
            site.family,
            site.width,
        )
        assert row.adapter in {"ast", "lexical"}
        assert row.class_ in {"integer", "string"}
        assert row.width == outcome.tag_bits
        assert set(row.slots) <= SLOTS
        assert set(row.to_dict()) == ROW_KEYS
        assert (row.found_line is not None) == (row.found_in is not None)
        if row.confirmed:
            assert row.found_in is not None, "a confirmed site was found somewhere"
            if row.moved:
                assert row.found_in != row.file
            else:
                assert row.found_in == row.file
        else:
            assert row.status in {"absent", "location-only"}
    assert seen == set(range(outcome.sites_expected))


@pytest.mark.parametrize("graded", SCENARIOS, indirect=True)
def test_the_document_form_holds_every_getter_and_nothing_else(graded):
    _, _, _, outcome = graded
    document = outcome.to_dict()
    assert set(document) == OUTCOME_KEYS
    json.dumps(document)
    for name, value in document.items():
        if name == "sites":
            assert [row["site"] for row in value] == [r.site for r in outcome.sites]
        else:
            assert value == getattr(outcome, name), name


@pytest.mark.parametrize("graded", ["intact", "deleted"], indirect=True)
def test_to_json_is_the_document_the_command_would_print(graded):
    _, summary, _, outcome = graded
    text = outcome.to_json()
    assert text.endswith("\n") and '\n  "' in text, "pretty-printed, as the CLI prints it"
    document = json.loads(text)
    assert document["schema"] == "SWP-1-verify-v1"
    assert document["verdict"] == outcome.verdict
    assert document["release_id"] == summary.release_id
    assert len(document["sites"]) == outcome.sites_expected
    assert document["sites"][0]["class"] in {"integer", "string"}
    assert "class_" not in text, "the document key is the schema's own"


@pytest.mark.parametrize("graded", SCENARIOS, indirect=True)
def test_the_advice_and_the_boundary_travel_inside_the_document(graded):
    _, summary, _, outcome = graded
    assert outcome.limitations[0].startswith(
        "a site that carries its code is a statement about this artifact"
    ), "the §51 boundary is the first thing a forwarded report still says"
    assert all(sentence.strip() for sentence in outcome.limitations)
    assert outcome.next[0] == f"swp inspect manifest --release {summary.release_id}"
    assert (len(outcome.next) == 3) == (outcome.verdict != "INTACT")
    if outcome.verdict != "INTACT":
        assert "swp protect" in outcome.next
    assert any(f"at tag widths {outcome.tag_bits}" in note for note in outcome.notes)
    # The store's own `.gitignore` is declined by the walk. A decline is a named
    # omission, not a hole in the tree: `partial` says something else entirely.
    assert all(": " in omission for omission in outcome.omissions)
    assert outcome.partial is False


def test_a_second_release_is_only_verified_when_it_is_asked_for(make_project):
    """`latest` is the newest record; an explicit id reads that constellation alone.

    Which of two releases is "newest" is `newest`'s answer in `swp-sdk` (crates/swp-sdk/
    src/session.rs:502): the recorded time, and on a tie inside one second the larger
    release id. Ids are drawn, so a test may not assume the *second* run is the newest —
    only that the default call reads whatever the store says is. What is deterministic is
    the other half: the tree carries the second run's codes, because that run rewrote the
    source, so that is the constellation that matches and the first is the one that does
    not.
    """
    made, first = _release(make_project, "verify-two-releases")
    second = made.protect(swp.Mode.Release, revision="build-7")
    assert second.release_id != first.release_id

    newest = made.session.releases(swp.ReleaseSelection.latest())[0]
    by_default = made.verify()
    assert by_default.release_id == newest

    matches = made.verify(release=second.release_id)
    assert matches.verdict == "INTACT" and matches.fingerprint == "match"
    assert matches.revision == "build-7", "the label the release recorded, or nothing"
    assert matches.sites_expected == second.sites_embedded

    older = made.verify(release=first.release_id)
    assert older.release_id == first.release_id
    assert older.fingerprint == "no-match"
    assert older.verdict != "INTACT"
    assert older.revision is None
    assert older.sites_expected == first.sites_embedded

    # Naming the newest release asks for what the default call already answered.
    assert by_default.to_dict() == (matches if newest == second.release_id else older).to_dict()


def test_the_release_record_and_the_document_describe_one_run(make_project):
    made, summary = _release(make_project, "verify-record")
    outcome = made.verify()
    record = made.session.release(outcome.release_id)
    assert record.release_id == outcome.release_id == summary.release_id
    assert record.project_id == outcome.project_id
    assert record.fingerprint == outcome.fingerprint_expected
    assert re.fullmatch(r"[0-9a-f]{64}", outcome.fingerprint_expected)
    assert record.watermark.tag_bits == outcome.tag_bits
    assert record.watermark.sites_embedded == outcome.sites_expected
    parsed = datetime.fromisoformat(outcome.release_created_at.replace("Z", "+00:00"))
    assert parsed.utcoffset().total_seconds() == 0


def test_a_save_writes_the_report_and_names_where_it_went(make_project):
    made, _ = _release(make_project, "verify-save")
    unsaved = made.verify()
    assert unsaved.report_saved is None
    assert made.session.reports() == []

    saved = made.verify(save=True)
    path = saved.report_saved
    assert re.fullmatch(
        r"\.swp/private/reports/verify-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z(-\d+)?\.json", path
    ), path
    assert "\\" not in path, "store-relative and forward-slashed, so it is safe to print"
    assert (made.root / Path(*path.split("/"))).is_file()
    stem = swp.report_stem(path)
    assert made.session.reports() == [stem]

    again = made.verify(save=True)
    assert again.report_saved != path, "a save never clobbers an earlier record"
    assert (made.root / Path(*again.report_saved.split("/"))).is_file()
    assert set(made.session.reports()) == {stem, swp.report_stem(again.report_saved)}
    assert unsaved.report_saved is None, "a run that did not save says it did not save"

    # The saved copy is the `SWP-1-report-v2` document the same run graded.
    stored = made.session.read_report(stem)
    assert stored.name == stem and stored.path == path
    assert stored.report.schema == "SWP-1-report-v2"
    assert stored.report.run.command == "verify"
    assert stored.report.result == "PROVENANCE_DETECTED"
    assert stored.report.candidate.files_scanned == unsaved.files_scanned
    assert swp.Report.from_json(stored.report.to_json()).to_json() == stored.report.to_json()


def test_rows_windows_only_the_text_rendering(make_project):
    """`rows` is `--rows`: it counts what the printout left out, and hides nothing.

    The getters and the stored document still hold every site, because a windowed
    site list would be a different artifact than the one that was graded.
    """
    made, summary = _release(make_project, "verify-rows")
    narrow = made.verify(rows=1)
    assert narrow.omitted_rows == summary.sites_embedded - 1
    assert len(narrow.sites) == summary.sites_embedded
    assert len(narrow.to_dict()["sites"]) == summary.sites_embedded
    assert json.loads(narrow.to_json())["sites"] == json.loads(
        made.verify().to_json()
    )["sites"]
    assert made.verify().omitted_rows == 0
    assert made.verify(rows=99).omitted_rows == 0


def test_a_release_this_project_never_published_is_refused(protected):
    missing = "rel-" + "q" * 13
    with pytest.raises(swp.Error) as caught:
        protected.verify(release=missing)
    assert caught.value.code == "NOT_PROTECTED"
    assert missing in caught.value.message
    assert "It has release" in caught.value.message
    with pytest.raises(swp.Error) as caught:
        swp.VerifyOptions(release="not-a-release")
    assert "rel-" in caught.value.message


def test_verifying_a_project_with_no_releases_is_refused(project):
    with pytest.raises(swp.Error) as caught:
        project.verify()
    assert caught.value.code == "NOT_PROTECTED"
    assert caught.value.next_step


@pytest.mark.parametrize("graded", ["intact"], indirect=True)
def test_an_outcome_is_read_only_and_cannot_be_built_from_python(graded):
    _, _, _, outcome = graded
    with pytest.raises(AttributeError):
        outcome.verdict = "INTACT"
    with pytest.raises(TypeError):
        swp.VerifyOutcome()
    with pytest.raises(TypeError):
        swp.SiteRow()


@pytest.mark.parametrize("graded", ["intact"], indirect=True)
def test_repr_states_the_release_the_verdict_and_the_counts(graded):
    _, summary, _, outcome = graded
    assert repr(outcome) == (
        f"VerifyOutcome(release_id='{summary.release_id}', verdict='{outcome.verdict}', "
        f"sites_confirmed={outcome.sites_confirmed}/{outcome.sites_expected})"
    )
    first = outcome.sites[0]
    assert repr(first).startswith(f"SiteRow(site={first.site}, file='")
    assert "class='integer'" in repr(first) or "class='string'" in repr(first)
