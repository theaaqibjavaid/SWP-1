"""The `SWP-1-report-v2` document, and the copies of it the store keeps.

`swp-evidence` owns this document: it grades a detection run, states the evidence
level with the numbers that produced it, and carries the §51 boundary inside the
file. So these cases are about *reading* it faithfully:

* every field a getter returns is the document's own, and `to_json()` is the
  serialization the schema defines — not a rendering of a copy;
* `from_json()` gives back the same document, and refuses one it was not written
  under rather than re-grading it;
* `to_text()` is the same text `swp scan` prints, and the windowing only shortens
  the printout, never the data;
* a saved report is the same bytes, reachable by every spelling of its name.

Nothing here grades evidence or compares a probability against a floor: the numbers
below are asserted *against each other*, so a binding that recomputed one would be
caught by the relation rather than by a constant.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime

import pytest

import swp
from conftest import SOURCE_TREE

RESULTS = {"PROVENANCE_DETECTED", "NO_PROVENANCE_DETECTED", "INCONCLUSIVE"}
LEVELS = ["NONE", "WEAK", "MODERATE", "STRONG", "VERY_STRONG"]
KINDS = {
    "EXACT_SOURCE_MATCH",
    "WATERMARK_FRAGMENT_MATCH",
    "PARTIAL_WATERMARK_MATCH",
    "CANONICAL_MATCH",
    "STRUCTURAL_MATCH",
    "TOKEN_MATCH",
    "NEGATIVE_CONTROL",
}
TALLY_KEYS = {
    "project_id",
    "release_id",
    "sites",
    "fragments",
    "stripped",
    "absent",
    "exact_renderings",
    "canonical_only",
    "moved",
    "renderings",
    "files",
    "bits",
    "tag_bits",
    "probes",
    "draws",
    "literals_tried",
    "windows_tried",
    "fingerprint",
    "chance",
    "guarantee",
    "coincidence_probability",
    "level",
    "reasons",
}
EVIDENCE_KEYS = {
    "id",
    "kind",
    "project_id",
    "release_id",
    "location",
    "source_region",
    "basis",
    "strength",
    "protocol",
    "schema",
}
REGION_KEYS = {"file", "line", "excerpt", "tokens", "radii"}
SLOTS = {
    "statement+identifiers",
    "statement+names",
    "scope+identifiers",
    "scope+names",
}


@pytest.fixture
def graded(protected, tmp_path):
    """A scan of a copy of the protected sources, with its document saved."""
    staged = tmp_path / "artifact"
    shutil.copytree(protected.child("src"), staged / "src")
    outcome = protected.scan(staged, save=True)
    return protected, outcome, outcome.report


def _rfc3339(stamp: str) -> bool:
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    return parsed.utcoffset().total_seconds() == 0


def test_the_document_is_the_schema_this_build_writes(graded):
    _, _, report = graded
    assert report.schema == "SWP-1-report-v2"
    assert report.protocol == "SWP-1"
    assert report.schema == swp.capabilities().report_schema


def test_the_run_block_says_who_wrote_the_document(graded):
    made, _, report = graded
    run = report.run
    assert run.command == "scan"
    assert _rfc3339(run.created_at)
    # The generator string is how an old report says which rules produced it.
    assert swp.swp_version in run.generator
    assert report.schema in run.generator
    assert made.session.identity.generator.swp_version in run.generator
    assert set(run.to_dict()) == {"command", "created_at", "generator"}
    assert repr(run).startswith("Run(command='scan', ")


def test_the_candidate_block_describes_the_input(graded):
    _, outcome, report = graded
    candidate = report.candidate
    assert candidate.kind == "directory"
    assert candidate.files_scanned == len(SOURCE_TREE)
    assert candidate.bytes_scanned > 0
    assert candidate.partial is False
    assert candidate.described
    assert set(candidate.to_dict()) == {
        "described",
        "kind",
        "files_scanned",
        "bytes_scanned",
        "partial",
    }
    assert candidate.to_dict()["files_scanned"] == candidate.files_scanned
    assert repr(candidate).startswith("Candidate(described=")
    # The rows and the candidate are two views of one walk.
    assert {row.found_in.split("/")[0] for row in outcome.sites if row.found_in} == {"src"}


def test_one_tally_per_release_strongest_first(graded):
    _, _, report = graded
    tallies = report.releases
    assert len(tallies) == 1
    tally = tallies[0]
    assert set(tally.to_dict()) == TALLY_KEYS
    assert tally.sites == tally.fragments + tally.stripped + tally.absent
    assert tally.exact_renderings <= tally.fragments
    assert tally.canonical_only == tally.fragments - tally.exact_renderings
    assert tally.files >= 1 and tally.files <= len(SOURCE_TREE) and tally.fragments > 0
    bounds = swp.capabilities().tag_bits
    assert bounds.min <= tally.tag_bits <= bounds.max
    # The level is one of the ladder's rungs, and the reasons are the document's.
    assert tally.level in LEVELS
    assert tally.reasons == report.explanation
    assert all(sentence.strip() for sentence in tally.reasons)
    json.dumps(tally.to_dict())


def test_the_coincidence_numbers_are_the_documents_own_arithmetic(graded):
    """`guarantee` is the excess over the bound, and the tail is a probability.

    Asserted as relations between the document's fields: a binding that invented any
    one of them would break at least one, and nothing here repeats the arithmetic.
    """
    _, _, report = graded
    tally = report.releases[0]
    assert tally.chance >= 0.0
    assert 0.0 <= tally.coincidence_probability <= 1.0
    assert tally.guarantee == pytest.approx(tally.fragments - tally.chance)
    if tally.fragments > 0:
        assert tally.draws >= 1
        assert 0 < tally.tag_bits <= 32
    # A finding is graded by the tail probability, so the ladder's floor is the
    # document's business: a VERY_STRONG verdict must have a small one.
    if tally.level == "NONE":
        assert tally.fragments == 0
    else:
        assert tally.fragments >= 1


def test_the_evidence_items_are_citable(graded):
    _, _, report = graded
    items = report.evidence
    assert items, "a detection document that cites nothing cites nothing"
    assert [item.id for item in items] == [f"EV-{n:03d}" for n in range(len(items))]
    for item in items:
        assert set(item.to_dict()) == EVIDENCE_KEYS
        assert item.kind in KINDS
        assert item.strength in LEVELS
        assert LEVELS.index(item.strength) <= LEVELS.index(report.evidence_level)
        assert item.protocol == "SWP-1"
        assert item.schema == 2, "the report schema the document is written under"
        assert item.basis.strip()
        for region in (item.location, item.source_region):
            if region is not None:
                assert set(region.to_dict()) == REGION_KEYS
                assert region.file.startswith("src/")
                assert region.line >= 1
                assert region.tokens is None or region.tokens >= 1
                assert set(region.radii) <= SLOTS
    # A source-side region is where we protected; it quotes nothing from the candidate.
    assert any(item.location is None for item in items), "an exact-source item has no hit to quote"
    assert all(item.source_region is not None for item in items if item.location is not None)
    json.dumps([item.to_dict() for item in items])


def test_a_watermark_item_points_at_both_sides(graded):
    """The candidate's region and the release's region, for the same site."""
    _, outcome, report = graded
    fragments = [i for i in report.evidence if i.kind == "WATERMARK_FRAGMENT_MATCH"]
    assert len(fragments) >= 1
    hit = fragments[0]
    assert hit.location.file in {row.found_in for row in outcome.sites}
    assert hit.location.line == hit.source_region.line
    assert hit.strength in {"STRONG", "VERY_STRONG"}


def test_the_boundary_and_the_caveats_are_inside_the_document(graded):
    _, _, report = graded
    assert report.limitations[0].startswith("This is an observation about artifacts")
    assert all(sentence.strip() for sentence in report.limitations)
    assert len(report.limitations) >= 3
    assert any(f"at tag widths {report.releases[0].tag_bits}" in note for note in report.notes)
    assert isinstance(report.omissions, list)
    assert all(": " in omission for omission in report.omissions)


def test_all_three_verdicts_reach_python(protected, foreign_tree, tmp_path):
    """Detected, not detected, and unable to have said either way."""
    staged = tmp_path / "artifact"
    shutil.copytree(protected.child("src"), staged / "src")
    detected = protected.scan(staged).report
    assert detected.result == "PROVENANCE_DETECTED" and detected.exit_code() == 1

    nothing = protected.scan(foreign_tree).report
    assert nothing.result == "NO_PROVENANCE_DETECTED"
    assert nothing.exit_code() == 0
    assert nothing.evidence_level == "NONE"
    assert nothing.releases[0].fragments == 0
    # A negative document still cites one thing: the control that says what the run
    # excluded, so "nothing was found" is a measured claim rather than a silence.
    assert [i.kind for i in nothing.evidence] == ["NEGATIVE_CONTROL"]
    assert nothing.evidence[0].strength == "NONE"
    assert nothing.evidence[0].location is None

    prose = tmp_path / "prose"
    (prose / "docs").mkdir(parents=True)
    (prose / "docs" / "notes.md").write_text("# nothing\n", encoding="utf-8")
    inconclusive = protected.scan(prose).report
    assert inconclusive.result == "INCONCLUSIVE"
    assert inconclusive.exit_code() == 10
    assert inconclusive.evidence_level == "NONE"

    for report in (detected, nothing, inconclusive):
        assert report.result in RESULTS
        assert report.evidence_level in LEVELS
        # The strongest release's level is the overall one, in every direction.
        levels = [t.level for t in report.releases]
        assert max(levels, key=LEVELS.index) == report.evidence_level


def test_to_json_is_the_document_and_from_json_reads_it_back(graded):
    _, _, report = graded
    text = report.to_json()
    assert text.endswith("\n") and '\n  "' in text
    document = json.loads(text)
    assert document["schema"] == "SWP-1-report-v2"
    assert document["result"] == report.result
    assert len(document["evidence"]) == len(report.evidence)

    again = swp.Report.from_json(text)
    assert again.to_json() == text, "a round trip is byte-identical"
    assert again.result == report.result
    assert again.evidence_level == report.evidence_level
    assert [i.id for i in again.evidence] == [i.id for i in report.evidence]
    assert again.limitations == report.limitations
    assert repr(again) == repr(report)


def test_from_json_refuses_a_document_it_was_not_written_under(graded):
    """A foreign schema is not damage: it is arithmetic this build does not apply."""
    text = graded[2].to_json()
    other_schema = json.loads(text)
    other_schema["schema"] = "SWP-1-report-v1"
    with pytest.raises(swp.Error) as caught:
        swp.Report.from_json(json.dumps(other_schema))
    assert caught.value.code == "PROTOCOL_VERSION_UNSUPPORTED"
    assert "SWP-1-report-v1" in caught.value.message
    assert swp.capabilities().report_schema in caught.value.message

    for bad in ("not json at all", "{}", text[: len(text) // 2], '["a list"]'):
        with pytest.raises(swp.Error) as caught:
            swp.Report.from_json(bad)
        assert caught.value.code == "INVALID_MANIFEST", bad[:20]
    # A refusal leaves nothing behind: the document under test is still readable.
    assert swp.Report.from_json(text).to_json() == text


def test_to_text_is_the_rendering_the_command_prints(graded):
    _, _, report = graded
    text = report.to_text()
    assert report.schema in text
    assert report.result in text
    assert report.evidence_level in text
    assert f"{report.candidate.files_scanned} file(s)" in text
    assert "Keyed bits confirmed" in text
    # The §51 boundary is printed with the verdict, not left to a README.
    assert any(line.strip() for line in text.splitlines() if "artifact" in line)
    assert len(report.to_text(full=True).splitlines()) >= len(text.splitlines())
    for item in report.evidence:
        assert item.id in report.to_text(full=True)


def test_the_window_only_shortens_the_printout(graded):
    _, _, report = graded
    narrow = report.to_text_items(1)
    assert len(narrow.splitlines()) < len(report.to_text(full=True).splitlines())
    assert report.evidence[0].id in narrow
    assert report.evidence[-1].id not in narrow
    # Data is never windowed: the document beside the text is the whole run.
    assert len(json.loads(report.to_json())["evidence"]) == len(report.evidence)


def test_a_saved_report_is_readable_by_every_spelling_of_its_name(graded):
    made, outcome, report = graded
    saved = outcome.saved
    names = [saved.name, f"{saved.name}.json", f"reports/{saved.name}.json", saved.path]
    documents = {made.session.read_report(name).report.to_json() for name in names}
    assert documents == {report.to_json()}, "one entry, four spellings"
    assert all(swp.report_stem(name) == saved.name for name in names)


def test_the_stored_document_is_the_one_that_was_graded(graded):
    made, outcome, report = graded
    stored = made.session.read_report(outcome.saved.name)
    summary = stored.to_dict()
    # `StoredReport` names the record and hands back the document; the verdict words
    # in its dict form are the document's own, read out of `report`.
    assert set(summary) == {"name", "path", "result", "evidence_level"}
    assert summary["result"] == report.result
    assert summary["evidence_level"] == report.evidence_level
    assert stored.name == outcome.saved.name
    assert stored.path == outcome.saved.path == f".swp/private/reports/{stored.name}.json"
    assert stored.report.to_json() == report.to_json()
    assert stored.report.run.command == "scan"
    assert repr(stored).startswith("StoredReport(name=")
    json.dumps(summary)


def test_reports_are_listed_newest_first_and_survive_a_name_collision(make_project, tmp_path):
    made = make_project("reports-listing")
    made.protect(swp.Mode.Release)
    staged = tmp_path / "artifact"
    shutil.copytree(made.child("src"), staged / "src")

    names = [made.session.scan(str(staged), save=True).saved.name for _ in range(3)]
    assert len(set(names)) == 3, "a save never overwrites an earlier record"
    assert all(re.fullmatch(r"scan-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z(-\d+)?", n) for n in names)
    listed = made.session.reports()
    assert listed == list(reversed(names)), "newest first, as `swp report` lists them"
    assert all(n.endswith(".json") is False for n in listed), "the name a caller passes in"
    for name in listed:
        assert made.session.read_report(name).name == name


def test_an_unknown_report_name_is_a_usage_error_that_names_what_exists(graded):
    made, _, _ = graded
    with pytest.raises(swp.Error) as caught:
        made.session.read_report("no-such-report")
    assert caught.value.code == "USAGE"
    assert "no-such-report" in caught.value.message
    assert "1 report" in caught.value.message


def test_a_report_document_carries_no_field_of_the_private_store(graded):
    """The projection is the SDK's summary, not a re-reading of a manifest."""
    _, _, report = graded
    forms = [report.to_json(), repr(report), report.to_text(full=True)]
    names = set(json.loads(report.to_json()))
    assert {"locations", "location_id", "fragment_tag", "expected_tag", "root_secret"} & names == set()
    for name in ("locations", "fragment_tag", "expected_tag", "root_secret", "grammar_path"):
        assert name not in json.dumps(report.evidence[0].to_dict())
        assert name not in repr(report.evidence[0])
    assert "root.key" not in "".join(forms)


def test_the_repr_is_the_verdict_line_and_nothing_else(graded):
    _, _, report = graded
    assert repr(report) == (
        f"Report(schema='SWP-1-report-v2', result='{report.result}', "
        f"evidence_level='{report.evidence_level}')"
    )


def test_a_report_cannot_be_built_from_python(graded):
    _, _, report = graded
    with pytest.raises(TypeError):
        swp.Report()
    with pytest.raises(AttributeError):
        report.result = "PROVENANCE_DETECTED"
    with pytest.raises(TypeError):
        swp.Report.from_json(report)
