"""The three protection modes, and what each one is allowed to touch.

`protect_summary` is the only protection operation this binding offers, by
[ADR-0001]'s decision: the Rust `protect` returns the keyed plan, and a foreign
binding reads the summary instead. These cases hold both halves of that — the
summary is complete enough to drive a release, and it carries nothing from the plan
it replaced.

The modes differ in one thing only: what they leave behind. Site selection reads the
tree and the project secret, neither of which a rehearsal changes, so `plan`,
`dry_run` and a real release of the same tree report the same run. That is what makes
a rehearsal worth running, and it is why `files_changed` is asserted on here the way
it is: it is the *predicted* rewrite in `plan` and `dry_run`, and the published one in
`release`. `artifacts` and `mode` are what tell the three apart.
"""

from __future__ import annotations

import json
import os
import py_compile
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import swp
from conftest import PRIVATE_FIELD_NAMES, SOURCE_TREE, walk_strings

#: The mode words the CLI, the plan document and the SDK all use for one run.
MODE_WORDS = {"plan", "dry-run", "release"}

#: The keys `ProtectSummary.to_dict()` has: the twenty values the CLI reads beside
#: its verdict, and no plan document among them.
SUMMARY_KEYS = {
    "mode",
    "project_id",
    "release_id",
    "created_at",
    "revision",
    "fingerprint",
    "fingerprint_level",
    "tag_bits",
    "requested_sites",
    "target_sites",
    "sites_embedded",
    "sites_skipped",
    "files_walked",
    "files_in_scope",
    "candidates",
    "files_changed",
    "sites",
    "refusals",
    "artifacts",
    "notes",
}

#: What one row of `files_changed` says, and no more: the byte counts are the run's
#: measurement of the file, not a summary of what was inserted.
PROTECTED_FILE_KEYS = {"file", "sites", "bytes_before", "bytes_after"}


def _bytes_at(project, rel: str) -> int:
    return (project.root / os.path.join(*rel.split("/"))).stat().st_size


def _whole_tree(project) -> dict[str, bytes]:
    """Every byte of every file under the project root, the private store included.

    A rehearsal is only a rehearsal if the disk is the same afterwards, and the half
    of the disk a caller cannot see is the half that has to be checked.
    """
    out: dict[str, bytes] = {}
    for dirpath, _dirnames, filenames in os.walk(project.root):
        for name in filenames:
            path = Path(dirpath) / name
            out[path.relative_to(project.root).as_posix()] = path.read_bytes()
    return out


def _site_rows(summary):
    return [(s.file, s.line_hint, s.class_, s.family, s.width, s.primary) for s in summary.sites]


def _file_rows(summary):
    return [(f.file, f.sites, f.bytes_before, f.bytes_after) for f in summary.files_changed]


def _private_row_keys(project) -> set[str]:
    """Every field name used by a row of the project's own plan or private manifest."""
    keys: set[str] = set()
    for _, document in project.private_documents():
        for value in document.values():
            if isinstance(value, list):
                for row in value:
                    if isinstance(row, dict):
                        keys.update(row)
    return keys


def test_the_three_modes_are_the_three_the_cli_prints():
    assert {m.name for m in (swp.Mode.Plan, swp.Mode.DryRun, swp.Mode.Release)} == MODE_WORDS
    assert str(swp.Mode.Release) == "release"
    assert repr(swp.Mode.Release) == "<Mode.Release>"
    # What a mode may touch is the SDK's answer, not this binding's guess.
    assert swp.Mode.DryRun.writes_source is False
    assert swp.Mode.DryRun.writes_store is False
    assert swp.Mode.Plan.writes_source is False
    assert swp.Mode.Plan.writes_store is True
    assert swp.Mode.Release.writes_source is True
    assert swp.Mode.Release.writes_store is True
    # Equality by value: a `Mode` read back out of an option is the mode passed in.
    assert swp.ProtectOptions(swp.Mode.Plan).mode == swp.Mode.Plan


@pytest.mark.parametrize(
    "mode,word",
    [(swp.Mode.Plan, "plan"), (swp.Mode.DryRun, "dry-run"), (swp.Mode.Release, "release")],
)
def test_every_mode_reports_the_same_run_of_the_same_tree(project, mode, word):
    """The arithmetic is the same in all three; only what they leave differs.

    Every count here is one the CLI prints beside the verdict, so a rehearsal that
    disagreed with a release would be a rehearsal that lied about the budget.
    """
    summary = project.protect(mode)
    assert summary.mode == mode
    assert summary.mode.name == word
    assert summary.sites_embedded >= 1
    assert len(summary.sites) == summary.sites_embedded
    assert len(summary.refusals) == summary.sites_skipped
    assert summary.requested_sites >= summary.target_sites >= summary.sites_embedded
    assert summary.candidates >= summary.sites_embedded + summary.sites_skipped
    assert summary.files_walked >= 1
    assert summary.files_in_scope >= summary.files_walked
    assert summary.tag_bits >= 1
    assert summary.project_id == project.init.project_id


def test_plan_predicts_the_release_file_for_file(make_project):
    """A plan is the constellation the release will apply, byte count for byte count.

    This is the property `swp generate` then `swp protect --release <id>` rests on,
    and it is why `files_changed` is filled in for a mode that writes no source: the
    caller is being told what the release will cost before it happens.
    """
    made = make_project("plan-then-release")
    before = _whole_tree(made)
    planned = made.protect(swp.Mode.Plan)
    assert _file_rows(planned), "a plan that names no file tells the caller nothing"
    after = _whole_tree(made)
    # The one thing a plan writes is its own document, and every source file the
    # plan says it would change is the file it was before the call.
    assert set(after) - set(before) == {f".swp/private/plans/{planned.release_id}.json"}
    for entry in planned.files_changed:
        assert after[entry.file] == before[entry.file], "a plan rewrote no source"
    assert any("no source file was modified" in n for n in planned.notes), planned.notes

    published = made.protect(swp.Mode.Release, release_id=planned.release_id)
    assert published.release_id == planned.release_id
    assert _site_rows(published) == _site_rows(planned)
    assert _file_rows(published) == _file_rows(planned)
    final = _whole_tree(made)
    for entry in published.files_changed:
        assert final[entry.file] != before[entry.file], "the rewrite is on disk"
        assert len(final[entry.file]) == entry.bytes_after, "the plan predicted the disk"


def test_dry_run_writes_nothing_anywhere(make_project):
    """Not a plan, not a manifest, not a byte of source — and still a full account.

    The release id a dry run names is one that does not exist, which is why the
    artifact list is the empty one and the note has to say so.
    """
    made = make_project("dry-run")
    before = _whole_tree(made)
    summary = made.protect(swp.Mode.DryRun)
    assert summary.artifacts == [], "a dry run claims no artifact"
    assert summary.files_changed, "the rehearsal still reports the rewrite it rehearsed"
    assert _whole_tree(made) == before
    assert any("Nothing was written" in n for n in summary.notes), summary.notes
    # The history is the store's own answer: a dry run published no release, so
    # there is nothing to list.
    assert made.session.release_history() == []


def test_plan_writes_only_a_plan_into_the_private_store(make_project):
    """A plan lands in the private store; the manifest and release record do not.

    This is the difference between "a run that decided" and "a run that published",
    read off the artifact list rather than from the mode word: every artifact of a
    plan is a store path, while a release also names the source files it rewrote.
    """
    made = make_project("plan-artifacts")
    before = _whole_tree(made)
    summary = made.protect(swp.Mode.Plan)
    assert any(a.startswith(".swp/private/plans/") for a in summary.artifacts), summary.artifacts
    assert not any(a.startswith(".swp/public/") for a in summary.artifacts), summary.artifacts
    assert not any(a.startswith(".swp/private/manifests/") for a in summary.artifacts)
    assert all(a.startswith(".swp/") for a in summary.artifacts), "no source file was claimed"
    assert _whole_tree(made) != before, "the plan itself is on disk"
    for entry in summary.files_changed:
        written = (made.root / os.path.join(*entry.file.split("/"))).read_bytes()
        assert written == before[entry.file], "the bytes it planned are not the bytes it wrote"
    # The plan document exists, and is the run's own, by id.
    assert (made.root / ".swp" / "private" / "plans" / f"{summary.release_id}.json").is_file()


def test_release_writes_source_records_the_plan_and_publishes_a_release(protected):
    summary = protected.protect(swp.Mode.Release)
    artifacts = summary.artifacts
    assert any(a.startswith(".swp/private/plans/") for a in artifacts)
    assert any(a.startswith(".swp/private/manifests/") for a in artifacts)
    assert any(a.startswith(".swp/public/releases/") for a in artifacts)
    assert summary.files_changed, "a release that rewrote nothing published nothing"
    for entry in summary.files_changed:
        assert entry.file in artifacts, f"{entry.file} was rewritten but not claimed"
        assert entry.bytes_after > entry.bytes_before
        assert entry.sites >= 1
        assert _bytes_at(protected, entry.file) == entry.bytes_after, "sizes are the files' sizes"
    assert sum(e.sites for e in summary.files_changed) == summary.sites_embedded
    assert summary.files_with_sites() == len(summary.files_changed)
    assert any("modified in place" in n for n in summary.notes), summary.notes
    assert protected.session.releases(swp.ReleaseSelection.all())


def test_protected_source_still_compiles(protected):
    """The rewrite must not change what a program computes.

    This is the failure this project exists to avoid, so the check is not that the
    bytes differ but that the file is still valid source: Python compiles here, and
    JavaScript is parsed by `node --check` where that is installed.
    """
    protected.protect(swp.Mode.Release)
    py_compile.compile(str(protected.child("src", "util.py")), doraise=True)
    node = shutil.which("node")
    if node is None:
        return
    path = protected.child("src", "app.js")
    parsed = subprocess.run([node, "--check", str(path)], capture_output=True, text=True)
    assert parsed.returncode == 0, parsed.stderr


def test_the_rewrite_is_a_real_change_in_the_named_place(protected):
    summary = protected.protect(swp.Mode.Release)
    for site in summary.sites:
        entry = next((f for f in summary.files_changed if f.file == site.file), None)
        assert entry is not None, f"{site.file} carries a site but was not rewritten"
        raw = (protected.root / os.path.join(*site.file.split("/"))).read_bytes()
        # Bytes, not text: the files were written with this platform's line endings,
        # and a text read would report fewer bytes than the run measured on disk.
        assert len(raw) == entry.bytes_after
        assert raw != SOURCE_TREE[site.file].encode(), f"{site.file} is claimed and unchanged"
        text = raw.decode("utf-8")
        original = SOURCE_TREE[site.file]
        # The rest of the file survives: a watermark added to one function must not
        # delete the lines around it.
        assert len(text.splitlines()) >= len(original.splitlines())
        for name in re.findall(r"(?:def|function|const|LIMIT)\s+(\w+)", original):
            assert name in text, f"{name} disappeared from {site.file}"


def test_a_refusal_names_a_place_and_a_reason(protected):
    summary = protected.protect(swp.Mode.Release)
    assert summary.refusals, "this fixture tree is built to leave a candidate refused"
    for refusal in summary.refusals:
        assert refusal.file in SOURCE_TREE, "a refusal names a file of the project"
        assert refusal.line_hint >= 1
        assert refusal.reason
    counts = summary.refusal_counts()
    assert set(counts) == {r.reason for r in summary.refusals}
    assert sum(counts.values()) == len(summary.refusals) == summary.sites_skipped
    assert json.dumps(counts)


def test_refusal_counts_are_sorted_and_stable(protected):
    """The same refusals print the same dict, so a log line is comparable."""
    first = protected.protect(swp.Mode.Release).refusal_counts()
    second = protected.protect(swp.Mode.Release).refusal_counts()
    assert list(first) == sorted(first)
    assert list(second) == sorted(second)


def test_sites_are_the_plan_rows_without_the_keyed_identities(protected):
    summary = protected.protect(swp.Mode.Release)
    bounds = swp.capabilities()
    for site in summary.sites:
        assert site.file.startswith("src/")
        assert site.line_hint >= 1
        assert site.language in bounds.language_names()
        assert site.adapter in {"ast", "lexical"}
        assert site.class_ in {"integer", "string"}
        assert site.family
        assert 1 <= site.width <= bounds.tag_bits.max
        assert site.primary in {0, 1, 2, 3}
        document = site.to_dict()
        assert document["class"] == site.class_, "the document key is the word class means"
        assert set(document) == {
            "file",
            "line_hint",
            "language",
            "adapter",
            "class",
            "family",
            "width",
            "primary",
        }, sorted(document)
        json.dumps(document)
    # The keyed half of the plan: every site identity the project's own store holds
    # is absent from every string the summary can print.
    printable = set(walk_strings(summary.to_dict())) | set(walk_strings(repr(summary)))
    assert protected.location_ids().isdisjoint(printable)


def test_no_private_field_name_appears_in_any_summary_form(protected):
    summary = protected.protect(swp.Mode.Release)
    document = summary.to_dict()
    keys = set()

    def collect(node):
        if isinstance(node, dict):
            keys.update(node)
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)

    collect(document)
    assert keys.isdisjoint(PRIVATE_FIELD_NAMES), sorted(keys & PRIVATE_FIELD_NAMES)
    assert set(document) == SUMMARY_KEYS, sorted(set(document) ^ SUMMARY_KEYS)
    # Compared against the real schema, not a list this suite invented: the plan and
    # the private manifest this run wrote do carry the keyed fields, and none of the
    # names they use for them appears anywhere in the summary's document.
    summary_names = set(document)
    for row in document["sites"] + document["refusals"] + document["files_changed"]:
        summary_names |= set(row)
    withheld = _private_row_keys(protected) - summary_names
    assert {"locations", "detail", "grammar_path", "original", "rendered"} <= withheld, sorted(
        withheld
    )
    printed = repr(summary) + repr(summary.sites[0]) + repr(summary.refusals[0]) + repr(
        summary.files_changed[0]
    )
    assert not [name for name in withheld if name in printed], printed


def test_the_summary_is_json_end_to_end(protected):
    document = protected.protect(swp.Mode.Release).to_dict()
    text = json.dumps(document)
    assert json.loads(text) == document
    assert isinstance(document["mode"], str)
    assert document["mode"] in MODE_WORDS, "the dict carries the word, not the enum object"
    assert set(document["files_changed"][0]) == PROTECTED_FILE_KEYS
    assert all(isinstance(a, str) for a in document["artifacts"])


def test_fingerprint_is_the_hex_digest_it_claims_to_be(protected):
    summary = protected.protect(swp.Mode.Release)
    assert re.fullmatch(r"[0-9a-f]{64}", summary.fingerprint), summary.fingerprint
    # The level names the method the §16 fingerprint was taken by, so a later tree
    # can be compared under the rules that produced this one.
    assert re.fullmatch(r"L[1-9]", summary.fingerprint_level), summary.fingerprint_level
    stored = protected.session.release(summary.release_id)
    assert stored.fingerprint == summary.fingerprint
    assert stored.fingerprint_level == summary.fingerprint_level


def test_explicit_release_id_is_honoured_and_a_malformed_one_is_refused(make_project):
    made = make_project("release-id")
    chosen = "rel-" + "a" * 13
    summary = made.protect(swp.Mode.Release, release_id=chosen)
    assert summary.release_id == chosen
    assert made.session.releases(swp.ReleaseSelection.all()) == [chosen]
    with pytest.raises(swp.Error) as caught:
        swp.ProtectOptions(swp.Mode.Release, release_id="not-a-release")
    assert "rel-" in caught.value.message
    assert caught.value.code in set(swp.error_codes())
    assert made.session.releases(swp.ReleaseSelection.all()) == [chosen]


def test_protecting_a_published_id_again_is_refused_not_duplicated(make_project):
    """A release id belongs to one constellation; reusing it would rewrite history."""
    made = make_project("same-id")
    chosen = "rel-" + "b" * 13
    made.protect(swp.Mode.Release, release_id=chosen)
    with pytest.raises(swp.Error) as caught:
        made.protect(swp.Mode.Release, release_id=chosen)
    assert caught.value.code in set(swp.error_codes())
    assert made.session.releases(swp.ReleaseSelection.all()) == [chosen]


def test_revision_is_display_metadata(make_project):
    made = make_project("revision")
    summary = made.protect(swp.Mode.Release, revision="  build-42  ")
    assert summary.revision == "build-42"
    # What the record holds is what the run stored, not what was typed.
    assert made.session.release(summary.release_id).revision == "build-42"
    plain = made.protect(swp.Mode.Release)
    assert plain.revision is None
    assert made.session.release(plain.release_id).revision is None
    assert swp.ProtectOptions(swp.Mode.Plan, revision="x").revision == "x"
    assert swp.ProtectOptions(swp.Mode.Plan).revision is None


#: Labels the door refuses rather than trims away: nothing, nothing but spaces, one
#: byte over the 200-byte cap, and one carrying a control character. `SourceRevision`
#: validates each for its own reason (`swp-identity/src/release.rs:70-91`), and ADR-0002
#: makes the refusal mode-independent, so `plan` and `dry_run` reject them too instead
#: of quietly dropping the label.
UNUSABLE_REVISIONS = ["", "   ", "x" * 201, "a\tb"]


@pytest.mark.parametrize("mode", [swp.Mode.Release, swp.Mode.Plan, swp.Mode.DryRun])
@pytest.mark.parametrize("label", UNUSABLE_REVISIONS)
def test_an_unusable_revision_is_refused_before_anything_is_written(make_project, mode, label):
    """The Python half of the invariant #26 settled, and the one Node already held.

    `ProtectOptions` takes the label without comment — the check is at the door of the
    run (`swp-embedding/src/protect.rs:200`), before the store is asked for a release
    id — so a refusal leaves the project exactly as it was found, private store
    included. `options.rs` validating the label at construction instead would pass
    every assertion below except the one that runs, which is why the pair is here.
    """
    made = make_project("revision-refused")
    options = swp.ProtectOptions(mode, revision=label)
    assert options.revision == label
    before = _whole_tree(made)
    with pytest.raises(swp.Error) as caught:
        made.protect(mode, revision=label)
    assert caught.value.code == "INVALID_MANIFEST", caught.value.message
    assert re.search("revision", caught.value.message), caught.value.message
    assert _whole_tree(made) == before
    assert made.private_documents() == []
    with pytest.raises(swp.Error) as nothing:
        made.session.releases(swp.ReleaseSelection.all())
    assert "no protected releases" in nothing.value.message


def test_target_sites_and_tag_bits_overrides_reach_the_run(make_project):
    """The overridden settings are the ones the run reports, not the stored ones.

    `requested_sites` is what the session was configured to ask for and
    `target_sites` is what the ceilings allowed, so a pair of them is the proof the
    override was applied where the CLI would have applied `--sites`.
    """
    bounds = swp.capabilities()
    made = make_project("site-budget")
    stored = made.session.config.protect.target_sites
    raised = stored + 4
    fewer = swp.Session.open(
        str(made.root), swp.Overrides(target_sites=raised, tag_bits=bounds.tag_bits.max)
    )
    assert fewer.config.protect.target_sites == raised
    assert fewer.config.protect.tag_bits == bounds.tag_bits.max
    assert made.session.stored_config().protect.target_sites == stored
    assert made.session.config.protect.target_sites == stored, "an open does not rewrite the file"
    summary = fewer.protect_summary(swp.ProtectOptions(swp.Mode.Release))
    made.observed.append(summary)
    assert summary.requested_sites == raised
    assert raised >= summary.target_sites >= summary.sites_embedded == len(summary.sites)
    assert summary.tag_bits == bounds.tag_bits.max
    assert summary.release_id == made.session.release_history()[-1].release_id


def test_an_illegal_setting_is_refused_where_the_sdk_judges_it(make_project):
    """`Overrides` takes an int; only the merge with the stored settings knows that 1
    is not a legal site budget, so that is where the refusal has to arrive.

    The binding does not copy the range into Python: a caller that got a
    `TypeError` here would be getting a second implementation of the rule.
    """
    made = make_project("illegal-override")
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(str(made.root), swp.Overrides(target_sites=1))
    assert caught.value.code == "USAGE"
    assert "target_sites" in caught.value.message
    # The refused open wrote nothing: the project is still the one `init` made.
    again = swp.Session.open(str(made.root))
    assert again.identity.project_id == made.init.project_id


def test_a_run_reports_what_it_declined_to_act_on(make_project):
    """A tree with no source in the configured targets is refused, not silently empty."""
    made = make_project("no-source", files={"docs/readme.md": "prose\n" * 10})
    with pytest.raises(swp.Error) as caught:
        made.session.protect_summary(swp.ProtectOptions(swp.Mode.Release))
    assert caught.value.code == "NO_SAFE_LOCATIONS"
    assert "config.toml" in caught.value.message


def test_options_are_frozen_and_printable():
    options = swp.ProtectOptions(swp.Mode.Plan, release_id="rel-" + "c" * 13)
    with pytest.raises((AttributeError, TypeError)):
        options.mode = swp.Mode.Release
    document = options.to_dict()
    assert json.dumps(document)
    assert document["mode"] == "plan", "the dict is the word; the attribute is the Mode"
    assert isinstance(options.mode, swp.Mode)
    assert repr(options) == "ProtectOptions(mode='plan', release_id='rel-ccccccccccccc', revision=None)"
    with pytest.raises((AttributeError, TypeError)):
        swp.Overrides(targets=["x"]).targets = ["y"]
