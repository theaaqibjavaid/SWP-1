"""Nothing a Python caller can read is keyed material, a site identity, or the private half.

This is the binding's version of the Rust `secret_leak` suite, and it works the same
way: it does not check that the code *avoids* certain variables. It takes every object
a real run handed back and prints it — `repr()`, `to_dict()`, `to_json()`, `to_text()` —
then looks for needles. The needles are read off the project's own store: the sealed
root secret in both of its spellings, and the keyed site identities the private plan
holds. Neither set is invented here, which is what makes their absence meaningful
rather than tautological.

Four claims sit behind the sweeps:

* a value that is keyed never crosses — no root secret, no derived rendering of it, no
  location id, and no field value the private documents keep under a keyed name;
* a document that is private never crosses: the plan's and the manifest's field names
  are not the shape of anything the binding offers, because the binding reads the
  summaries `swp-sdk` hands back and builds nothing itself;
* a *name* for the private half never crosses: the module exports no class or method
  that would be an accessor for a store, a secret or a plan, and `read_report` cannot
  be pointed at the manifests folder by naming a path;
* a private path is named only by the two lists that exist to disclose it —
  `InitResult.created` and `ProtectSummary.artifacts`, the same lists `swp init` and
  `swp protect` print in their JSON — and by nothing else.

The positive control is part of the test. A sweep whose needle sets were empty would
pass on a binding that leaked everything, so every case first asserts that this project
really does hold ids and secret renderings, and that the sweep ran over a great many
characters.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import swp
from conftest import PRIVATE_FIELD_NAMES, Project, documents_of

#: Field names the private half uses for a value it keeps to itself. A private
#: document's value under one of these keys contributes a needle.
#:
#: Two private values are deliberately *not* here. `rendered` is the protected
#: rendering of a literal, and a scan report quotes the text it found — that is what
#: an evidence excerpt is. `fingerprint` is the §16 tree fingerprint, published in the
#: release record and printed by `swp verify`. Excluding them is what keeps this sweep
#: a statement about the boundary rather than a statement about nothing.
KEYED_FIELDS = frozenset(
    {
        "locations",
        "location_id",
        "location_ids",
        "fragment_tag",
        "expected_tag",
        "grammar_path",
        "root_secret",
        "secret_bytes",
        "signature",
    }
)

#: The identifiers the boundary reserves for the private crates. Matched exactly, so a
#: documented name that merely contains one of these words is not accused.
FORBIDDEN_NAMES = frozenset(
    {
        "RootSecret",
        "SecretBytes",
        "ManifestKeys",
        "ReleaseIndex",
        "CandidateRelease",
        "Protection",
        "Plan",
        "PlannedSite",
        "SkippedSite",
        "LocationId",
        "Store",
        "open_store",
        "store",
        "fragment_tag",
        "expected_tag",
        "root_key",
        "secret",
    }
)

#: Directories whose documents are unsigned intermediate state: the binding is not
#: given them, so nothing it prints should send a caller looking for them.
#: `.swp/private/reports/` is deliberately absent — `verify(save=True)` and
#: `scan(save=True)` name where they wrote, and a path is not the document.
PRIVATE_DIRS = (".swp/private/plans", ".swp/private/manifests", ".swp/private/root.key")

#: The two values allowed to name those paths, because listing what a run wrote is
#: their documented job — `swp protect --format json` prints the same `artifacts`.
DISCLOSING = (swp.InitResult, swp.ProtectSummary)


@pytest.fixture
def run_everything(make_project):
    """One project taken through init, protect, verify, scan and the store's listings.

    Everything the binding can hand back is in `observed`, because the tests that
    populate it record what they received rather than what this file expects to see.
    """
    made = make_project("leak")
    made.protect(swp.Mode.Release)
    made.protect(swp.Mode.Plan)
    made.verify(save=True)
    scanned = made.scan(made.root, save=True)
    latest = made.session.releases(swp.ReleaseSelection.latest())[0]
    made.observed.extend(
        [
            made.session,
            made.session.identity,
            made.session.config,
            made.session.limits,
            made.session.release(latest),
            made.session.read_report(Path(scanned.saved.path).name),
            scanned.report,
            scanned.saved,
        ]
    )
    made.observed.extend(made.session.release_history())
    return made


def needles(project: Project) -> set[str]:
    """The strings that must never appear in anything Python can print."""
    out = {n for n in project.secret_strings() if len(n) >= 8}
    out |= {n for n in project.location_ids() if len(n) >= 8}
    assert out, "the store holds no secret rendering and no site id: nothing was tested"
    return out


def keyed_values(project: Project) -> set[str]:
    """Every value the private documents keep under a keyed field name.

    Read from the disk rather than from a list this file maintains, so a new keyed
    field in a plan or a manifest contributes a needle on the day it appears.
    """
    found = set()

    def walk(value, key=None):
        if isinstance(value, dict):
            for name, nested in value.items():
                walk(nested, name)
        elif isinstance(value, list):
            for nested in value:
                walk(nested, key)
        elif isinstance(value, str) and key in KEYED_FIELDS and len(value) >= 8:
            found.add(value)

    documents = project.private_documents()
    assert documents, "the run left no private document, so this sweep read nothing"
    for _, document in documents:
        walk(document)
    assert found, "no private document holds a keyed value"
    return found


def printed(obj) -> list[str]:
    """Every rendering this object offers, each produced the way a caller would.

    An object that raises while being printed is a finding of its own, so the failure
    is reported rather than skipped.
    """
    out = []
    try:
        out.append(f"repr: {obj!r}")
    except Exception as e:  # noqa: BLE001 - the assertion is the point
        pytest.fail(f"{type(obj).__name__} cannot be repr'd: {e}")
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        try:
            out.append("dict: " + json.dumps(to_dict(), indent=1))
        except Exception as e:  # noqa: BLE001
            pytest.fail(f"{type(obj).__name__}.to_dict() is not printable: {e}")
    to_json = getattr(obj, "to_json", None)
    if callable(to_json):
        out.append("json: " + to_json())
    to_text = getattr(obj, "to_text", None)
    if callable(to_text):
        for full in (False, True):
            out.append(f"text(full={full}): " + to_text(full=full))
        out.append("text(items=1): " + obj.to_text_items(1))
    return out


def sweep(project: Project, *, skip_disclosing: bool = False) -> list[tuple[str, str]]:
    """`(object label, printed text)` for everything this project handed back."""
    pairs = []
    for obj in [project.session, project.init, *project.observed]:
        if obj is None or (skip_disclosing and isinstance(obj, DISCLOSING)):
            continue
        label = type(obj).__name__
        for text in printed(obj):
            pairs.append((label, text))
    if not skip_disclosing:
        pairs.append(("banner", swp.banner()))
        pairs.append(("capabilities", json.dumps(swp.capabilities().to_dict())))
    assert len(pairs) >= 20, pairs
    return pairs


def test_the_needles_are_real_and_the_sweep_is_large(run_everything):
    """A guard that measures nothing is not a guard.

    The site identities exist in the private plan, the root secret exists on disk in
    base64 and in hex, and the printed forms of one project's whole run number in the
    tens of thousands of characters.
    """
    project = run_everything
    assert project.location_ids(), "the plan holds no location id, so that half tested nothing"
    assert any(len(s) >= 32 for s in project.secret_strings()), "root.key is not the shape read here"
    pairs = sweep(project)
    assert len(pairs) >= 2 * len(project.observed)
    assert sum(len(text) for _, text in pairs) > 40_000, sum(len(t) for _, t in pairs)


def test_no_printed_form_of_any_returned_object_names_a_key_or_an_id(run_everything):
    """The whole of the boundary, measured against a real protection run."""
    project = run_everything
    for needle in needles(project):
        for label, text in sweep(project):
            assert needle not in text, f"{label} printed {needle[:6]}…"


def test_no_keyed_value_from_the_private_documents_is_mirrored(run_everything):
    """A plan's keyed strings stay in the plan.

    Stronger than banning a list of field names: this takes the *values* the store
    keeps under keyed names — the location ids today, whatever else it records that
    way tomorrow — and requires that none of them appears in a Python-visible form.
    """
    project = run_everything
    values = keyed_values(project)
    # The containment that *is* designed is one-directional: every site identity the
    # private documents record is swept, because `locations` is a keyed field. The
    # reverse does not hold, and should not be demanded — the sweep also reads the plan's
    # `grammar_path` strings and the manifest's `signature`, which are keyed but are not
    # secret, while the root secret itself is keyed only in the sense of living in a
    # sealed file rather than under a JSON field name.
    assert project.location_ids() <= values, "the keyed sweep missed a site identity"
    assert values - needles(project), "the sweep read site ids only, so KEYED_FIELDS tested one key"
    for value in values:
        for label, text in sweep(project):
            assert value not in text, f"{label} mirrors the private value {value[:6]}…"


def test_no_document_key_belongs_to_the_private_half(run_everything):
    """`locations`, `expected`, `fragment_tag`: the private plan's vocabulary, absent.

    Matched against the *keys* of every `to_dict()` the run produced, not its values —
    a plan-mode summary legitimately says `"mode": "plan"`, and the claim here is that
    no document the binding offers is *shaped* like a private one.
    """
    project = run_everything
    keys = set()
    for obj in project.observed:
        document = documents_of(obj)
        if isinstance(document, dict):
            keys |= set(document_keys(document))
    assert keys, "nothing the run returned has a document form"
    assert not PRIVATE_FIELD_NAMES & keys, PRIVATE_FIELD_NAMES & keys


def document_keys(value):
    """Every mapping key in a nested document, however deep."""
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from document_keys(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            yield from document_keys(nested)


def test_a_private_path_is_named_only_by_the_lists_that_disclose_it(run_everything):
    """Nothing but `init.created` and `ProtectSummary.artifacts` points there.

    Those two lists exist to tell an operator what a run wrote, and the CLI prints the
    same paths. A report, a verdict document, a repr or an exception that named the
    plans or manifests folder would be sending a caller to unsigned intermediate state
    the binding was never given.
    """
    project = run_everything
    disclosed = [text for _, text in sweep(project) if any(d in text.replace("\\", "/") for d in PRIVATE_DIRS)]
    assert disclosed, "the artifact lists name no private path, so this case read nothing"
    for label, text in sweep(project, skip_disclosing=True):
        normalised = text.replace("\\", "/")
        for folder in PRIVATE_DIRS:
            assert folder not in normalised, (label, folder)


def test_the_module_exports_no_accessor_for_the_private_half():
    """No class or session method is named for a store, a secret or a plan.

    `PublicKeys` is exported and stays out of this list on purpose: it is the Ed25519
    *verify* key and the scheme that made it, which is the public half of the identity
    a report already quotes. What is missing here is the accessor for the private one.
    """
    exported = {n for n in dir(swp) if not n.startswith("_")}
    assert exported & FORBIDDEN_NAMES == set(), exported & FORBIDDEN_NAMES
    for name in sorted(exported):
        member = getattr(swp, name)
        if isinstance(member, type):
            # A mode of a pyo3 enum class is a class attribute whose name *is* its case,
            # so `Mode.Plan` would otherwise be read as a `Plan` accessor. The cases of a
            # public mode are not the private half they are named after.
            members = set()
            for attribute in dir(member):
                if attribute.startswith("_"):
                    continue
                try:
                    value = getattr(member, attribute)
                except Exception:  # noqa: BLE001 - an unreadable attribute is a name, not a case
                    members.add(attribute)
                    continue
                if not isinstance(value, member):
                    members.add(attribute)
            assert members & FORBIDDEN_NAMES == set(), (name, members & FORBIDDEN_NAMES)
    assert not hasattr(swp.Session, "open_store")
    assert not hasattr(swp.Session, "store")


def test_a_private_document_cannot_be_read_as_a_report(run_everything):
    """`read_report` is confined to the reports folder, whatever name it is given.

    A store-relative path is normalised to a stem and looked for under
    `.swp/private/reports/`, so a release's manifest is not reachable by naming its
    path — the answer is the same refusal as for a report that was never saved.
    """
    project = run_everything
    manifests = sorted((project.root / ".swp" / "private" / "manifests").glob("*.json"))
    assert manifests, "the release wrote no manifest, so this case tested nothing"
    name = Path(manifests[0]).name
    for spelling in (name, f"../manifests/{name}", f".swp/private/manifests/{name}"):
        with pytest.raises(swp.Error) as caught:
            project.session.read_report(spelling)
        assert caught.value.code == "USAGE", spelling
        assert "no saved report" in caught.value.message


def test_a_summary_and_a_release_record_share_the_private_documents_vocabulary_with_nothing(
    protected,
):
    """A plan's rows and a release's watermark use the public field names only.

    Both sets are read from the objects rather than from a list this file maintains, so
    a new field that copies a private document's key is caught on the day it is added.
    """
    summary = protected.protect(swp.Mode.Plan)
    # The release record comes from the release the fixture published, not from the
    # plan summary's id: a plan protects nothing and publishes nothing, so its id names
    # a manifest that will never exist.
    release = protected.session.release(protected.session.releases(swp.ReleaseSelection.latest())[0])
    for document in (summary.to_dict(), release.to_dict()):
        assert not PRIVATE_FIELD_NAMES & set(document_keys(document)), document.keys()
    assert "artifacts" in summary.to_dict()
    assert "watermark" in release.to_dict()


def test_an_exception_about_a_project_never_prints_the_key(run_everything):
    """Failures are a surface too: their text, their path, their cause and their advice."""
    project = run_everything
    refusals = []
    for call in (
        lambda: project.session.release("rel-" + "q" * 13),
        lambda: project.session.read_report("nope"),
        lambda: project.session.scan(project.root / "absent-candidate"),
        lambda: swp.Session.open(str(project.child("nowhere"))),
        lambda: swp.Session.init(str(project.root), options=swp.InitOptions(name="other")),
        lambda: swp.Session.open(str(project.root), swp.Overrides(tag_bits=99)),
    ):
        with pytest.raises(swp.Error) as caught:
            call()
        refusals.append(caught.value)
    assert refusals
    for needle in needles(project):
        for error in refusals:
            rendered = error.rendered + repr(error) + str(error) + json.dumps(
                [error.code, error.message, error.path, error.caused_by, error.next_step]
            )
            assert needle not in rendered, error.code
