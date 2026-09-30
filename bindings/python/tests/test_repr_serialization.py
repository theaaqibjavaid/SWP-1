"""Printing, stringifying and serializing everything a real run hands back.

The per-class tests elsewhere pin individual reprs and documents. This file is the
cross-cutting sweep: it walks the whole object graph one project's run produced —
init, protect in each mode, verify, scan, the store's listings — and holds every object
in it to the rules the binding's own implementation makes, rather than to a list this
file maintains:

* an object whose `__repr__` comes from `repr_of` prints **exactly** its `to_dict()`
  field list, in the document's order. `src/error.rs` uses one implementation for that
  reason: a hand-written repr is a second list of the same fields, and the second list
  is the one that forgets a field the day a DTO gains one. That forgetting is only
  caught by a test like this one;
* the few classes that write their repr by hand are named here, and each prints the
  documented set of values — never a field the object does not have, never the whole
  document, which is `to_dict()`'s job;
* `str()` of anything returned is its `repr()`, with one exception that has a word to
  say: a `Mode` stringifies to the tool's own name for itself;
* nothing a caller received can be edited, and a returned list is a fresh projection, so
  sorting what you were handed cannot change what the run reported;
* the verify document's two renderings are the same document — `to_json()` the schema's,
  `to_dict()` the Python view — and the only key the view adds is `confirmed`, which is
  a getter and not a field.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import swp
from conftest import SOURCE_TREE, Project, _purge, _tempdir, _write_tree

#: Classes whose `__repr__` is written by hand, on purpose: their whole account is a
#: document, and the line in a traceback is the few values a caller branches on.
#: Anything with a `to_dict()` that is not listed here prints that field list.
SUMMARY_REPRS = frozenset(
    {"ProtectSummary", "VerifyOutcome", "ScanOutcome", "Report", "ScannedSite"}
)

#: The values each of those lines is allowed to name. A field added to the repr without
#: a reason, or one quietly dropped when the DTO grows, fails here.
SUMMARY_FIELDS = {
    "ProtectSummary": {"mode", "release_id", "sites_embedded", "sites_skipped"},
    "VerifyOutcome": {"release_id", "verdict", "sites_confirmed"},
    "ScanOutcome": {"result", "evidence_level", "sites"},
    "Report": {"schema", "result", "evidence_level"},
    "ScannedSite": {"release_id", "site", "status"},
}

#: How deep the walk goes before it stops calling itself. The graph is a tree — a
#: summary points at its rows, a report at its tallies — and nothing points back up at a
#: `Session`, so this is a guard against a future cycle, not a bound anyone works in.
MAX_DEPTH = 6

#: The classes the module exports under their own names. `Error` is among them; a
#: built-in method of a `swp` class is not, even though pyo3 labels it `swp`.
BINDING_CLASSES = frozenset(
    cls
    for name, cls in vars(swp).items()
    if isinstance(cls, type) and name == cls.__name__ and not name.startswith("_")
)


def is_binding_object(value) -> bool:
    """Whether this is an instance of one of the module's own classes."""
    return type(value) in BINDING_CLASSES


def spelled(obj) -> str:
    """`repr_of` as Python: `Name(k=v, …)` over `to_dict()`'s keys, in order."""
    fields = ", ".join(f"{key}={value!r}" for key, value in obj.to_dict().items())
    return f"{type(obj).__name__}({fields})"


def document_of(obj):
    """The `to_dict()` of anything that has one, else `None`."""
    to_dict = getattr(obj, "to_dict", None)
    return to_dict() if callable(to_dict) else None


def reachable(obj, depth=0):
    """`obj` and every binding object its public getters hand out."""
    yield obj
    if depth >= MAX_DEPTH:
        return
    for name in dir(obj):
        if name.startswith("_"):
            continue
        try:
            value = getattr(obj, name)
        except Exception as error:  # noqa: BLE001
            raise AssertionError(
                f"{type(obj).__name__}.{name} raised while being read: {error}"
            ) from error
        for item in value if isinstance(value, (list, tuple)) else [value]:
            if is_binding_object(item):
                yield from reachable(item, depth + 1)


@pytest.fixture(scope="module")
def full_run():
    """One project taken through every operation, and everything those returned.

    Module-scoped and purged in its own `finally`, like `conftest.big_project`: a
    project directory holds a sealed root secret, so it must not outlive this file.
    """
    root = _tempdir("repr-serialization")
    try:
        _write_tree(root, SOURCE_TREE)
        outcome = swp.Session.init(str(root), options=swp.InitOptions(name="printing"))
        made = Project(root=root, session=outcome.session, init=outcome.result)
        made.protect(swp.Mode.Release)
        made.protect(swp.Mode.Plan)
        made.verify(save=True)
        scanned = made.scan(root, save=True)
        latest = made.session.releases(swp.ReleaseSelection.latest())[0]
        made.observed.extend(
            [
                outcome,
                made.session.identity,
                made.session.config,
                made.session.stored_config(),
                made.session.limits,
                made.session.release(latest),
                made.session.read_report(Path(scanned.saved.path).name),
                swp.capabilities(),
                swp.Overrides(tag_bits=4),
                swp.ReleaseSelection.all(),
            ]
        )
        made.observed.extend(made.session.release_history())
        yield made
    finally:
        _purge(root)


@pytest.fixture(scope="module")
def objects(full_run):
    """Every binding class the run reached, folded to one instance each."""
    seen: dict[str, list] = {}
    for start in [full_run.session, full_run.init, *full_run.observed]:
        for obj in reachable(start):
            seen.setdefault(type(obj).__name__, []).append(obj)
    assert len(seen) >= 25, sorted(seen)
    return seen


def one_per_class(objects):
    return [instances[0] for _, instances in sorted(objects.items())]


def test_every_class_the_run_reached_is_exported_and_prints_on_one_line(objects):
    """A `repr()` that raises, wraps, or names a class the module hides is a defect.

    The class name is the only pointer a traceback gives anybody: `swp._internal.SiteRow`
    would be a name with no page to send a reader to.
    """
    exported = {name for name in dir(swp) if not name.startswith("_")}
    for obj in one_per_class(objects):
        name = type(obj).__name__
        text = repr(obj)
        assert "\n" not in text, name
        assert name in exported, f"{text[:60]} names an unexported class"
        if name == "Mode":
            # The one object whose repr is an enum case rather than a field list.
            assert re.fullmatch(r"<Mode\.[A-Za-z]+>", text), text
        else:
            assert text.startswith(f"{name}("), text[:80]


def test_a_dto_repr_is_exactly_its_document_field_list(objects):
    """The anti-drift rule, for every class that follows it: one field list, two renderings."""
    offenders = []
    checked = set()
    for obj in one_per_class(objects):
        name = type(obj).__name__
        if document_of(obj) is None or name in SUMMARY_REPRS:
            continue
        checked.add(name)
        if repr(obj) != spelled(obj):
            offenders.append((name, repr(obj)[:150], spelled(obj)[:150]))
    assert len(checked) >= 20, sorted(checked)
    assert not offenders, offenders


def test_only_the_documented_classes_write_their_repr_by_hand(objects):
    """A new DTO that hand-rolls a repr has to be argued for here, not merely written."""
    differs = {
        type(obj).__name__
        for obj in one_per_class(objects)
        if document_of(obj) is not None and repr(obj) != spelled(obj)
    }
    assert differs <= set(SUMMARY_REPRS), differs - set(SUMMARY_REPRS)
    assert differs == set(SUMMARY_REPRS) & differs


def test_a_summary_line_names_the_documented_values_and_no_more(objects):
    """The exception classes may say less than their document, but never something else."""
    seen = set()
    for obj in one_per_class(objects):
        name = type(obj).__name__
        if name not in SUMMARY_REPRS:
            continue
        seen.add(name)
        printed = set(re.findall(r"([a-z][a-z0-9_]*)=", repr(obj)))
        assert printed == SUMMARY_FIELDS[name], (name, repr(obj)[:120])
        document = document_of(obj)
        if document is not None:
            assert printed <= set(document), name
            assert len(repr(obj)) < len(spelled(obj)), name


def test_every_returned_object_stringifies_to_its_repr(objects):
    """One account per object: `str()` adds a second thing to disagree with, so it does not."""
    for obj in one_per_class(objects):
        if isinstance(obj, swp.Mode):
            assert str(obj) == obj.name, obj
            continue
        assert str(obj) == repr(obj), type(obj).__name__


def test_the_mode_is_the_one_value_that_stringifies_to_a_word():
    for case_name in ("Plan", "Release", "DryRun"):
        case = getattr(swp.Mode, case_name)
        assert repr(case) == f"<Mode.{case_name}>"
        assert str(case) == case.name
        assert case.name != case_name, "the tool's word and the Python case are different names"


def test_a_mode_is_hashable_and_hashes_as_the_number_it_compares_equal_to():
    """Python clears `__hash__` on any class that defines `__eq__`, and `Mode` does.

    A mode is a value a caller puts in a set, and `eq_int` means `Mode.Release` also
    compares equal to the number it is written as in C — so the hash has to be that
    number's hash, or `{Mode.Release: 1}[1]` and `{1: 1}[Mode.Release]` would disagree
    while the keys compared equal.
    """
    assert {swp.Mode.Plan, swp.Mode.Release, swp.Mode.Release} == {swp.Mode.Plan, swp.Mode.Release}
    for index, case in enumerate((swp.Mode.Plan, swp.Mode.Release, swp.Mode.DryRun)):
        assert case == index, case.name
        assert hash(case) == hash(index), case.name
    assert swp.Mode.Release != swp.Mode.Plan
    assert swp.Mode.Release != 2


def test_nothing_a_caller_received_can_be_edited(objects):
    """Frozen all the way down: a printed account cannot be talked into agreeing."""
    refused = 0
    for obj in one_per_class(objects):
        for attribute in (n for n in dir(obj) if not n.startswith("_")):
            with pytest.raises(AttributeError) as caught:
                setattr(obj, attribute, None)
            assert "is not writable" in str(caught.value) or "attribute" in str(caught.value)
            refused += 1
            break
    assert refused >= 25, refused


def test_a_returned_collection_is_a_fresh_projection(protected):
    """Sorting or clearing a list you were handed cannot change what the run reported.

    The rows are copied out of the Rust result each time you ask, so `summary.sites`
    twice is two lists and neither is a window into the summary. Without that, one
    `.sort()` in application code would silently reorder what a later line prints.
    """
    summary = protected.protect(swp.Mode.Release)
    before = summary.to_dict()
    count = summary.sites_embedded
    assert count >= 1
    first, second = summary.sites, summary.sites
    assert first is not second
    first.clear()
    second.sort(key=lambda site: site.line_hint, reverse=True)
    assert len(summary.sites) == count
    assert summary.to_dict() == before
    files = summary.files_changed
    files.reverse()
    assert [row.file for row in summary.files_changed] == [row["file"] for row in before["files_changed"]]


def test_the_verify_json_is_the_document_and_the_dict_adds_the_derived_line(protected):
    """One document, two renderings, and exactly one key that is a getter.

    `confirmed` is `SiteRow::confirmed` in `swp-evidence` — the protocol's single place
    where the watermark/not-watermark line is drawn — so it belongs in the Python view
    and not in the schema's file. Requiring the key lists to agree everywhere else is
    what stops `to_dict()` from quietly becoming a second document.
    """
    protected.protect(swp.Mode.Release)
    outcome = protected.verify()
    document = json.loads(outcome.to_json())
    view = outcome.to_dict()
    assert list(document) == list(view), set(document) ^ set(view)
    for key in document:
        if key != "sites":
            assert document[key] == view[key], key
    assert len(document["sites"]) == len(view["sites"]) == outcome.sites_expected
    for row, printed, live in zip(document["sites"], view["sites"], outcome.sites, strict=True):
        assert set(printed) - set(row) == {"confirmed"}, set(printed) ^ set(row)
        assert printed["confirmed"] == live.confirmed
        assert printed["status"] == live.status == row["status"]
        assert "class_" not in json.dumps(row), row
