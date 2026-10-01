"""Failure: one exception type, six fields, and the codes the SDK already defines.

The contract this module checks is the one [docs/SDK_API.md] §8 states: every
failure a Python caller can meet is a `swp.Error`, and it carries `code`,
`message`, `path`, `caused_by`, `next_step` and `rendered`. There is no subclass
per code, so a caller branches on `code` — and every case here produces a real
refusal from a real store rather than a hand-built exception, because an envelope
nobody raised is an envelope nobody tested.

Two boundaries are checked against each other:

* a *semantic* refusal — an id with the wrong shape, a target outside the project,
  a report that was never saved — comes back as `swp.Error` with a code;
* a *type or arity* mistake — an `int` where a path belongs is also refused by the
  binding, but an integer that cannot be a `u8`, or a missing argument, is
  Python's own `OverflowError` / `TypeError`. The binding does not translate the
  interpreter's complaint about a call that never reached Rust.
"""

from __future__ import annotations

import json

import pytest

import swp

#: The six fields §8 declares, and nothing else a caller may read.
ENVELOPE = {"code", "message", "path", "caused_by", "next_step", "rendered"}


@pytest.fixture
def refusals(protected, tmp_path):
    """Every failure this binding can raise on a real project, already raised.

    Each entry is `(code, exception)`. The setups are the ones the messages name:
    a missing directory, an id with the wrong shape, a report never saved.
    """
    made = protected
    cases: list[tuple[str, swp.Error]] = []

    def capture(expected: str, call):
        with pytest.raises(swp.Error) as caught:
            call()
        assert caught.value.code == expected, (expected, caught.value.code, caught.value.message)
        cases.append((expected, caught.value))

    capture("PATH_REJECTED", lambda: swp.Session.open(str(tmp_path / "never-made")))
    capture("NOT_PROTECTED", lambda: swp.Session.open(str(made.child("src", "app.js"))))
    capture("USAGE", lambda: swp.Session.open(str(made.root), swp.Overrides(tag_bits=99)))
    # An id that is not an id is judged by the same reader as a corrupt record.
    capture("INVALID_MANIFEST", lambda: swp.ProtectOptions(swp.Mode.Release, release_id="bad"))
    capture("INVALID_MANIFEST", lambda: swp.ReleaseSelection.ids(["nope"]))
    capture("USAGE", lambda: made.session.read_report("no-such-report"))
    capture("USAGE", lambda: swp.Session.open(123))
    capture("USAGE", lambda: swp.Session.open(b"some/bytes"))
    capture(
        "PROTOCOL_VERSION_UNSUPPORTED",
        lambda: swp.Report.from_json('{"schema":"SWP-1-report-v1","protocol":"SWP-1"}'),
    )
    capture("INVALID_MANIFEST", lambda: swp.Report.from_json("not json at all"))
    capture("IO_ERROR", lambda: made.scan(tmp_path / "also-never-made"))
    return cases


def test_every_failure_is_the_same_type_with_the_same_six_fields(refusals):
    for code, error in refusals:
        assert type(error) is swp.Error, "one exception type per §8, not a subclass per code"
        assert isinstance(error, Exception)
        assert error.code == code
        assert error.message
        assert error.next_step, f"{code} arrives without advice"
        assert error.path is None or isinstance(error.path, str)
        assert error.caused_by is None or isinstance(error.caused_by, str)
        assert ENVELOPE <= {name for name in dir(error) if not name.startswith("_")}


def test_str_is_the_message_and_args_hold_only_it(refusals):
    for _, error in refusals:
        assert str(error) == error.message
        assert error.args == (error.message,)


def test_rendered_is_the_sentence_the_command_prints(refusals):
    """`{code} — {message}`, then the cause if there is one, then the next step."""
    for code, error in refusals:
        lines = error.rendered.splitlines()
        assert lines[0] == f"{code} — {error.message}"
        assert lines[-1] == f"  next step: {error.next_step}"
        causes = [line for line in lines if line.startswith("  caused by: ")]
        assert bool(causes) == (error.caused_by is not None)
        for line in causes:
            assert line == f"  caused by: {error.caused_by}"
        assert error.rendered.startswith(f"{error.code} ")


def test_a_path_naming_failure_says_which_path(protected):
    """The one field that is not text: the store entry the caller asked for.

    Forward-slashed and store-relative, so it can be printed in a log without
    revealing where the project lives.
    """
    with pytest.raises(swp.Error) as caught:
        protected.session.read_report("nope")
    assert caught.value.code == "USAGE"
    assert caught.value.path == ".swp/private/reports/nope.json"
    assert "\\" not in caught.value.path
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(str(protected.root / "nope-nope"))
    assert caught.value.path is None


def test_codes_come_from_the_table_the_module_publishes(refusals):
    declared = set(swp.error_codes())
    assert declared >= {"USAGE", "NOT_PROTECTED", "IO_ERROR", "INTERNAL_ERROR"}
    for code, _ in refusals:
        assert code in declared, code
    assert "INTERNAL_ERROR" not in {code for code, _ in refusals}, (
        "a defect in SWP-1 is not a failure mode this suite can produce on purpose"
    )
    # Each code's advice is its own: the table is not one string repeated.
    advice = {code: error.next_step for code, error in refusals}
    assert advice["USAGE"] != advice["NOT_PROTECTED"]


def test_a_range_mistake_is_the_interpreters_own_error():
    """`u8` and `u32` bounds are Python's argument checking; the SDK's are `swp.Error`.

    `tag_bits=400` cannot be an unsigned 8-bit integer at all, so no Rust code runs
    and the caller gets `OverflowError`. `tag_bits=99` fits the type and is refused
    by the settings validator with a code — see `refusals` above.
    """
    with pytest.raises(OverflowError):
        swp.Overrides(tag_bits=400)
    with pytest.raises(OverflowError):
        swp.Overrides(target_sites=-1)
    with pytest.raises(TypeError):
        swp.ProtectOptions()
    with pytest.raises(TypeError):
        swp.InitOptions(not_a_field=True)
    with pytest.raises(TypeError):
        swp.Session.open()


def test_an_exception_can_be_read_and_reraised(protected):
    """A caller's `except` clause gets an object it can log, compare and re-raise."""
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(str(protected.child("src")))
    error = caught.value
    # `open` needs the store at the exact directory; `discover` walks up to it.
    assert swp.Session.discover(str(protected.child("src"))).identity.to_dict() == (
        protected.session.identity.to_dict()
    ), "the parent store was found from the same directory the refusal named"
    try:
        raise error
    except swp.Error as again:
        assert again.code == error.code
        assert again.rendered == error.rendered
    assert json.dumps(
        {
            "code": error.code,
            "message": error.message,
            "path": error.path,
            "caused_by": error.caused_by,
            "next_step": error.next_step,
        }
    )


def test_no_failure_text_carries_keyed_material(protected, refusals):
    """The message is what a user reads; it must not be where a secret surfaces.

    Swept against this project's own sealed key material and every keyed site
    identity in its private store.
    """
    needles = protected.secret_strings() | protected.location_ids()
    assert needles, "a sweep against an empty needle set proves nothing"
    for _, error in refusals:
        text = "".join(
            part
            for part in (
                error.code,
                error.message,
                error.path or "",
                error.caused_by or "",
                error.next_step,
                error.rendered,
                str(error),
            )
        )
        for needle in needles:
            assert needle not in text, (error.code, needle[:8])
        assert "root.key" not in text
        assert "PRIVATE KEY" not in text.upper()


def test_a_refusal_raised_while_building_an_argument_has_the_same_shape(make_project):
    """`Overrides` is judged when the session reads it, so the code arrives from the
    session constructor — the envelope is the same six fields either way.
    """
    made = make_project("errors-usage")
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(str(made.root), swp.Overrides(targets=["../outside"]))
    assert caught.value.code == "USAGE"
    assert "outside" in caught.value.message
    assert caught.value.rendered.startswith("USAGE — ")
    # The project is unharmed by a refusal that happened before it was used.
    assert made.session.release_history() == []
