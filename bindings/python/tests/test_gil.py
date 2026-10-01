"""The GIL is given up for the length of a call, and the binding survives threads.

Every operation in `src/error.rs` runs inside `detached`, which calls `py.detach`: the
interpreter lock is released for the walk, the parse and the arithmetic, and taken back
only to hand over owned data or to raise. Two properties follow, and both are testable
from Python rather than from review of the Rust:

* a long `swp` call does not stop the rest of the program. An application that protects
  a tree in a worker thread still serves its UI, its heartbeat and its Ctrl-C while that
  call runs — which is the whole reason `detached` exists and is not a performance
  gesture;
* what crosses a thread boundary is a value, not a window into the interpreter. A
  `Failure` is `Send` data and becomes a `PyErr` on the thread that raises it, so a
  worker's refusal cannot land on another thread's stack, and one session can be read
  from two threads at once.

What this file does *not* claim is that two threads may protect the same project at the
same time. They would write the same store and the same source files, and nothing in the
protocol serialises them. The tested pattern is one project per worker, plus read-only
sharing of a session.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

import swp

#: How often the heartbeat thread tries to run, in seconds. Windows coalesces short
#: sleeps to the scheduler tick (~15 ms), which is why the assertions count wakes
#: rather than compare a wake rate to the measured call length.
HEARTBEAT = 0.005

#: The shortest call whose release of the lock this can tell from a lucky window.
#: GitHub runners finish `protect` over the big tree in ~0.1 s; a slower dev box
#: (this suite was first written on one) in ~0.5 s. The floor is set for the fast
#: end, and a call below it fails loudly instead of being skipped.
MIN_MEASURABLE = 0.03


def beats_during(fn):
    """`(returned value, seconds it took, ticks a rival Python thread got)`."""
    state = {"ticks": 0, "running": True}

    def heartbeat():
        while state["running"]:
            time.sleep(HEARTBEAT)
            state["ticks"] += 1

    rival = threading.Thread(target=heartbeat, daemon=True)
    rival.start()
    try:
        # Let the rival settle into its sleep, so the window measured is the call.
        time.sleep(4 * HEARTBEAT)
        started = time.perf_counter()
        beats_before = state["ticks"]
        value = fn()
        elapsed = time.perf_counter() - started
        ticks = state["ticks"] - beats_before
    finally:
        state["running"] = False
        rival.join(timeout=30)
    return value, elapsed, ticks


def assert_lock_was_released(elapsed, ticks, label):
    """A sleeping rival ran during the call, which it cannot do if the lock is held.

    A held lock keeps the rival at zero: its wake needs the interpreter, so a
    tick counted inside the window is a release. Two are demanded because one
    could be boundary luck — the rival waking as the call returns. The count is
    not compared to a ratio of the window: a shared runner may schedule the
    rival far less often than `HEARTBEAT` promises, and a missed beat is not a
    held lock. `MIN_MEASURABLE` keeps the claim honest: a call that short
    cannot distinguish a released lock from a lucky window, and says so rather
    than passing.
    """
    assert elapsed > MIN_MEASURABLE, (
        f"{label} took {elapsed:.3f}s — too short to measure anything; "
        "give this test a bigger tree rather than lowering the floor"
    )
    assert ticks >= 2, f"{label} appears to hold the GIL: {ticks} ticks in {elapsed:.3f}s"


def run_in_threads(bodies):
    """Run each `body` on its own thread; return `(values, errors)` in the same order."""
    values: list = [None] * len(bodies)
    errors: list = [None] * len(bodies)

    def wrapper(index, body):
        try:
            values[index] = body()
        except BaseException as error:  # noqa: BLE001 - the assertion is that it lands here
            errors[index] = error

    threads = [
        threading.Thread(target=wrapper, args=(index, body)) for index, body in enumerate(bodies)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=300)
    assert not any(thread.is_alive() for thread in threads), "a worker never finished"
    return values, errors


def test_a_long_call_does_not_stop_the_interpreter(big_project):
    """Protect, verify and scan: three calls long enough to measure, each with a rival.

    They run in this order because they are the real sequence — the release publishes
    what `verify` and `scan` then read, and this file is the only one that uses
    `big_project`.
    """
    session = big_project.session
    checks = [
        ("protect", lambda: session.protect_summary(swp.ProtectOptions(swp.Mode.Release))),
        ("verify", lambda: session.verify()),
        ("scan", lambda: session.scan(str(big_project.root))),
    ]
    for label, call in checks:
        value, elapsed, ticks = beats_during(call)
        assert_lock_was_released(elapsed, ticks, label)
        if label == "protect":
            assert value.sites_embedded >= 1
        elif label == "verify":
            assert value.verdict == "INTACT", "a concurrent heartbeat must not change the answer"
        else:
            assert len(value.sites) == value.report.releases[0].sites


def test_projects_on_parallel_threads_answer_like_projects_on_one(make_project):
    """One project per worker: the pattern an embedding application actually uses.

    Four temporary trees are made on the main thread — the factory is what records them
    for teardown — and each is protected, verified and scanned on its own thread. The
    assertions are about isolation, not about the counts: which literals a key selects
    differs between projects, so what has to agree is that each worker's *own* three
    calls describe the same release, on the same root, with no other project's identity
    mixed in.
    """
    made = [make_project(f"parallel-{index}") for index in range(4)]

    def work(project):
        summary = project.protect(swp.Mode.Release)
        outcome = project.verify()
        scan = project.scan(project.root)
        return summary, outcome, scan

    values, errors = run_in_threads([lambda p=p: work(p) for p in made])
    assert [error for error in errors if error is not None] == [], errors
    roots = set()
    for project, (summary, outcome, scan) in zip(made, values, strict=True):
        assert summary.mode == swp.Mode.Release
        assert summary.project_id == project.session.identity.project_id
        assert outcome.release_id == summary.release_id
        assert outcome.verdict == "INTACT"
        assert outcome.sites_confirmed == outcome.sites_expected == len(summary.sites)
        assert scan.report.result in {"PROVENANCE_DETECTED", "PROVENANCE_SUSPECTED"}
        assert str(project.root) in outcome.tree or str(project.root.resolve()) in outcome.tree
        roots.add(str(project.root))
    assert len(roots) == 4, "two workers ran on the same project"


def test_a_refusal_raises_on_the_thread_that_asked_for_it(project):
    """`Failure` is `Send` data; the `PyErr` is built where it is raised.

    Eight threads ask the same session for a release that does not exist. Each has to
    catch its own `swp.Error`, with the same code and its own traceback, and nothing may
    surface as an unhandled exception on a thread it was not asked from.
    """
    absent = "rel-" + "q" * 13

    def ask():
        with pytest.raises(swp.Error) as caught:
            project.session.release(absent)
        return caught.value

    values, errors = run_in_threads([ask] * 8)
    assert [error for error in errors if error is not None] == [], errors
    assert len(values) == 8
    codes = {error.code for error in values}
    assert len(codes) == 1, codes
    assert absent in values[0].message
    # A worker's failure is not the main thread's: the same call here raises the same
    # refusal, and the session still answers a read afterwards.
    with pytest.raises(swp.Error) as here:
        project.session.release(absent)
    assert here.value.code == values[0].code
    assert project.session.identity.project_id


def test_one_session_served_from_several_threads_reads_the_same(protected):
    """Read-only sharing: the session is `Sync`, and every caller gets one document.

    `verify()` without `save` writes nothing, so four of it plus the store's listings
    can run against one project at once. If any of these answers were assembled under
    a lock the binding does not take, the four documents would not be byte-identical.
    """
    solo = protected.verify()
    expected = solo.to_json()
    values, errors = run_in_threads(
        [
            lambda: protected.session.verify(),
            lambda: protected.session.verify(),
            lambda: protected.session.verify(),
            lambda: protected.session.verify(),
            lambda: protected.session.release_history(),
            lambda: protected.session.releases(swp.ReleaseSelection.all()),
            lambda: protected.session.identity.to_dict(),
            lambda: protected.session.limits.to_dict(),
        ]
    )
    assert [error for error in errors if error is not None] == [], errors
    for value in values[:4]:
        assert value.to_json() == expected
    assert {row.release_id for row in values[4]} == set(values[5]) == {solo.release_id}
    assert sorted(row.release_id for row in values[4]) == sorted(values[5])
    assert values[6]["project_id"] == protected.session.identity.project_id
    assert values[7]["max_file_bytes"] > 0


def test_a_module_helper_called_from_a_thread_does_not_need_a_session():
    """`capabilities()` and `banner()` read the build, not a store — and stay callable
    from anywhere, which is how a worker reports what it is running against."""
    values, errors = run_in_threads([swp.capabilities, swp.banner] * 6)
    assert [error for error in errors if error is not None] == [], errors
    documents = {
        json.dumps(value.to_dict(), sort_keys=True)
        for value in values
        if isinstance(value, swp.Capabilities)
    }
    words = {value for value in values if isinstance(value, str)}
    assert len(documents) == 1 == len(words), (documents, words)
    assert words == {swp.banner()}
