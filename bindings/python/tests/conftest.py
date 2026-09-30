"""Fixtures the binding suite shares.

Two rules shape this file, and both come from what a project directory holds.

* **A test project is a real project.** Every case here runs `init` and
  `protect_summary` for its own temporary root: the values a test asserts on are
  the ones the Rust crates produced for that tree, with that tree's own drawn
  secret. Nothing is mocked, and no expected site count, release id or fingerprint
  is written into a test — several of them depend on the key, and a hard-coded one
  would be a number this suite invented.
* **A test project is left nowhere.** The root secret lives in the project
  directory, so a directory that outlives its test leaves a sealed key in a shared
  temp folder. `_purge` is the teardown, and it fails the run out loud rather than
  ignoring a leftover, which is what `swp_test_suite::TempDir::sensitive()` does on
  the Rust side for the same reason.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import swp

#: One tree per language adapter this build claims, plus a shared-shape spread so
#: the walker has several candidate sites to choose among. The contents are
#: deliberately ordinary: a test that depended on an exotic construct would be
#: testing the adapter's fixtures rather than the binding.
SOURCE_TREE: dict[str, str] = {
    "src/app.js": """
const greeting = 'hello world';

function add(left, right) {
  return left + right;
}

export function label(value) {
  return '[' + value + ']';
}

const table = { alpha: 1, beta: 2, gamma: 3 };

export function total(items) {
  let sum = 0;
  for (const item of items) {
    sum = sum + item;
  }
  return sum;
}
""",
    "src/util.py": """
def scale(value, factor):
    return value * factor


LIMIT = 4096


def render(name):
    parts = []
    for index in range(3):
        parts.append(name + str(index))
    return '-'.join(parts)
""",
    "src/main.ts": """
export function pick(items: string[], index: number): string {
  const offset = 7;
  return items[index + offset];
}

export const retries = 5;
""",
}


def _tempdir(label: str) -> Path:
    """A fresh directory whose name says which test made it."""
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in label)
    return Path(
        tempfile.mkdtemp(prefix=f"swp-py-{safe}-")
    )


def _write_tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _purge(root: Path) -> None:
    """Remove a project directory, and fail loudly if a secret survived it.

    Windows seals `root.key` with an ACL, and DPAPI-protected files can carry a
    deny-read entry that makes `shutil.rmtree` fail on a first pass, so the walk
    gives the owner write permission before deleting. The final check is the point:
    a leftover directory holding `root.key` is the one thing this suite must not
    leave behind, so it raises instead of being logged.
    """
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames + dirnames:
            try:
                os.chmod(os.path.join(dirpath, name), stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
    shutil.rmtree(root, ignore_errors=True)
    if root.exists():
        secret = root / ".swp" / "private" / "root.key"
        if secret.exists():
            raise RuntimeError(
                f"a directory holding a test root secret could not be removed: {root}"
            )
        shutil.rmtree(root, ignore_errors=True)


@dataclass
class Project:
    """One temporary project: its directory, its session, and what it wrote."""

    root: Path
    session: swp.Session
    init: object = None
    #: Every object this test handed to the leak sweep, recorded so the sweep
    #: covers what a test actually received rather than a hand-picked few.
    observed: list[object] = field(default_factory=list)

    def child(self, *rel: str) -> Path:
        return self.root.joinpath(*rel)

    def protect(self, mode: swp.Mode = swp.Mode.Release, **kwargs) -> swp.ProtectSummary:
        summary = self.session.protect_summary(swp.ProtectOptions(mode, **kwargs))
        self.observed.append(summary)
        self.observed.extend(summary.sites)
        self.observed.extend(summary.files_changed)
        self.observed.extend(summary.refusals)
        return summary

    def verify(self, **kwargs) -> swp.VerifyOutcome:
        outcome = self.session.verify(options=swp.VerifyOptions(**kwargs) if kwargs else None)
        self.observed.append(outcome)
        self.observed.extend(outcome.sites)
        return outcome

    def scan(self, candidate, **kwargs) -> swp.ScanOutcome:
        outcome = self.session.scan(str(candidate), **kwargs)
        self.observed.append(outcome)
        self.observed.append(outcome.report)
        self.observed.extend(outcome.sites)
        if outcome.saved is not None:
            self.observed.append(outcome.saved)
        return outcome

    # -- the private half, read by the tests that sweep it -------------------

    def private_documents(self) -> list[tuple[Path, dict]]:
        out = []
        for kind in ("plans", "manifests"):
            folder = self.root / ".swp" / "private" / kind
            for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
                out.append((path, json.loads(path.read_text(encoding="utf-8"))))
        return out

    def location_ids(self) -> set[str]:
        """Every keyed site identity this project's own store holds.

        Read off the disk, never printed: these are the strings whose appearance in
        a Python-visible value is the failure `secret_leak` is built to catch.
        """
        ids: set[str] = set()
        for _, document in self.private_documents():
            for key in ("sites", "skipped"):
                for site in document.get(key) or []:
                    if isinstance(site, dict):
                        ids.update(site.get("locations") or [])
        return ids

    def secret_strings(self) -> set[str]:
        """Renderings of the sealed root secret that must never cross the boundary.

        The envelope's payload is DPAPI ciphertext rather than the key itself, so a
        test that only checked the key bytes would pass on a binding that dumped this
        file into a `repr()`. Both spellings of the same bytes are needles.
        """
        path = self.root / ".swp" / "private" / "root.key"
        if not path.is_file():
            return set()
        text = path.read_text(encoding="utf-8")
        needles = set()
        for line in text.splitlines():
            name, _, value = line.partition(":")
            value = value.strip()
            if not value or name.strip() == "scheme":
                continue
            needles.add(value)
            try:
                needles.add(base64.b64decode(value).hex())
            except Exception:
                pass
        return needles


@pytest.fixture
def make_project():
    """Build temporary projects, and remove every one of them afterwards."""
    created: list[Path] = []

    def factory(
        label: str = "project",
        *,
        files: dict[str, str] | None = None,
        init: bool = True,
        name: str | None = None,
        overrides: swp.Overrides | None = None,
    ) -> Project:
        root = _tempdir(label)
        created.append(root)
        _write_tree(root, SOURCE_TREE if files is None else files)
        if not init:
            return Project(root=root, session=None)  # type: ignore[arg-type]
        outcome = swp.Session.init(str(root), options=swp.InitOptions(name=name or label))
        session = outcome.session
        if overrides is not None:
            session = swp.Session.open(str(root), overrides)
        return Project(root=root, session=session, init=outcome.result)

    yield factory
    for root in created:
        _purge(root)


@pytest.fixture
def project(make_project) -> Project:
    """The one project almost every case needs: a fresh tree, already initialised."""
    return make_project("basic")


@pytest.fixture
def protected(make_project) -> Project:
    """A project with a published release, so verify and scan have something to find."""
    made = make_project("protected")
    made.protect(swp.Mode.Release)
    return made


@pytest.fixture(scope="module")
def big_project():
    """A tree large enough that a walk of it takes measurable time.

    Module-scoped and cleaned by the module itself: its only job is to give the GIL
    tests a call long enough that "the other thread ran during it" is observable
    rather than a race.
    """
    root = _tempdir("big")
    try:
        files = {}
        for index in range(160):
            files[f"src/mod{index:03d}.js"] = (
                f"const base{index} = {index * 31 + 7};\n"
                + "".join(
                    f"export function f{index}_{step}(x) {{\n"
                    f"  let acc = x + {step * 101 + index};\n"
                    f"  for (let i = 0; i < {step + 3}; i++) {{ acc = acc + i; }}\n"
                    f"  return acc;\n"
                    f"}}\n"
                    for step in range(4)
                )
            )
        _write_tree(root, files)
        outcome = swp.Session.init(str(root), options=swp.InitOptions(name="big"))
        yield Project(root=root, session=outcome.session, init=outcome.result)
    finally:
        _purge(root)


@pytest.fixture
def foreign_tree():
    """A tree that is nobody's protected project, for a scan that must find nothing."""
    root = _tempdir("foreign")
    try:
        _write_tree(
            root,
            {
                "src/other.py": """
def unrelated(values):
    total = 0
    for value in values:
        total = total + value
    return total
""",
                "src/other.js": """
export function unrelated(n) {
  return n * 3;
}
""",
            },
        )
        yield root
    finally:
        _purge(root)


# -- assertions several modules share ---------------------------------------

#: Field names that belong to the private plan and the private manifest. They are
#: not secret by themselves; they are the shape of the documents a binding is not
#: given, so their appearance in a Python document form means the binding rebuilt
#: one rather than read the summary it was handed.
PRIVATE_FIELD_NAMES = frozenset(
    {
        "locations",
        "location_id",
        "location_ids",
        "grammar_path",
        "original",
        "rendered",
        "root_secret",
        "secret_bytes",
        "plan",
        "fragment_tag",
        "expected_tag",
        "expected",
    }
)


def walk_strings(value):
    """Every string in a nested dict/list, and every key too."""
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str):
                yield key
            yield from walk_strings(nested)
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            yield from walk_strings(nested)
    elif isinstance(value, str):
        yield value


def documents_of(obj) -> dict:
    """The `to_dict()` form of any binding object, or of a run outcome."""
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    if isinstance(obj, Project):
        out = {}
        if obj.init is not None:
            out["init"] = obj.init.to_dict()
        return out
    return {}
