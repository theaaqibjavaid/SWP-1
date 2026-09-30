"""What the module promises before any project is opened.

A binding that imports is not a binding that works: this module checks the parts a
caller reads first — the two versions, the capability list, the failure-code table,
the names in the namespace — because those are the surface an application codes
against without ever running a protection.
"""

from __future__ import annotations

import json
import keyword
import re
from pathlib import Path

import pytest

import swp


def _pyproject_version() -> str:
    """The version `pyproject.toml` advertises, read from the source tree.

    The wheel under test is built from that file, so the two agreeing is a fact
    about the build rather than a number this suite repeats.
    """
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    in_project = False
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        if line.strip() == "[project]":
            in_project = True
            continue
        if in_project and line.startswith("["):
            break
        if in_project:
            match = re.fullmatch(r'version\s*=\s*"([^"]+)"', line.strip())
            if match:
                return match.group(1)
    raise AssertionError(f"{pyproject} declares no [project] version")


def test_import_exposes_a_named_module():
    assert swp.__name__ == "swp"
    assert swp.__file__


def test_the_two_versions_are_the_two_lifecycles():
    """`__version__` is the binding's, `swp_version` the tool's — §1 of VERSIONING_POLICY.

    The binding's own number is the one in the packaging metadata of the wheel that
    is installed, so a mismatch would mean a rebuilt crate and a stale distribution.
    Only the tool version is constrained by the rest of the build: it must be what
    `banner()` and `capabilities()` report, since a report's `generator` field is
    how a finding says which rules produced it.
    """
    assert swp.__version__ == _pyproject_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+[0-9A-Za-z.\-]*", swp.__version__), swp.__version__
    assert swp.swp_version == swp.capabilities().swp_version
    assert swp.swp_version in swp.banner()


def test_banner_names_the_protocol_and_the_report_schema():
    banner = swp.banner()
    capabilities = swp.capabilities()
    assert "SWP-1" in banner
    assert capabilities.protocol in banner
    assert capabilities.report_schema in banner
    assert swp.swp_version in banner


def test_error_codes_is_the_table_the_exception_draws_from():
    codes = swp.error_codes()
    assert isinstance(codes, list)
    assert len(codes) == len(set(codes)), "a code listed twice makes a branch ambiguous"
    assert "INTERNAL_ERROR" in codes
    assert "USAGE" in codes
    for code in codes:
        assert re.fullmatch(r"[A-Z][A-Z0-9_]*", code), code


def test_suggest_sites_is_a_step_function_on_file_count():
    """The ladder is the SDK's; the binding only re-speaks it.

    Two checks that hold for any monotone ladder: more files never asks for fewer
    sites, and a small project still gets a usable suggestion rather than zero.
    """
    ladder = [swp.suggest_sites(n) for n in (0, 1, 5, 20, 50, 100, 500, 1000, 5000)]
    assert ladder == sorted(ladder)
    assert all(n > 0 for n in ladder)


@pytest.mark.parametrize(
    "spelling",
    ["stem", "stem.json", "reports/stem.json", ".swp/private/reports/stem.json"],
)
def test_report_stem_normalises_every_spelling_of_one_entry(spelling):
    assert swp.report_stem(spelling) == "stem"


def test_capabilities_describe_the_build_that_is_running():
    capabilities = swp.capabilities()
    assert capabilities.protocol == "SWP-1"
    assert capabilities.report_schema
    assert capabilities.canonicalizer_version >= 1

    names = capabilities.language_names()
    # The order is the adapter registry's, not alphabetical and not key-dependent,
    # so `language_names()` and `languages` must agree element for element — the
    # short list is the long list's projection, not a second list someone maintains.
    assert names == [info.name for info in capabilities.languages]
    assert len(names) == len(set(names)), "a language listed twice is a listing, not a capability"
    for info in capabilities.languages:
        assert info.extensions, f"{info.name} with no extension is never selected"
        # Bare extensions: the walker compares them against a path's `extension()`,
        # so a leading dot or a separator here would silently match nothing.
        for ext in info.extensions:
            assert re.fullmatch(r"[A-Za-z0-9]+", ext), (info.name, ext)
        assert len(set(info.extensions)) == len(info.extensions)

    for rng in (capabilities.tag_bits, capabilities.target_sites):
        assert rng.min <= rng.default <= rng.max
    assert all(isinstance(rule, str) and rule for rule in capabilities.defaults.excludes)

    # A capability list you can print is a capability list you can debug.
    json.dumps(capabilities.to_dict())
    assert repr(capabilities).startswith("Capabilities(")


EVERY_CLASS = [
    name
    for name in dir(swp)
    if name[0].isupper() and isinstance(getattr(swp, name), type)
]


def test_every_exported_class_claims_the_module():
    for name in EVERY_CLASS:
        cls = getattr(swp, name)
        assert cls.__module__ == "swp", f"{name} claims {cls.__module__}"


def test_no_exported_attribute_name_is_a_python_keyword():
    """`class` would be unreachable as an attribute, so the surface renames it.

    The document key stays `"class"`; only the Python name moves. Sweeping the
    exported names keeps the two halves of that decision from drifting apart.
    """
    for name in dir(swp):
        if not name.startswith("_"):
            assert not keyword.iskeyword(name), name


def test_error_is_the_only_exception_type_the_module_exports():
    assert issubclass(swp.Error, Exception)
    assert swp.Error.__module__ == "swp"
    exported = [
        name
        for name in dir(swp)
        if isinstance(getattr(swp, name), type) and issubclass(getattr(swp, name), BaseException)
    ]
    assert exported == ["Error"], f"the module exports {exported}"
