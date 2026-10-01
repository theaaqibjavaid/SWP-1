"""Opening, finding and describing a project.

A `Session` is the only handle this binding gives a caller, so these cases check
what it can say about a project without protecting anything: the root it was opened
at, the identity and config it parsed, the limits it runs under, and the release
list it refuses to invent.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime

import pytest

import swp
from conftest import SOURCE_TREE


def _plain(root: str) -> str:
    r"""Drop the Windows verbatim prefix, if this build used one.

    `project_root` hands back the store's own path, which on Windows is verbatim
    (`\\?\C:\…`) because the store canonicalises past MAX_PATH instead of being
    limited by it. Comparing that string to `pathlib`'s spelling directly would test
    two path printers against each other, so both sides are normalised here.
    """
    return root[4:] if root.startswith("\\\\?\\") else root


def _same_directory(left: str, right) -> bool:
    return os.path.normcase(os.path.realpath(_plain(left))) == os.path.normcase(
        os.path.realpath(str(right))
    )


def test_init_writes_the_store_it_describes(project):
    result = project.init
    assert result.project_id.startswith("swp1-")
    assert result.pre_existing is False
    assert result.secret_state == "created"
    assert result.secret_scheme in ("dpapi", "plain")
    assert result.created, "an init that created nothing still claims a list of paths"
    assert ".swp/private/root.key" in result.created
    # Every path the result names is a path that now exists: the disclosure and the
    # filesystem have to agree, on Windows separators as well as on POSIX.
    for rel in result.created:
        assert (project.root / os.path.join(*rel.split("/"))).exists(), rel
    assert result.permissions_verified is True
    assert result.permissions_detail
    assert isinstance(result.gitignore, str) and result.gitignore


def test_init_reports_where_the_secret_went_and_not_what_it_is(project):
    """`secret_handle` is a fingerprint of the key, and the payload never appears.

    This is the whole of what `init` discloses about the root secret: which scheme
    sealed it, that a handle for naming it in a log exists, and nothing else.
    """
    needles = project.secret_strings()
    assert project.init.secret_handle
    assert project.init.secret_handle not in needles
    rendered = json.dumps([project.init.measurement.to_dict(), project.init.settings.to_dict()])
    rendered += repr(project.init) + str(project.init.measurement) + str(project.init.settings)
    for needle in needles:
        assert needle not in rendered


def test_re_running_init_keeps_the_identity_and_says_so(make_project):
    """An existing store is not an error, and not a new secret either.

    The second call reports `pre_existing` and `secret_state == "kept"`: SWP never
    replaces a project secret, so a caller that re-inits gets the same project back
    rather than a silently re-keyed one.
    """
    made = make_project("reinit")
    again = swp.Session.init(str(made.root))
    assert again.result.pre_existing is True
    assert again.result.secret_state == "kept"
    assert again.result.project_id == made.init.project_id
    assert again.session.identity.to_dict() == made.session.identity.to_dict()


def test_a_conflicting_label_is_a_usage_error_unless_forced(make_project):
    """A rename needs `force`, because reports written before it keep the old label."""
    made = make_project("label")
    with pytest.raises(swp.Error) as caught:
        swp.Session.init(str(made.root), options=swp.InitOptions(name="something else"))
    assert caught.value.code == "USAGE"
    assert "force" in caught.value.message
    renamed = swp.Session.init(
        str(made.root), options=swp.InitOptions(name="renamed", force=True)
    )
    assert renamed.result.renamed is True
    assert renamed.session.identity.display_name == "renamed"


def test_measurement_counts_the_tree_it_was_given(project):
    measurement = project.init.measurement
    assert measurement.files == len(SOURCE_TREE)
    assert measurement.bytes > 0
    assert sum(measurement.languages().values()) == measurement.files
    assert sum(measurement.tops().values()) == measurement.files
    assert set(measurement.languages()) == {"javascript", "python", "typescript"}
    assert measurement.tops() == {"src": len(SOURCE_TREE)}


def test_skipped_counts_what_the_walk_declined_and_not_what_it_pruned(make_project):
    """`skipped` is the walk's hole report: a file with no adapter, a file with no bytes.

    Measured as a difference between two trees that differ only in those two files,
    because the store `init` writes beside the sources contributes its own declines
    (its `.gitignore`) and that number belongs to the build, not to this fixture.
    The `.swp/` directory itself never appears: the store is pruned, not declined.
    """
    plain = make_project("measure-plain")
    extended = make_project(
        "measure-extended",
        files={
            **SOURCE_TREE,
            "extra/notes.txt": "prose, not source\n",
            "extra/empty.js": "",
        },
    )
    before = plain.init.measurement
    after = extended.init.measurement
    assert after.files == before.files, "a declined file is not a counted one"
    assert after.skipped == before.skipped + 2, (before.skipped, after.skipped)
    # `bytes` is the sum over admitted files, so a declined file contributes nothing
    # to the measurement a target suggestion is drawn from.
    assert after.bytes == before.bytes


def test_settings_are_the_suggestion_applied(project):
    settings = project.init.settings
    assert settings.suggestion == swp.suggest_sites(project.init.measurement.files)
    assert settings.written is True
    assert settings.targets == ["src"]
    assert settings.target_sites >= 1
    bounds = swp.capabilities().tag_bits
    assert bounds.min <= settings.tag_bits <= bounds.max


def test_open_returns_the_same_project(project):
    again = swp.Session.open(str(project.root))
    assert again.project_root == project.session.project_root
    assert again.identity.to_dict() == project.session.identity.to_dict()
    assert again.config.to_dict() == project.session.config.to_dict()
    assert again.limits.to_dict() == project.session.limits.to_dict()


def test_discover_walks_up_from_a_subdirectory_to_the_same_root(project):
    found = swp.Session.discover(str(project.child("src")))
    assert _same_directory(found.project_root, project.root)
    assert found.identity.project_id == project.session.identity.project_id


def test_project_root_is_the_directory_that_exists(project):
    assert _same_directory(project.session.project_root, project.root)


def test_identity_is_the_public_half_of_the_store(project):
    identity = project.session.identity
    assert identity.protocol == "SWP-1"
    assert identity.project_id == project.init.project_id
    assert identity.display_name == "basic"
    assert identity.schema >= 1
    assert identity.canonicalizer_version == swp.capabilities().canonicalizer_version
    # RFC 3339 in UTC: the same stamp a report prints beside its verdict.
    parsed = datetime.fromisoformat(identity.created_at.replace("Z", "+00:00"))
    assert parsed.utcoffset().total_seconds() == 0
    assert identity.verification.algorithm == "ed25519"
    assert identity.verification.verify_key_b64
    assert identity.generator.swp_version == swp.swp_version
    json.dumps(identity.to_dict())


def test_config_and_stored_config_are_one_document(project):
    assert project.session.config.to_dict() == project.session.stored_config().to_dict()
    config = project.session.config
    assert config.protocol == "SWP-1"
    assert config.protect.targets == ["src"]
    assert isinstance(config.protect.excludes, list)
    assert config.limits.to_dict() == project.session.limits.to_dict()


def test_limits_are_the_knobs_the_build_declares(project):
    limits = project.session.limits.to_dict()
    assert len(limits) == 17, "the resource budget is the seventeen knobs `Limits` has"
    for name, value in limits.items():
        assert isinstance(value, int) and value > 0, name


def test_overrides_reach_the_session_that_reads_them(make_project):
    """A `targets` override is applied to the session, and the config is left alone.

    Two different overrides of one project are two different sessions: the store's
    own `[protect]` section is what `config` shows when nothing overrides it.
    """
    made = make_project(
        "overrides",
        files={
            "app/index.js": SOURCE_TREE["src/app.js"],
            "lib/util.py": SOURCE_TREE["src/util.py"],
        },
    )
    session = swp.Session.open(
        str(made.root),
        swp.Overrides(targets=["app"], excludes=["**/generated/**"], tag_bits=6),
    )
    assert session.config.protect.targets == ["app"]
    assert session.config.protect.tag_bits == 6
    assert "**/generated/**" in session.config.protect.excludes
    # The store keeps what the operator wrote; an override is this run's.
    assert session.stored_config().protect.targets == ["app", "lib"]
    assert session.stored_config().protect.tag_bits == made.session.config.protect.tag_bits
    assert any(
        "[protect] targets for this run" in warning and "config.toml says" in warning
        for warning in session.warnings
    ), session.warnings


def test_a_target_outside_the_project_is_refused(make_project):
    """Containment is checked when the session is built, not when it writes."""
    made = make_project("escape")
    outside = str(make_project("elsewhere").root)
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(str(made.root), swp.Overrides(targets=[outside]))
    assert caught.value.code == "USAGE"
    assert "--target" in caught.value.message


def test_warnings_are_strings_this_build_has_a_word_for(project):
    assert all(isinstance(w, str) and w for w in project.session.warnings)


def test_an_unprotected_directory_is_refused_not_invented(make_project):
    bare = make_project("bare", init=False)
    with pytest.raises(swp.Error) as caught:
        swp.Session.open(str(bare.root))
    assert caught.value.code == "NOT_PROTECTED"


def test_a_project_with_no_releases_says_so(project):
    """`releases` refuses rather than returning an empty list a caller would trust."""
    for method in ("releases", "one_release"):
        with pytest.raises(swp.Error) as caught:
            getattr(project.session, method)(swp.ReleaseSelection.all())
        assert caught.value.code == "NOT_PROTECTED"
    assert project.session.release_history() == []
    assert project.session.reports() == []


def test_release_listing_names_the_releases_this_project_published(make_project):
    """Two releases, listed, with `latest` meaning the newest record and not the last name.

    `releases()` comes back in the store's own order; `release_history()` is sorted
    oldest-first, and `one_release(latest())` picks by the recorded time. A test that
    confused those three would pass on a single-release project and fail on the
    second one, which is the case that matters.
    """
    made = make_project("two-releases")
    first = made.protect(swp.Mode.Release)
    second = made.protect(swp.Mode.Release)
    session = made.session
    assert second.release_id != first.release_id

    ids = session.releases(swp.ReleaseSelection.all())
    assert set(ids) == {first.release_id, second.release_id}
    history = session.release_history()
    assert {r.release_id for r in history} == set(ids)
    stamps = [r.created_at for r in history]
    assert stamps == sorted(stamps), "history is oldest-first, by the recorded time"
    assert session.one_release(swp.ReleaseSelection.latest()) == history[-1].release_id
    assert session.releases(swp.ReleaseSelection.ids(ids[:1])) == ids[:1]
    assert session.one_release(swp.ReleaseSelection.ids(ids[:1])) == ids[0]

    selection = swp.ReleaseSelection.ids(ids)
    assert selection.kind == "ids"
    assert selection.release_ids == ids
    assert swp.ReleaseSelection.all().kind == "all"
    assert swp.ReleaseSelection.latest().kind == "latest"
    assert swp.ReleaseSelection.latest().release_ids == []


def test_a_selection_naming_an_unknown_release_is_refused(protected):
    protected.protect(swp.Mode.Release)
    with pytest.raises(swp.Error) as caught:
        protected.session.releases(swp.ReleaseSelection.ids(["rel-" + "q" * 13]))
    assert caught.value.code == "NOT_PROTECTED"
    assert "It has" in caught.value.message, "the refusal should name what does exist"


def test_release_record_matches_the_run_that_wrote_it(protected):
    summary = protected.protect(swp.Mode.Release)
    record = protected.session.release(summary.release_id)
    assert record.project_id == summary.project_id
    assert record.release_id == summary.release_id
    assert record.fingerprint == summary.fingerprint
    assert record.fingerprint_level == summary.fingerprint_level
    assert record.watermark.tag_bits == summary.tag_bits
    assert record.watermark.sites_embedded == summary.sites_embedded
    assert record.watermark.target_sites == summary.target_sites
    assert record.watermark.canonicalizer_version == swp.capabilities().canonicalizer_version
    assert record.protocol == "SWP-1"
    assert record.signature
    assert re.fullmatch(r"[0-9a-f]{64}", record.private_manifest_digest)
    assert record.watermark.adapters, "a release with no adapter row claims nothing"
    for adapter in record.watermark.adapters:
        assert adapter.language in swp.capabilities().language_names()
        assert adapter.files > 0
    json.dumps(record.to_dict())


def test_an_unknown_release_id_is_an_error_not_an_empty_record(protected):
    with pytest.raises(swp.Error) as caught:
        protected.session.release("rel-" + "z" * 13)
    assert caught.value.code in set(swp.error_codes())


def test_session_repr_names_the_root_and_the_id_and_nothing_else(project):
    text = repr(project.session)
    assert text.startswith("Session(project_root='")
    assert project.init.project_id in text
    assert "root.key" not in text
    for needle in project.secret_strings():
        assert needle not in text
