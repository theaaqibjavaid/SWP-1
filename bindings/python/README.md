# `jrs-swp` — the Python binding

`swp` is a native Python extension over [`swp-sdk`](../../docs/SDK_ARCHITECTURE.md): one
call into the same orchestration layer the CLI uses — the walk, the safety
preconditions, the cryptography, the detection, the evidence grading, the report
arithmetic. The binding adds a Python object model, `os.PathLike` handling, one
exception type, and the GIL discipline; it subtracts the terminal.

The wheel carries the whole implementation, so a wheel built from this directory
adds no dependencies to an application — the extension links the Rust crates,
and nothing here can pull a transitive package into a provenance tool's own
supply chain.

The import is `swp` — `swp` *is* the extension module, not a Python package:
[`[tool.maturin] module-name`](pyproject.toml) says so, and the choice is explained
at [`docs/SDK_ARCHITECTURE.md`](../../docs/SDK_ARCHITECTURE.md) §5, where a
wrapper layer would be where a binding starts restating Rust decisions in Python.

```python
>>> import swp
>>> swp.swp_version          # the tool version the wheel drives
'1.0.0-beta.4'
>>> swp.__version__          # the binding's own version
'0.1.0'
>>> swp.banner()
'SWP-1 — swp 1.0.0-beta.4 — report schema SWP-1-report-v2'
```

## The two rules that shape this surface

* **Nothing keyed crosses the boundary.** `docs/BINDING_SURFACE.json` classifies the
  Rust surface, and the binding wraps exactly the items that file permits. The
  private plan, the keyed site identities, the root secret and the store handle are
  not on any Python type, and they are not reachable by walking a field graph
  from one that is. The suite's leak sweep exercises this against a real
  protection run, in both directions: every string a returned object can print is
  checked against the keyed identities the project's own store holds, and every
  field name a private document carries is checked against the summary's document
  form.
* **No unwind crosses the boundary.** Every operation runs through
  [`detached`](src/error.rs), which releases the GIL, catches a panic, and raises
  the documented [`INTERNAL_ERROR`](src/error.rs) instead of aborting the
  interpreter. What a caller sees is one exception type — [`swp.Error`](#errors)—
  and the code the branch should key on.

## Initialise a project

`Session.init` is the one operation that creates a project, and the only place a
root secret exists: it is drawn, sealed by the operating system, and never
returned. What comes back is *where* it went — `secret_scheme`, `secret_state`
and the 40-bit non-secret `secret_handle` on the result — which is the whole of
the disclosure. `secret_scheme` is `"dpapi"` on Windows and `"plain"` everywhere
else, including macOS: DPAPI is the Windows API, and on the other two the key is
written as itself and protected only by the file's permissions. On Windows
`SWP_SECRET_PLAIN=1` (or `=true`) asks for `"plain"` explicitly, for backup
tooling, containers and CI.

```python
import swp

outcome = swp.Session.init(
    "my-project",
    options=swp.InitOptions(name="sample"),
)
session = outcome.session
print(outcome)
# InitOutcome(project_id='swp1-…', pre_existing=False)

print(outcome.result.secret_scheme)   # "dpapi" on Windows, "plain" on macOS and Linux
print(outcome.result.secret_state)    # "created" here; "kept" on a re-init
print(outcome.result.permissions_verified)
print(outcome.result.settings)
# Settings(targets=['src'], target_sites=4, tag_bits=4, embed_strings=True,
#          written=True, suggestion=4)
```

Re-running `init` on a directory that already has a `.swp/` is idempotent rather
than an error: the existing identity and secret are kept (`pre_existing` and
`secret_state == "kept"` say so on the result), because SWP never replaces a
project secret. Importing somebody else's secret is not offered, in any language.

Opening a project that is already initialised does not re-draw anything:

```python
session = swp.Session.open("my-project")
print(session)
# Session(project_root='…', project_id='swp1-…')

session = swp.Session.discover("my-project/src/util.py")   # walks up to the root
print(session.identity.project_id)
# 'swp1-…'
```

The settings one call overrides, and the releases it selects, live on the
option objects:

```python
overrides = swp.Overrides(target_sites=64, tag_bits=swp.capabilities().tag_bits.max)
session = swp.Session.open("my-project", overrides)
print(session.config.protect.target_sites)   # 64, the override
print(session.stored_config().protect.target_sites)   # 4, what the file says
```

## Protect a tree

`protect_summary` is the only protection operation this binding offers. The Rust
`protect` returns the plan the run wrote, and that plan's site identities are
keyed under the project secret; [ADR-0001](../../docs/adr/0001-protect-generate-binding-boundary.md)
settled that a foreign binding reads the summary instead. What the summary
carries is everything else: the run's arithmetic, its artifacts, its refusal
list, and — for a mode that writes no source — the predicted rewrite it would
have applied.

The three modes differ in one thing only: what they leave behind.

```python
summary = session.protect_summary(swp.ProtectOptions(swp.Mode.Plan))
print(summary)
# ProtectSummary(mode='plan', release_id='rel-…', sites_embedded=2, sites_skipped=4)
print(summary.refusal_counts())
# {'overlapping-radius': 4}
print([ (f.file, f.sites, f.bytes_before, f.bytes_after) for f in summary.files_changed ])
# [('src/app.js', 1, 268, 274), ('src/util.py', 1, 204, 210)]
```

A plan writes nothing but its own document into the private store; a release
publishes a release record and the rewrite:

```python
published = session.protect_summary(
    swp.ProtectOptions(swp.Mode.Release, release_id=summary.release_id, revision="build-7"),
)
print(published)
# ProtectSummary(mode='release', release_id='rel-…', sites_embedded=2, sites_skipped=4)
print(published.artifacts)
# ['.swp/private/plans/rel-…json',
#  '.swp/private/manifests/rel-…json',
#  '.swp/public/releases/rel-…json',
#  'src/app.js', 'src/util.py']
print(published.revision)   # "build-7"
```

A dry run leaves nothing anywhere — no plan, no manifest, no source:

```python
rehearsal = session.protect_summary(swp.ProtectOptions(swp.Mode.DryRun))
assert rehearsal.artifacts == []
assert session.release_history() == []
```

`files_changed` is filled in for every mode; the `mode` word and `artifacts`
are what tell the three apart.

## Verify a copy

`verify` grades this project's own tree against one of its releases; the document
is `SWP-1-verify-v1` and it is built by the Rust crate that grades it —
nothing on this side decides a verdict, compares a probability, or maps a
result to an exit code.

```python
outcome = session.verify(
    options=swp.VerifyOptions(release=published.release_id),
)
print(outcome)
# VerifyOutcome(release_id='rel-…', verdict='INTACT', sites_confirmed=2/2)
print(outcome.fingerprint)          # "match", "no-match" or "not-comparable"
print(outcome.exit_code)            # 0, 5, or 10 — the code a shell would have got
print(outcome.sites[0])
# SiteRow(site=0, file='src/app.js', line_hint=10, language='javascript',
#        adapter='ast', class='integer', family='sub', width=4,
#        status='exact-rendering', confirmed=True,
#        slots=['statement+identifiers', 'statement+names',
#               'scope+identifiers', 'scope+names'],
#        found_in='src/app.js', found_line=10,
#        refactored=False, moved=False)
```

The document is the schema's; `to_json()` is the serialization, and `to_dict()`
is the document plus `report_saved`, the one derived line this binding adds:

```python
import json
document = json.loads(outcome.to_json())
assert "report_saved" not in document     # the schema does not carry it
assert set(outcome.to_dict()) - set(document) == {"report_saved"}
```

## Scan somebody else's artifact

`scan` looks for this project's provenance in a tree or archive it does not own.
The candidate can be a path, a directory, or a zip; the candidate is described by
where it was, not by anything keyed.

```python
outcome = session.scan("staged-artifact")
print(outcome)
# ScanOutcome(result='PROVENANCE_DETECTED', evidence_level='VERY_STRONG', sites=4)
tally = outcome.report.releases[0]
print(tally.level, tally.chance, tally.coincidence_probability)
# 'VERY_STRONG' 0.125 0.007190984592330141
```

`scan` saves a copy of the report under `.swp/private/reports/` when asked —
which is where it belongs, beside the secret and not beside the release:

```python
outcome = session.scan("staged-artifact", save=True)
print(outcome.saved)
# SavedReport(name='scan-…', path='.swp/private/reports/scan-….json')
stored = session.read_report(outcome.saved.name)
print(stored)
# StoredReport(name='scan-…', path='.swp/private/reports/scan-….json',
#              result='…', evidence_level='…')
```

## Read the release history

`session.release_history()` returns the public record of every protected release,
signatures included:

```python
for record in session.release_history():
    print(record.release_id, record.revision, record.fingerprint[:16])
    assert record.validation_error() is None
```

A record that refuses itself carries its reason, and `None` is the answer that
means proceed.

## The module helpers

Four functions need no session:

```python
swp.capabilities()      # the languages, tag widths, site ranges this build claims
swp.banner()            # what `swp --version` prints
swp.error_codes()       # the 17 codes `swp.Error.code` may carry
swp.suggest_sites(128)  # the §9 ladder: how many sites this tree size should aim at
swp.report_stem("scan-2026-09-30T14-18-00Z.json")   # → 'scan-2026-09-30T14-18-00Z'
```

`capabilities()` touches nothing: no filesystem, no project, no secret. It
cannot fail.

## GIL and threads

Every session call runs with the GIL released, so a worker-thread application
does not have its interpreter stop for the length of a walk.

```python
import threading

session = swp.Session.open("my-project")   # one session is safe to share read-only
for thread in range(4):
    t = threading.Thread(target=lambda: session.verify())
    t.start()
```

Two threads may hold two sessions for the same project, exactly as two shells
can; two threads may not *protect* the same project at the same time, for the
same reason two shells must not rewrite the same tree concurrently.

## The objects and their document form

Every returned object answers to `to_dict()` — the document form, in the same
key names the underlying Rust document uses — and to a one-line `__repr__`
naming the fields a traceback would want:

```python
summary = session.protect_summary(swp.ProtectOptions(swp.Mode.Plan))
summary.to_dict()        # the 20 values the CLI reads
repr(summary)
# ProtectSummary(mode='plan', release_id='rel-…', sites_embedded=…, sites_skipped=…)
```

The option types are the same, so `ProtectOptions`, `VerifyOptions`, `Overrides`
and `InitOptions` are all JSON-serializable via their `to_dict()`.

## Errors

One exception type. A new failure mode needs an error code, the text a user
reads, and a line in [`docs/CLI.md`](../../docs/CLI.md) and
[`docs/TROUBLESHOOTING.md`](../../docs/TROUBLESHOOTING.md) — the binding's
`Error` is the same contract on a library side:

```python
try:
    session.scan("never-there")
except swp.Error as err:
    print(err.code)        # 'IO_ERROR'
    print(err.message)     # "cannot read …: The system cannot find the file specified."
    print(err.path)        # None when the path is the cause, a path otherwise
    print(err.next_step)   # the advice the CLI prints
    print(err.rendered)    # the one line a user-facing UI should show
```

Branch on `code`, never on the message. `swp.error_codes()` is the table the
branch can check itself against — the same 17 codes the CLI exits with, spelled
the same way.

## Building the wheel

The binding is a cdylib; `maturin` drives the build and produces an abi3
wheel for the oldest supported interpreter.

```console
$ cd bindings/python
$ pip install maturin
$ maturin build --release --locked
$ pip install target/wheels/jrs_swp-* .whl
```

Tests live in [`tests/`](tests/) and run against the built wheel:

```console
$ python -m pip install pytest jrs-swp
$ python -m pytest
```

The test suite writes real projects with real sealed secrets into temporary
directories, and one test sweeps every byte of them for key material. Leaving
those behind would be leaving key material in the system temp directory, so
nothing is kept; `--keep-tmp` is what a failing run gets read with.

## What this page does not cover

The binding is a transport over `swp-sdk`, and a decision this binding re-speaks
in Python is a second implementation of it. So: nothing here re-derives a tag,
a location id, a coincidence probability, a verdict, or an exit-code mapping.
Where a value is shown, it was read off the Rust document that decided it. The
protocol's full surface — including the CLI's own `swp protect`, `swp verify`
and `swp scan` — is documented at [`docs/`](../../docs/); the boundary this
binding keeps is documented at
[`docs/BINDING_SURFACE.json`](../../docs/BINDING_SURFACE.json) and
[ADR-0001](../../docs/adr/0001-protect-generate-binding-boundary.md).
