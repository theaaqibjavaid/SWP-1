# Agent instructions for this repository

SWP-1 is a source-provenance watermark: `swp protect` embeds a keyed mark across a
tree, `swp verify` and `swp scan` recover it. It is a provenance instrument, not
DRM, and its documentation is not permitted to blur that. A large share of the work
here is the work of *not overclaiming* — the evidence ladder has stated rungs, the
report prints the coincidence bound beside the verdict, and one test suite exists to
defeat the watermark. A change that makes a finding sound stronger than the
measurement behind it gets closed rather than revised.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before a non-trivial change, and
[docs/DEVELOPER-GUIDE.md](docs/DEVELOPER-GUIDE.md) for the module map. This file is
the short list an agent session needs to start with; it does not replace either.

## Commands

```sh
cargo build --workspace --locked
cargo test --workspace --locked --no-fail-fast
cargo run -p swp-cli -- --version
```

Everything CI runs, in the order `ci.yml` runs it:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast
cargo test --locked -p swp-test-suite --test secret_leak
cargo test --locked -p swp-test-suite --test docs_examples
sh scripts/check-release.sh
```

`rust-toolchain.toml` pins 1.91.1, the version this tree actually builds with;
`rust-version = "1.85"` in `Cargo.toml` is the declared floor, which no CI job
compiles. Scripts in `scripts/` are POSIX `sh`, run through Git Bash on Windows.

## Rules that bind a change

* **Dependencies point one way.** `swp-cli` over the service crates over
  `swp-core`/`swp-crypto`, and only `swp-adapters` links a parser. If a change needs
  `swp-core` to know about languages, the design is telling you something.
* **No network code path, ever.** Not in the product, a build script, or behind a
  feature flag. `swp` opens no socket in any code path.
* **Never invent a primitive.** Hashes, MACs, signatures and randomness come from
  the crates already in `[workspace.dependencies]`; the third-party list is a
  decision, and adding to it needs a reason that survives review.
* **The root secret stays out of everything** — source, public manifests, CLI
  output, logs, documentation, test snapshots, temporary files. `secret_leak`
  sweeps each of those artifact types.
* **If a location cannot be embedded safely, skip it.** Never force. A refusal that
  costs the user a site is a designed outcome; a rewrite that changes what a
  program computes is the failure this project exists to avoid.
* **Errors use the existing model.** A new failure mode needs an error code, the
  text a user reads, and a line in [docs/CLI.md](docs/CLI.md) and
  [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). Exit codes are stable;
  changing one is a breaking change even when no signature moved.

## Documentation is a test target

`docs_examples` re-executes every `console` block in `README.md`, the pages under
`docs/` and the example transcripts against the current build, with fresh root
secrets, and compares the output line by line. Change a flag, a wording, or what
`protect` prints, and the documented example has to change in the same commit —
that is the mechanism, not a nuisance. A number that varies with the key is written
`…`; a number that does not is re-checked, so never "fix" one by inventing a
plausible value. When output moved for a real reason, capture the current
transcripts and reconcile the quoted blocks from them:
`SWP=target/release/swp sh scripts/capture-docs.sh /tmp/capture` writes one text
file per documented command under `/tmp/capture/text`.

## Licence and sponsorship facts to keep true

* Contributions beyond a trivial change require [CLA.md](CLA.md); its §2 grants a
  perpetual, irrevocable, sublicensable right to relicense a *derivative*, which is
  the whole reason it exists instead of a `Signed-off-by:` line. Code already
  published stays Apache-2.0 and irrevocably so.
* [SPONSORS.md](SPONSORS.md) is the promise and the prices on it are the prices.
  Sponsorship funds attention and engineering time; it never unlocks the tool and
  never gates a security patch.
* Adding, renaming or republishing a document means every link to it has to exist:
  check references before a commit, and leave no unfilled `[bracketed]` field
  anywhere in the tree — `check-release.sh` fails on them.

## Working here

* Commit locally. Do not push, add a remote, tag a release or open a pull request
  unless the owner asks for that specific thing.
* One change per commit, message in the imperative and stating *why*; the history
  reads like `adapters: refuse a template literal whose spans overlap`.
* The workspace is public: assume anything committed is read by an auditor, and
  anything under `.swp/private/` is not yours to commit, print, or summarise.
