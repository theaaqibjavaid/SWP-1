# Contributing to SWP-1

Thank you for taking the tool seriously enough to change it. This page is the
short version of what happens to a contribution here: how to build it, what the
checks will reject, which rules the codebase is shaped by, and what you agree to
when you send code.

Start with the honest framing. SWP-1 is a provenance instrument, not DRM, and its
documentation is not permitted to blur that —
[docs/SECURITY.md](docs/SECURITY.md#attacks-and-what-still-gets-through) states
what each attack leaves unpunished. A very
large share of the work in this repository is the work of *not overclaiming*: the
evidence ladder has stated rungs, the report prints the coincidence bound beside
the verdict, and the test suite includes a section whose job is to defeat the
watermark. Changes that make a finding sound stronger than the measurement behind
it are the one category of pull request that will be closed rather than revised.

## Before you write code

* Read [GETTING-STARTED.md](docs/GETTING-STARTED.md) far enough to have protected
  a tree and scanned a copy of it. Most "the tool should do X" reports are the
  tool doing X in a way the report did not expect, and the transcript settles it.
* Search the open issues. If you found a false positive or a missed detection,
  that is a bug and it needs a reproducing tree; if you think a claim in the
  documentation is wrong, that is a bug too, and a more serious one.
* Open an issue before a change that alters the protocol or an artifact format,
  what a report is permitted to claim, the CLI surface, the dependency list, or
  key material and sealing. Those five are expensive to reverse and cheap to
  discuss, and they are the same five the pull request template asks about.
* For anything smaller — an adapter gap, a wrong word, a confusing error message —
  a pull request is a fine first contact.

## Getting set up

The workspace declares Rust 1.85 as its minimum supported version, and
`rust-toolchain.toml` names the one version this project actually builds and lints
with, so CI and your machine agree. The floor is a declaration in `Cargo.toml`, not a
CI job: nothing in the matrix compiles the tree at 1.85, so the minimum is what the
manifest promises rather than what the suite proves. If you depend on an old toolchain
and hit a failure at the declared floor, that is a bug worth filing.
Nothing else is needed: the grammars are prebuilt crates, the CLI's argument parser
is hand-written, and there is no code generation step to run.

```sh
git clone https://github.com/theaaqibjavaid/SWP-1
cd SWP-1
cargo build --locked            # or cargo build --release --locked
cargo test --workspace --locked
cargo run -p swp-cli -- --version
```

Everything below is what CI runs; running it locally before pushing saves the
round trip.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast
cargo test --locked -p swp-test-suite --test docs_examples
```

The last one is the project's odd rule, and it is load-bearing. Every `console`
block in `README.md`, in every page under `docs/` and in the four example
transcripts is re-executed against the current build, with fresh root secrets, and
compared line by line. Add a flag, change a wording, alter what `protect` prints,
and you may have to update a documented example — which is the intended
mechanism, not a nuisance. A number that varies with the key is written `…`;
a number that does not is a number the test re-checks, so do not "fix" one by
inventing a plausible value.

## The rules the shape of the code is made of

These are the ones a reviewer will point at. The long version, with the module
map, is [DEVELOPER-GUIDE.md](docs/DEVELOPER-GUIDE.md).

* **Dependencies point one way.** `swp-cli` over the services over
  `swp-core`/`swp-crypto`, and only `swp-adapters` links a parser. If your change
  needs `swp-core` to know about languages, or the evidence layer to know how a
  fragment is rendered, the design is telling you something.
* **No network code path, ever.** Not in the product, not in a build script, not
  behind a feature flag. `swp` opens no socket in any code path, and a test that
  needed one would be a change of scope rather than a change of code.
* **Never invent a primitive.** Hashes, MACs, signatures and randomness come from
  the crates already in `[workspace.dependencies]`. New ones need a reason that
  survives review, and a smaller supply chain is one of the reasons this tool can
  be trusted offline.
* **The root secret stays out of everything.** Not in source, generated source,
  public manifests, CLI output, logs, documentation, test snapshots or temporary
  files. The `secret_leak` suite sweeps each of those artifact types; if you touch
  key material, run it first.
* **If a location cannot be embedded safely, skip it.** Never force. A refusal
  that costs the user a site is a designed outcome; a rewrite that changes what a
  program computes is the failure this project exists to avoid.
* **Errors use the existing model.** A new failure mode needs an error code, the
  text a user reads, and a line in [CLI.md](docs/CLI.md) and
  [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). Exit codes are stable, and
  changing one is a breaking change even when no function signature moved.
* **A claim in a document needs a measurement behind it.** If you write that a
  detection is strong, point at the suite that counts it and put the number in
  [VALIDATION.md](docs/VALIDATION.md).

## Adding a language

That is the most useful contribution available, and it is deliberately walled off
from the rest of the protocol. [Adding a language
adapter](docs/DEVELOPER-GUIDE.md#adding-a-language-adapter)
is the specification of what an adapter must prove — including the part that
matters more than parsing: after the rewrite, the file must re-parse, canonicalize
to what the protocol expected, and evaluate to the same value. C, Java, Go, Ruby
and PHP are the shapes users ask for most; the generic fallback does not become an
adapter by being left in place, and `examples/generic` documents the refusal.

## The CLA, and the DCO

Anything beyond a trivial change requires the
[Contributor Licence Agreement](CLA.md) to be signed — the bot will ask on your
first pull request, and one signature covers all your later contributions.

It is worth being plain about what that agreement does and does not do, because
this is where a project either earns trust or loses it. The code you contribute
stays yours, and the Apache-2.0 licence you contribute under is irrevocable for
what has already been published. What the CLA adds is the Maintainers' right to
relicense a *derivative* — which exists because the same team intends to build a
closed, sponsor-funded product on top of this codebase. That is a real asymmetry,
it is not hidden in a footer, and you are free to decline it: a contributor who
wants a licence that can never change should send their work to a copyleft project
instead, and nothing here is worse for you if you do.

A [Developer Certificate of Origin](https://developercertificate.org/) — the
`Signed-off-by:` trailer — states that you may submit the code. It grants the
project nothing beyond the licence the code already carries, so it cannot support
the right described above. If this project ever gives up that commercial path,
switching to a DCO is the correct move, and this section should say so in the same
change that removes the CLA bot. Until then, a `Signed-off-by:` line is welcome as
provenance and is not a substitute.

## Sending the pull request

One change per pull request, a description that says *why*, and a title in the
imperative under about 70 characters. The history here reads like
`adapters: refuse a template literal whose spans overlap`, which is the register
that works.

If you changed behaviour, the pull request should contain the test that fails
without it — including for documentation, where the test is `docs_examples`. If
you changed what a report can claim, say so in the description and expect a
reviewer to read the wording in [Reading a
report](docs/USER-GUIDE.md#reading-a-report) line by line.

Squash-merging is fine. Do not rebase a branch after review comments have been
answered against it; force-pushing over a reviewed commit makes a review that no
longer describes what landed.

## Conduct

The [Code of Conduct](CODE_OF_CONDUCT.md) applies to every thread in this
project's name, including the ones where somebody is wrong about the protocol.
Technical disagreement is the point of the thing; contempt is not.

## Getting help

[TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) covers every error the tool prints,
[docs/USER-GUIDE.md](docs/USER-GUIDE.md#reading-a-report) every field of a report,
and [the discussions](https://github.com/theaaqibjavaid/SWP-1/discussions) is where
a question belongs before it becomes an issue. If you think you have found a
security problem rather than a bug, use the route in [SECURITY.md](SECURITY.md)
instead of an issue.
