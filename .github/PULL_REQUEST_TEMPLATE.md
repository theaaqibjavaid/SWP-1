## Before anything else

* The checks passed locally, with the same flags CI uses: `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test
  --workspace --locked --no-fail-fast`.
* If behaviour changed, this pull request contains the test that fails without it.
  For a documentation change, that test is `docs_examples`.
* If you are a new contributor, the Contributor Licence Agreement statement is in
  the description or has reached `CLA/signatures/` — see `CLA.md`.

## What this changes, and why

One paragraph. Say what problem the change solves before how it solves it; a
reviewer who understands the motivation can tell you about a better mechanism.

## Which of the five this touches

Check every one that applies. Each is expensive to reverse, so a change that
touches one is reviewed differently from a change that touches none.

- [ ] the protocol or a wire/artifact format (`swp-core`, `swp-manifest`)
- [ ] the evidence ladder or what a report is permitted to claim (`swp-evidence`)
- [ ] the CLI surface: a verb, a flag, an output line, an exit code (`swp-cli`)
- [ ] the dependency list (`Cargo.toml`, `Cargo.lock`)
- [ ] key material or sealing (`swp-crypto`)

## If you touched a claim

Which sentence in `docs/` changed, and which suite measures the number behind it.
A claim that no suite measures gets weakened in the documentation rather than left
standing — "does" becomes "does not", or the sentence goes.

- [ ] No claim about detection strength, false positives, or removal resistance was
      added or strengthened in this pull request.

## If you touched an adapter or a language

- [ ] A rewritten file re-parses, canonicalizes to what the protocol expects, and
      evaluates to the same value — and the round-trip test says so.
- [ ] A location that cannot be embedded safely is refused with a reason, not
      forced.

## If you touched the scanner or the archive handling

- [ ] Nothing in the candidate is executed, and no path outside the extraction
      directory is read, written or deleted.
- [ ] Hostile input is refused under the existing limits rather than by a new
      special case.

## Notes for the reviewer

Anything you know is incomplete: a case you did not cover, a simplification you
took, an assumption the tests do not check. Saying it here is cheaper than having
it found later, and it is the reason the adversarial suite gets to exist at all.
