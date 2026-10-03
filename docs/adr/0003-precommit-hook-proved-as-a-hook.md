# ADR-0003 — `pre-commit` is documented as a hook but has never been run as one

**Status: proposed.** This record settles what the next increment on the hook should
prove. It starts by correcting two claims that were made about the hook in conversation
and are false: the JSON output does not need adding, and neither does the documentation of
the option that selects it.

## 1. Problem

`docs/GETTING-STARTED.md:343` tells an operator to put `swp pre-commit` in
`.git/hooks/pre-commit`, and `docs/USER-GUIDE.md:308` tells them the same line works as
the last step of a CI job. Both sentences are claims about behaviour *inside git and
inside a pipeline*, and no code in this repository has ever exercised them.

## 2. What is already true, measured on this tree

* `swp pre-commit --format json` is accepted and works. Five call sites in
  `crates/swp-cli/src/precommit.rs` run it (lines 103, 125, 151, 212, 215).
* The option is documented: `docs/CLI.md:379`, in the `swp pre-commit` section, lists
  `--format <text|json>` as "the same verdict as a document".
* The document is `VerifyDocument` (`crates/swp-evidence/src/verify.rs:139`), whose
  fields a pipeline reads are `release_id` (`:145`) and `verdict` (`:167`), the latter
  serialised in `SCREAMING_SNAKE_CASE` (`:49`) — `INTACT`, `INCOMPLETE`, `INCONCLUSIVE`.
* The three verdicts are already pinned by name in the tests: `precommit.rs:107`, `:134`
  and `:160` assert `doc["verdict"]` is `INTACT`, `INCOMPLETE` and `INCONCLUSIVE`, and
  `:108` asserts `exit_code` agrees with the process status. So there is no missing
  assertion to add, and a proposal to "pin the machine field in a test" would be redoing
  work that is already done.
* What the documentation does not say: which document `--format json` emits, or which
  field of it carries the grade. Grepping `"schema"` and `"verdict"` across `docs/CLI.md`
  returns nothing, so a pipeline author following `docs/CLI.md:379` learns the option
  exists and not what it prints. The exit-code half *is* documented
  (`docs/CLI.md:395-399`), and correctly.
* Nothing anywhere invokes the command through git. Grepping `hooks/pre-commit`,
  `core.hooksPath` and `git commit` across `.rs`, `.sh`, `.yml` and `.md` finds only the
  two prose instructions above and a comment at `precommit.rs:191`.

## 3. Decision

Do two things, and no third one:

1. **Run the hook as a hook, in a test.** Build a throwaway repository with `git init`,
   protect it, write `.git/hooks/pre-commit` by hand in the test (the product does not
   install it), and assert the pair the documentation promises: a clean tree commits, and
   after a protected site is stripped `git commit` fails *and no commit exists*. The
   second half is the claim, because a command that exits 5 but whose exit status git
   ignores would still let the commit through.
2. **Name the document the option emits**, in prose only. One sentence in `docs/CLI.md`'s
   `pre-commit` section: `--format json` writes the `SWP-1-verify-v1` document, a pipeline
   keys on its `verdict` field, and the exit code is the same answer in the shape git
   reads. No new field, no new document, no new assertion — §2 shows the three verdict
   values are already pinned in the tests, and a sentence that the tests already prove is
   a sentence that cannot drift.

## 4. Rejected

* **An installer verb** (`swp pre-commit install`) that writes into `.git/hooks/`. The
  product writes only inside `.swp/`, and a hook file is the operator's, versioned or not
  by their choice. Writing outside the store for a convenience line is the kind of scope
  creep SPEC's non-goals exist to stop.
* **A `--bypass` or `--warn-only` flag.** Git already has `--no-verify`, and a second
  bypass inside the tool makes the gate advisory: the tool would then be the thing that
  weakened the check it exists to run.
* **Reading git's index instead of the working tree.** It would need either `.git/index`
  parsing or a git subprocess, and the command's promise is deliberately the weaker one
  it documents.

## 5. Consequences

The hook becomes the one surface whose tests run through the tool that calls it, which
means a regression in how git treats exit codes is caught here rather than in someone's
commit. It also costs a test that depends on a working `git` binary on the runner, so the
job must fail loudly on `git --version` rather than reporting a watermark problem.

## 6. Follow-ups

Whether `verdict` deserves a documented `null` for a tree with no release is a separate
question; today that path is `NOT_PROTECTED` (exit 4) before a document exists.
