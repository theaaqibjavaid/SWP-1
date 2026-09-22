# Generic example — a tree this build refuses

`src/frame.c` computes a CRC, `src/retry.sh` retries a command with a bounded
backoff, `src/rollup.sql` is a view over settled invoices. None of the three is a
language this build can protect, and that is the whole point of the directory:
the other three examples show what SWP-1 does, and this one shows where it stops
and how it says so.

Conventions as elsewhere — verbatim output, `…` for whatever the project secret
influences, re-checked against the current build by
`cargo test -p swp-test-suite --test docs_examples`.

## Init works; nothing after it does

```console
$ swp init
warning: no file under the default scope has a language adapter, so `swp protect` will refuse this tree. This build parses javascript, typescript, python; point [protect] targets at part of it that does, or add an adapter.
  name       generic
  secret     created · handle … · permissions verified
  .gitignore created

What this tree holds
  0 source file(s) a scanner can use, 0 byte(s) read — none of it has a parser
  5 file(s) the walk refused or excluded, so they are not in that count

What was configured in .swp/config.toml
  [protect] targets      src
  [protect] target_sites 4
  [protect] tag_bits       4
  [protect] embed_strings true
exit 0
```

`init` succeeds here on purpose. It writes a store and a secret and touches no
source; refusing it would mean a user could never open the `.swp/config.toml` the
warning tells them to edit. The refusal belongs to the command that would have
done the damage, so the warning is the whole of `init`'s answer, and the zero
count is stated as a count rather than hidden.

```console
$ swp generate
error [NO_SAFE_LOCATIONS]: nothing to protect under "…": 3 paths refused (no language adapter for this file type). Check [protect] targets and excludes in .swp/config.toml
  next: Nothing under [protect] targets has a language adapter, so this tree is not source to SWP-1 and nothing was written. This build parses javascript, typescript, python; another language needs an adapter, which is the extension point the documentation describes. Point [protect] targets at the part of the tree that is one of them, if there is one.
exit 15
```

```console
$ swp protect --sites 12
error [NO_SAFE_LOCATIONS]: nothing to protect under "…": 3 paths refused (no language adapter for this file type). Check [protect] targets and excludes in .swp/config.toml
  next: Nothing under [protect] targets has a language adapter, so this tree is not source to SWP-1 and nothing was written. This build parses javascript, typescript, python; another language needs an adapter, which is the extension point the documentation describes. Point [protect] targets at the part of the tree that is one of them, if there is one.
exit 15
```

`NO_SAFE_LOCATIONS`, exit `15`, and no source file opened for writing. This is not
the §11 skip — that rule refuses a *location* inside a tree the tool can read. A
tree it cannot read is a different answer and gets a different code, because the
next step is different: one is "ask for fewer sites", the other is "this language
is not here".

```console
$ swp verify
error [NOT_PROTECTED]: this project has no protected releases yet. Run `swp generate` to plan one, then `swp protect`
  next: Run `swp init` then `swp protect` in the project first.
exit 4

$ swp inspect releases
error [NOT_PROTECTED]: this project has no releases yet. `swp generate` plans one; `swp protect` makes one.
  next: Run `swp init` then `swp protect` in the project first.
exit 4
```

`swp scan <candidate>` from this directory fails the same way, for the same
reason: a scan is a comparison against a release, and there is none. It does not
report `NO_PROVENANCE_DETECTED`, which would be a claim about the candidate
rather than about the missing half of this comparison.

## The refusal that is not this one

A tree being *partly* unsupported is normal, and the same naming rule applies at
file granularity. On the Python page, scanning a copy lists `pyproject.toml`
under **"Skipped (1): not examined, so not cleared"** and still exits `0`. That is
not a contradiction. A file no adapter covers can never have carried a site of
this release, so leaving it out does not weaken the statement the scan makes about
the files it did read.

What does weaken it is a file that *could* have carried a site and was not
examined — over a size limit, inside an archive the scanner stopped taking apart,
a link it refused to follow. Those omissions mark the report `partial`, and a
partial scan with nothing in it reads `INCONCLUSIVE` and exits `10`, never `0`.
The exit code is the difference between "this copy holds no fragment of the
release" and "this scan did not finish".

That is the distinction worth carrying away from this directory. SWP-1 has three
verbs for a file: it protected it, it examined it and found nothing, or it never
looked. The third is printed and counted, and when the third is the reason a scan
came back empty, the empty answer is not allowed to look like a clean one.

## There is a lexical fallback, and it is not wired to a file type

A `GenericAdapter` does exist in this build: it tokenizes literals without a
grammar, offers numeric literals in expression positions only, refuses every
string, and caps whatever it produces at token-level evidence. `swp protect` never
sees any of that. The walk admits a path only when a real grammar covers its
extension:

```rust,ignore
if registry.for_path(Path::new(&rel)).is_none() {
    out.omissions.push(Omission {
        path: rel,
        reason: "no language adapter for this file type".to_string(),
        kind: OmissionKind::NotSource,
    });
    return;
}
```

The reason is the rule that leaves `pyproject.toml` in the Python page's Skipped
list, applied to a whole language instead of one file: without a parser there is
no way to re-read the file after rewriting it and prove the surrounding code
unchanged, and an edit inside a `Makefile` recipe or a JSON value is precisely the
behavioral change §11 forbids forcing. A weaker scan is a decision this build does
not make on a user's behalf, because it is the kind of decision that changes what
a report is worth.

So: adding a language is the extension point, and it is a real one — a grammar, a
[`Dialect`](../../crates/swp-adapters/src/dialect.rs), and an extension list, with
every family, radius rule and refusal shared from there.
[`../../docs/LANGUAGE-ADAPTERS.md`](../../docs/LANGUAGE-ADAPTERS.md) walks through
what an adapter has to answer. What no adapter does is make an unsupported
language supported by guessing over it.

## Reading it as a check on the tool

```bash
cd examples/generic
swp init                 # succeeds, and warns
swp generate             # exit 15
swp protect              # exit 15
swp verify               # exit 4
```

If any of those four ever stops behaving this way, this page is wrong and
`cargo test -p swp-test-suite --test docs_examples` is the thing that should say
so first.

## Reading the rest

- [`../../docs/LANGUAGE-ADAPTERS.md`](../../docs/LANGUAGE-ADAPTERS.md) — what adding C, shell or SQL would take
- [`../../docs/CLI.md`](../../docs/CLI.md) — the exit-code contract this page leans on
- [`../../docs/TROUBLESHOOTING.md`](../../docs/TROUBLESHOOTING.md) — the same messages, from the other side
- [`../python`](../python) — the partly-unsupported case, with its transcript
