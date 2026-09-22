# Python example — the same cart, unprotected and then protected

Two files: `src/money.py` is whole-cent arithmetic, `src/cart.py` a cart that
stores cents and basis points. It is deliberately the Python twin of
[`../javascript`](../javascript) — the same shape of program, a different parser,
a different runtime's idea of a number — because the interesting documentation
question is not "does it work" but *what differs*, and this page answers it with
transcripts.

The conventions are the ones described on the JavaScript page: a `console` block
is verbatim tool output, `…` stands for whatever this project's secret influences,
and every unelided line is re-checked against the current build by
`cargo test -p swp-test-suite --test docs_examples`.

## Protecting it

```console
$ swp init
  name       python
  secret     created · handle … · permissions verified
  .gitignore created

What this tree holds
  2 source file(s) a scanner can use, 2316 byte(s) read — python 2
  3 file(s) the walk refused or excluded, so they are not in that count

What was configured in .swp/config.toml
  [protect] targets      src
  [protect] target_sites 4
  [protect] tag_bits       4
  [protect] embed_strings true
exit 0
```

```console
$ swp generate
plan mode: no source file was modified, and no release record or manifest exists for this run
warning: 14 candidate location(s) were refused for safety; the release carries 4 sites
  sites       4/4 embedded, 14 refused
  scope       2 file(s) analyzed, 2 file(s) hashed into the fingerprint

What was modified
  src/cart.py — 2 site(s), 1213 → … bytes
  src/money.py — 2 site(s), 1103 → … bytes

What was refused, and why (§11: skipped, never forced)
  constellation-full       14
exit 0
```

```console
$ swp protect --sites 12
2 source files modified in place
warning: 10 candidate location(s) were refused for safety; the release carries 8 sites
  sites       8/12 embedded, 10 refused
  tag         4 bits per site
  fingerprint … (L1)
  scope       2 file(s) analyzed, 2 file(s) hashed into the fingerprint

What was modified (2 file(s))
  src/cart.py — 3 site(s), 1213 → … bytes
  src/money.py — 5 site(s), 1103 → … bytes

What was refused, and why (§11: skipped, never forced)
  overlapping-radius       10
exit 0
```

Two files hold eight sites where three hold ten, and every refusal in this tree is
`overlapping-radius` rather than an unsafe location: `src/money.py` and
`src/cart.py` are dense with literals sitting close together. That eight is the
same eight under a different root secret is the property that lets this page print
the number at all — it is a fact about the tree, established by the selector's
ordering rules, while which literal inside each file carries a site stays keyed.

```console
$ swp verify
  manifest    authenticated · 8 site(s) at 4 bit(s) each
  fingerprint match (release published …)
  verdict     INTACT — 8/8 site(s) still carry their code, 32 keyed bit(s)
  channels    8 exact rendering(s), 0 address-without-code, 0 absent

Every site of this release is present with its code. That is the whole claim; it says nothing about the tree being otherwise unchanged.
exit 0
```

```console
$ swp scan ./copy
scope     2 file(s), … byte(s)
result    PROVENANCE_DETECTED
evidence  VERY_STRONG

Project swp1-… · release rel-…
  Watermark fragments: 8/8
  Exact renderings: 8
  Found outside their original file: 0
  Keyed bits confirmed: 32 at 4 bits per site
  Fingerprint (8): match
  Evidence: VERY_STRONG
exit 1
```

## The same source with nothing written into it

`../plain` is the tree this example started from: `src/` and `pyproject.toml`
copied out before `swp init` ever ran, so it is the same program, function for
function, with no fragment of this release in it. `scripts/capture-docs.sh`
assembles it that way on purpose. Scanning it is the most useful transcript on
this page:

```console
$ swp scan ../plain
result    NO_PROVENANCE_DETECTED
evidence  NONE

Project swp1-… · release rel-…
  Watermark fragments: 0/8
  Address without its code: 8
  Exact renderings: 0
  Keyed bits confirmed: 0 at 4 bits per site
  Fingerprint (8): no-match
  Evidence: NONE

Skipped (1): not examined, so not cleared
  - pyproject.toml: no language adapter for this file type
exit 0
```

`NO_PROVENANCE_DETECTED`, exit `0`, and not one of the eight sites carrying its
code — while all eight of their *addresses* are reproduced. The report prints that
as `Address without its code: 8`, records each one as `STRUCTURAL_MATCH`, and
rates it WEAK — a grade that asserts nothing, which is the point: the finding it
declines to make is stated in its own words, that a copy of an unprotected build
and a deliberate strip are indistinguishable here.

That is the boundary this project documents rather than oversells. SWP-1 proves
provenance when a fragment survives. It cannot see this cart, because there is
nothing in it to see: the literals the watermark lived in are ordinary literals
again, and a reimplementation from memory leaves the same trace — which is to say,
none. Nothing about a clean scan of this kind supports a claim of removal, only
the far weaker one that this candidate holds no code this project wrote.

`pyproject.toml` in the Skipped list is the other half of the same honesty. A file
no adapter parses was not examined, so it is not cleared, and `scan` keeps a clean
reading of what it did look at separate from the parts of a candidate it could not
read at all.

## What a Python site looks like

Four families can write a site into Python. These are all real renderings from
protected copies of these two files; the three integer lines are one release, so
they belong together, and the rest are other secrets.

```python
total = 0
extra = 1 if index < rest else 0
return int(round(units * percent / 100))
```

```python
total = (6 - 6)
extra = (13 - 12) if index < rest else 0
return int(round(units * percent / (97 + 3)))
```

```python
raise TypeError("units must be an integer count of cents")
```

```python
raise TypeError(("units must be" + " an integer count of cents"))
```

The pair above is what JavaScript does too, and for the same reason: one literal
becomes two with a `+` between them. Python additionally allows two string
literals to sit side by side and concatenate at compile time, so it has a family
the other two languages cannot use:

```python
raise TypeError(("units" " must be an integer count of cents"))
```

```python
raise ValueError("quantity must be between 1 and 50")
```

```python
raise ValueError("\x71uantity must be between 1 and 50")
```

Each of those four is available because the Python dialect says so, and the
gates run in both directions. `adjacent_strings` is true for Python alone, so
`str-adjacent` is the one family the other two languages never see; a scanner
working under a JavaScript release refuses to decode an adjacent pair rather than
guess at what that parser meant. `hex_escapes` is what `str-escape` needs, and all
three parsed languages set it. The last difference runs the other way: the
arithmetic families stop at 2^53 − 1 in JavaScript and TypeScript because a number
there is an IEEE-754 double, while Python integers have no such ceiling, so a site
here is bounded by the implementation's own integer width instead.

## What never became a candidate here

`inspect plan` lists ten refusals and all ten are radius overlaps. This tree also
contains a module docstring in each file, four f-strings, a `"\n"` in
`Cart.receipt` and an empty `""` in `units_to_text`. None of them appears in that
table, because none of them was ever offered: a string whose contents are not its
value is not a literal this protocol rewrites.

| in this tree | why the adapter declines it |
| --- | --- |
| `"""A shopping cart …"""` | triple quotes may span lines; the text between them is not source text |
| `f"{sign}{whole}.{part:02d}"` | a prefix character changes how the contents are read |
| `"\n".join(rows)` | the body already contains an escape, so splitting it would move a value |
| `""` | nothing to carry a code in |

Those omissions are not counted as refusals anywhere, which is worth knowing when
a tree offers far fewer sites than it appears to: `10 refused` in the transcript
above means ten candidates that reached selection and lost, not ten literals the
tool was shy about touching.

## Running it

```bash
cd examples/python
swp init
swp generate
swp protect --sites 12
swp verify
```

Run it in a copy of this directory. `swp init` writes a real root secret to
`.swp/private/root.key` inside it, and that file is the one thing on this page
that must never be committed or shared.

## Reading the rest

- [`../../docs/GETTING-STARTED.md`](../../docs/GETTING-STARTED.md) — the same sequence, step by step
- [`../../docs/LANGUAGE-ADAPTERS.md`](../../docs/LANGUAGE-ADAPTERS.md) — every family and every refusal rule
- [`../../docs/CLI.md`](../../docs/CLI.md) — every option used above
- [`../../docs/REPORTS.md`](../../docs/REPORTS.md) — what each report line means
- [`../../docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md) — why the clean scan above is the expected result, not a failure
