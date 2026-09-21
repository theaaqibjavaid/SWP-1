//! Deterministic source fixtures.
//!
//! Every fixture here is fixed content, not generated noise: a measurement that
//! moves between runs is not a measurement. Randomised inputs belong in the
//! property tests, which seed explicitly and print the seed on failure.
//!
//! One fixture is emitted from a template rather than stored verbatim —
//! [`Corpus::Generated`], which writes a code-generator's output. That is the
//! exception that proves the rule: a real generator emits one file per API tag
//! from a single template, so a *single* stored file would not be that corpus at
//! all, and the fan-out below is a pure function of the index, with no key, no
//! clock and no RNG anywhere in it. It writes the same 81 files every run.

use std::path::Path;

/// A small JavaScript project with real literal-bearing code, so the embedding
/// suites have material and the leak suites have something to sweep.
pub fn javascript_project(root: &Path) -> Vec<String> {
    let files = [
        (
            "src/color.js",
            include_str!("../fixtures/javascript/src/color.js"),
        ),
        (
            "src/http.js",
            include_str!("../fixtures/javascript/src/http.js"),
        ),
        (
            "src/main.js",
            include_str!("../fixtures/javascript/src/main.js"),
        ),
        (
            "package.json",
            include_str!("../fixtures/javascript/package.json"),
        ),
    ];
    write_files(root, &files)
}

/// The same program in TypeScript, used to show the watermark does not depend on
/// one language's syntax.
pub fn typescript_project(root: &Path) -> Vec<String> {
    let files = [
        (
            "src/color.ts",
            include_str!("../fixtures/typescript/src/color.ts"),
        ),
        (
            "src/main.ts",
            include_str!("../fixtures/typescript/src/main.ts"),
        ),
        (
            "tsconfig.json",
            include_str!("../fixtures/typescript/tsconfig.json"),
        ),
    ];
    write_files(root, &files)
}

/// The same program in Python.
pub fn python_project(root: &Path) -> Vec<String> {
    let files = [
        (
            "src/color.py",
            include_str!("../fixtures/python/src/color.py"),
        ),
        (
            "src/main.py",
            include_str!("../fixtures/python/src/main.py"),
        ),
        (
            "pyproject.toml",
            include_str!("../fixtures/python/pyproject.toml"),
        ),
    ];
    write_files(root, &files)
}

/// A tree whose literals were chosen so that **every** rendering family the
/// protocol has is reachable, which no realistic project is.
///
/// The three example projects above are realistic, and that turns out to be the
/// problem, twice over. A string can carry a four-bit tag only if it is longer
/// than the modulus, sixteen, and the whole shipped JavaScript example contains
/// one literal that long; and §9's constellation keeps two sites out of the same
/// radius, so four literals inside one function are worth one site. A round-trip
/// matrix over those trees therefore tests two families and passes, which is the
/// vacuous cover `tests/detection/roundtrip.rs` exists to refuse.
///
/// So this corpus is the opposite of the others: nine strings over twenty
/// characters in each of three dialects, one literal per function so the
/// constellation can use all of them, numbers with a divisor in every residue
/// class mod 16 (`720720` is the least common multiple of 1..=16, which is what
/// the factorisation family needs), and numbers whose hexadecimal spelling has
/// four letters — `beef`, `dead`, `ffff` — which is what the radix family needs.
/// `Python` is in the set because `str-adjacent` has no JavaScript spelling at
/// all, so no table of `.js` files could ever have reached it.
///
/// What it does **not** contain is a file no grammar covers: `swp-embedding`'s
/// walk admits only extensions a parser handles, because the lexical fallback
/// cannot prove the surrounding code unchanged, so a `Makefile` would be offered
/// to `swp scan` as evidence and never to `swp protect` as a site. That asymmetry
/// is `walk.rs`'s own rule and this corpus obeys it.
pub fn form_project(root: &Path) -> Vec<String> {
    let files = [
        ("src/pricing.js", include_str!("../fixtures/forms/src/pricing.js")),
        ("src/report.py", include_str!("../fixtures/forms/src/report.py")),
        ("src/labels.ts", include_str!("../fixtures/forms/src/labels.ts")),
    ];
    write_files(root, &files)
}

/// The config that gives [`form_project`] room to write every family, at the
/// protocol's **default** four-bit width.
///
/// Nothing here lowers `tag_bits` to make a family reachable: reaching it at the
/// width a real project ships at is the point, and the difficulty of doing so is
/// itself one of the measurements `docs/LANGUAGE-ADAPTERS.md` quotes. Two suites
/// and the locator's own ground-truth test read this one definition, so a table
/// about "the form corpus" and a table about "the shapes a writer emits" cannot
/// quietly become tables about two different constellations.
pub const FORMS_CONFIG: &str = "[protect]\ntargets = [\"src\"]\ntarget_sites = 48\ntag_bits = 4\n\
                                embed_strings = true\n";

/// An unrelated project that shares the *shapes* a watermark might collide
/// with: the same constants, the same framework idioms, none of the code.
pub fn lookalike_project(root: &Path) -> Vec<String> {
    let files = [
        (
            "src/palette.js",
            include_str!("../fixtures/lookalike/src/palette.js"),
        ),
        (
            "src/server.js",
            include_str!("../fixtures/lookalike/src/server.js"),
        ),
    ];
    write_files(root, &files)
}

/// One of §27's kinds of unrelated source.
///
/// The list is §27's list: common algorithms, common framework patterns, common
/// constants, common boilerplate, standard library usage, generated code,
/// popular open-source structures. Two of those bullets describe the same files
/// (a framework pattern is usually boilerplate too), so the six corpora below
/// cover the seven bullets and each says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corpus {
    /// Sorting, searching, graph traversal, `gcd`, `sieve`, `fibonacci`.
    Algorithms,
    /// A middleware chain and a repository module: the scaffolding a tutorial
    /// produces, with its `200/404/500` and its retry backoff.
    Framework,
    /// An event emitter, `deepClone`, debounce and the colour/byte formatters
    /// every front end has. This is the *common constants* case as much as the
    /// boilerplate one: `255`, `1024`, `360`, `60`.
    Boilerplate,
    /// What a generator emits: one statement shape, restated with a different
    /// name each time. The most self-similar source a scanner can meet.
    Generated,
    /// A Python script over `csv`, `collections` and `argparse`.
    Stdlib,
    /// A redux-shaped store and a keyed list diff, written the way the famous
    /// implementations of them are written.
    Oss,
}

impl Corpus {
    pub const ALL: [Corpus; 6] = [
        Corpus::Algorithms,
        Corpus::Framework,
        Corpus::Boilerplate,
        Corpus::Generated,
        Corpus::Stdlib,
        Corpus::Oss,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Corpus::Algorithms => "algorithms",
            Corpus::Framework => "framework",
            Corpus::Boilerplate => "boilerplate",
            Corpus::Generated => "generated",
            Corpus::Stdlib => "stdlib",
            Corpus::Oss => "oss",
        }
    }

    /// The §27 bullet this corpus answers, for the table the documentation
    /// quotes.
    pub fn describes(self) -> &'static str {
        match self {
            Corpus::Algorithms => "common algorithms: sorts, searches, graphs, primes",
            Corpus::Framework => {
                "common framework patterns and constants: middleware, status codes, backoff"
            }
            Corpus::Boilerplate => {
                "common boilerplate and constants: emitters, clone, colour and byte formatting"
            }
            Corpus::Generated => {
                "generated code at repository scale: one template, 80 modules, same constants"
            }
            Corpus::Stdlib => "standard library usage, in a second language",
            Corpus::Oss => "popular open-source structures: a reducer store and a keyed diff",
        }
    }

    /// Write the corpus into `root` and return the relative paths.
    pub fn write(self, root: &Path) -> Vec<String> {
        let files: &[(&str, &str)] = match self {
            Corpus::Algorithms => &[
                (
                    "src/sort.js",
                    include_str!("../fixtures/false_positive/algorithms/src/sort.js"),
                ),
                (
                    "src/graph.js",
                    include_str!("../fixtures/false_positive/algorithms/src/graph.js"),
                ),
            ],
            Corpus::Framework => &[
                (
                    "src/app.js",
                    include_str!("../fixtures/false_positive/framework/src/app.js"),
                ),
                (
                    "src/repository.js",
                    include_str!("../fixtures/false_positive/framework/src/repository.js"),
                ),
            ],
            Corpus::Boilerplate => &[
                (
                    "src/emitter.js",
                    include_str!("../fixtures/false_positive/boilerplate/src/emitter.js"),
                ),
                (
                    "src/format.js",
                    include_str!("../fixtures/false_positive/boilerplate/src/format.js"),
                ),
            ],
            Corpus::Generated => return generated_sdk(root),
            Corpus::Stdlib => &[(
                "src/inventory.py",
                include_str!("../fixtures/false_positive/stdlib/src/inventory.py"),
            )],
            Corpus::Oss => &[
                (
                    "src/store.js",
                    include_str!("../fixtures/false_positive/oss/src/store.js"),
                ),
                (
                    "src/diff.js",
                    include_str!("../fixtures/false_positive/oss/src/diff.js"),
                ),
            ],
        };
        write_files(root, files)
    }
}

/// How many resource modules [`generated_sdk`] emits. Eighty puts the corpus
/// past the tier where a location id starts to have more candidate spans than
/// the matcher is willing to hold on to, which is the only way the biggest §27
/// risk — that scale, not bad luck, manufactures a confirmation — gets tested.
const SDK_MODULES: usize = 80;

/// The two word lists a resource name is made from, so the fan-out needs no
/// table of 80 strings and no RNG: `FIRST[i / 10]` joined to `FIRST[i % 10]`
/// names every module, and the same `i` picks the path.
const SDK_HEAD: [&str; 10] = [
    "project",
    "deploy",
    "member",
    "quota",
    "region",
    "secret",
    "build",
    "audit",
    "token",
    "cluster",
];
const SDK_TAIL: [&str; 10] = [
    "access",
    "policy",
    "limit",
    "event",
    "cursor",
    "metric",
    "bundle",
    "link",
    "group",
    "index",
];

/// One module of the generator's output, verbatim except for the three names.
///
/// The constants deliberately *do not* vary between modules, which is the exact
/// opposite of [`synthetic_variant`]: a code generator emits `PAGE_SIZE = 100`
/// into all eighty files, because that is what a template is. Every file below
/// therefore carries the same `while` loop, the same five method bodies and the
/// same three numbers — so the statement that holds a literal in file 1 and the
/// statement that holds it in file 80 canonicalize alike, and one site's keyed
/// address is offered several hundred candidate spans.
const SDK_MODULE: &str = r#"'use strict';

// Generated by example-sdk-codegen 2.1.0. Edit the spec, not this file.

const { request } = require('./runtime.js');

const PATH = '@PATH@';
const PAGE_SIZE = 100;
const PAGE_INTERVAL = 30000;
const RETRY_LIMIT = 3;

class @CLASS@Api {
  constructor(client) {
    this.client = client;
  }
  list(params) {
    return request(this.client, 'GET', PATH, undefined, params);
  }
  create(body) {
    return request(this.client, 'POST', PATH, body, undefined);
  }
  read(id) {
    return request(this.client, 'GET', PATH + '/' + encodeURIComponent(id), undefined, undefined);
  }
  update(id, body) {
    return request(this.client, 'PATCH', PATH + '/' + encodeURIComponent(id), body, undefined);
  }
  destroy(id) {
    return request(this.client, 'DELETE', PATH + '/' + encodeURIComponent(id), undefined, undefined);
  }
}

function paginate_@SLUG@(client, params, pages) {
  let cursor = 0;
  const size = params.limit || PAGE_SIZE;
  const out = [];
  while (cursor < pages.length && out.length < PAGE_INTERVAL) {
    const page = pages[cursor];
    if (page.items.length > size * RETRY_LIMIT) {
      break;
    }
    for (const item of page.items) {
      out.push(item);
    }
    cursor += 1;
  }
  return out.slice(0, size);
}

module.exports = { @CLASS@Api, paginate_@SLUG@ };
"#;

/// The hand-written runtime the generated modules require: real codegen trees
/// have one, and a corpus of `require`s to nothing would be a tree no scanner
/// could be blamed for reading oddly.
const SDK_RUNTIME: &str = r#"'use strict';

const BASE = 'https://api.example.com/v1';
const USER_AGENT = 'example-sdk/2.1.0';
const DEFAULT_TIMEOUT = 30000;
const MAX_RETRIES = 3;
const BACKOFF_MS = 250;

function isRetryable(err) {
  const code = err.code || '';
  return code === 'ECONNRESET' || code === 'ETIMEDOUT' || err.status >= 500;
}

function request(client, method, path, body, query) {
  const url = new URL(path, client.base);
  for (const key of Object.keys(query || {})) {
    url.searchParams.set(key, String(query[key]));
  }
  return client.transport({
    url: url.toString(),
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: {
      'user-agent': USER_AGENT,
      accept: 'application/json',
      'content-type': 'application/json',
      authorization: 'Bearer ' + client.token,
    },
    timeout: client.timeout || DEFAULT_TIMEOUT,
    retries: client.retries === undefined ? MAX_RETRIES : client.retries,
  });
}

async function withRetry(client, method, path, body, query) {
  let attempt = 0;
  for (;;) {
    try {
      return await request(client, method, path, body, query);
    } catch (err) {
      attempt += 1;
      if (attempt >= (client.retries || MAX_RETRIES) || !isRetryable(err)) {
        throw err;
      }
      await sleep(BACKOFF_MS * attempt);
    }
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { BASE, request, withRetry, isRetryable };
"#;

/// §27's "generated code" bullet at the scale a generated SDK really has: the
/// hand-written entry point and runtime, plus [`SDK_MODULES`] modules from one
/// template.
pub fn generated_sdk(root: &Path) -> Vec<String> {
    let mut paths = [
        write_files(
            root,
            &[(
                "src/client.js",
                include_str!("../fixtures/false_positive/generated/src/client.js"),
            )],
        ),
        write_files(root, &[("src/generated/runtime.js", SDK_RUNTIME)]),
    ]
    .concat();
    for i in 0..SDK_MODULES {
        let head = SDK_HEAD[i / 10];
        let tail = SDK_TAIL[i % 10];
        let body = SDK_MODULE
            .replace("@PATH@", &format!("/{head}/{tail}"))
            .replace("@SLUG@", &format!("{head}_{tail}"))
            .replace(
                "@CLASS@",
                &format!("{}{}", capitalize(head), capitalize(tail)),
            );
        let name = format!("src/generated/{head}_{tail}.js");
        paths.extend(write_files(root, &[(name.as_str(), body.as_str())]));
    }
    paths
}

/// `project` → `Project`, for the class name the generator would use.
fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// A pricing class: the anchor for `class_rename`, `dead_code_removal`,
/// `function_inlining` and `expression_rewrite`, all of which match its text.
///
/// The three literals it repeats — `0.25`, `0`, `100` — are deliberately *not*
/// parameterised: real codebases have idioms like this in every file, and a
/// measurement tree with no repeated statement at all would flatter the
/// coincidence bound.
const CLASS_BODY: &str = r#"class Bucket_@ID@ {
  constructor(seed) {
    this.seed = seed + @INT@;
  }
  scale(value, rate) {
    const step = value * rate * 0.25;
    return step + @INT@;
  }
  total(rows) {
    let sum = 0;
    for (const row of rows) {
      sum += this.scale(row.amount, row.rate);
    }
    return Math.round(sum * 100) / 100;
  }
}

"#;

/// A ledger class: a getter, a `for…of` over an array of objects, and a float
/// tolerance, which is a different literal class from the pricing one.
const LEDGER_BODY: &str = r#"class Ledger_@ID@ {
  constructor(entries) {
    this.entries = entries;
    this.opened = @INT@;
  }
  get size() {
    return this.entries.length;
  }
  balance(unit) {
    let owed = @FLOAT@;
    for (const entry of this.entries) {
      owed = owed + entry.debit / unit - entry.credit;
    }
    return Math.abs(owed) < 0.005 ? 0 : owed;
  }
}

"#;

/// A range class written the other way round: setters, guards, and a string in
/// the error rather than a number in the return.
const RANGE_BODY: &str = r#"class Range_@ID@ {
  set(value) {
    if (value < @SMALL@) {
      this.low = value - @SMALL@;
    } else {
      this.low = @SMALL@;
    }
    this.high = value + @PCT@;
  }
  covers(other) {
    return other >= this.low && other <= this.high;
  }
}

"#;

/// A free function with a numeric clamp: the anchor for `function_rename`
/// (`duty_` → `charge_`) and for `expression_rewrite`'s `/ 4` rule.
const DUTY_BODY: &str = r#"function duty_@ID@(amount, weeks) {
  const base = amount + @INT@;
  const cap = base / @SMALL@;
  if (cap > @PCT@) {
    return cap - @PCT@;
  }
  return Math.max(cap, @SMALL@) / 1.5;
}

"#;

/// Exception control flow, which is a shape the parser sees differently from a
/// straight-line function.
const TRY_BODY: &str = r#"function parse_@ID@(raw) {
  try {
    const parts = String(raw).split(':');
    const head = Number(parts[0]);
    if (!Number.isFinite(head)) {
      throw new Error('not a number');
    }
    return { head, tail: parts.length > 1 ? Number(parts[1]) : @INT@ };
  } catch (err) {
    return { head: @SMALL@, tail: @SMALL@ };
  }
}

"#;

/// A `while` loop over a `switch`: two integer literals inside the arms, so a
/// site can sit on either the counter or the rate.
const WHILE_BODY: &str = r#"function tally_@ID@(rows, mode) {
  let total = @PCT@;
  let i = 0;
  while (i < rows.length) {
    const row = rows[i];
    switch (mode) {
      case 'gross':
        total += row.amount;
        break;
      case 'net':
        total -= row.amount * @FLOAT@;
        break;
      default:
        total += row.amount / @SMALL@;
    }
    i += 1;
  }
  return total;
}

"#;

/// A method chain: the literals sit inside arrow bodies, which is where a
/// radius has the least statement structure around it.
const PIPE_BODY: &str = r#"function rank_@ID@(items) {
  const scored = items
    .filter((item) => item.score > @SMALL@)
    .map((item) => ({ name: item.name, score: item.score / @PCT@ }));
  return scored.sort((a, b) => b.score - a.score).slice(0, @SMALL@);
}

"#;

/// A data table and its lookup, so a module also offers literals that are never
/// read by any expression.
const TABLE_BODY: &str = r#"const TIERS_@ID@ = {
  gold: { multiplier: @PCT@, floor: @INT@ },
  silver: { multiplier: @FLOAT@, floor: @SMALL@ },
  bronze: { multiplier: @SMALL@, floor: 0 },
};

function tier_@ID@(name, amount) {
  const tier = TIERS_@ID@[name] || TIERS_@ID@.bronze;
  if (amount < tier.floor) {
    return tier.floor - amount;
  }
  return amount * tier.multiplier;
}

"#;

/// Recursion over a tree, with the same literal in two different roles.
const RECURSE_BODY: &str = r#"function depth_@ID@(node, limit) {
  if (node === null || node === undefined) {
    return 0;
  }
  if (limit <= @SMALL@) {
    return @SMALL@;
  }
  const left = depth_@ID@(node.left, limit - 1);
  const right = depth_@ID@(node.right, limit - 1);
  return (left > right ? left : right) + @SMALL@;
}

"#;

/// String building rather than arithmetic: a different literal class again, and
/// the only shape in the generator with a decimal in a method argument.
const LABEL_BODY: &str = r#"function label_@ID@(value, unit) {
  const rounded = value.toFixed(2);
  if (unit === 'kg') {
    return rounded + ' kg (' + (@PCT@ * value).toFixed(1) + ' lb)';
  }
  return unit + ': ' + rounded + ' @WORD@';
}

"#;

/// Guard clauses, one literal per return.
const CHECK_BODY: &str = r#"function check_@ID@(row) {
  if (typeof row.amount !== 'number') {
    return 'amount';
  }
  if (row.amount <= @SMALL@) {
    return 'zero';
  }
  if (row.amount > @INT@) {
    return 'too-large';
  }
  if (row.rate && row.rate > @FLOAT@) {
    return 'rate';
  }
  return '';
}

"#;

/// The one block every module carries verbatim.
///
/// Real projects have these — a clamp, a currency helper, the same five lines in
/// eleven files — and a location id cannot tell them apart, because the names are
/// what differs and the names are exactly what a rename-tolerant radius erases.
/// Keeping one in the tree is what stops the coincidence bound from being
/// measured on a corpus no engineer ever wrote.
const TRIVIA_BODY: &str = r#"function clamp_@ID@(value, unit) {
  let out = 0;
  if (value <= 0) {
    out = 0;
  } else if (value >= unit) {
    out = unit;
  }
  return out;
}

"#;

/// The class shapes, in the order a module picks them.
const CLASS_SHAPES: &[&str] = &[CLASS_BODY, LEDGER_BODY, RANGE_BODY];
/// The function shapes. `TABLE_BODY` contributes a class-level `const` as well.
const FN_SHAPES: &[&str] = &[
    DUTY_BODY, TRY_BODY, WHILE_BODY, PIPE_BODY, TABLE_BODY, RECURSE_BODY, LABEL_BODY, CHECK_BODY,
];

/// A deterministic multi-module JavaScript tree, for the measurement suites.
///
/// §24 asks what happens when a tenth of a project is copied, and §25 when a
/// function moves between files; both need more than a hand-written four-file
/// fixture can offer, and both compare one run against another, so the tree is
/// generated from a fixed seed. The generator is a plain documented LCG rather
/// than `rand`: same module count in, byte-identical files out, on any machine,
/// which is what makes a measured detection rate a measurement and not a sample.
///
/// What a module is made of is chosen by the same seed, and every literal the
/// shapes carry comes from [`Pool`] — so no two statements in the tree share a
/// constant unless the template says so. That matters more than it sounds: a
/// location id is a content address, and a tree built from one template repeated
/// twelve times puts forty candidate spans at *one* site's address, which the
/// coincidence bound must then discount. Measuring that would report on the
/// generator, not on the protocol. `TRIVIA_BODY` is the deliberate exception —
/// one genuinely repeated idiom, because an unrepeatable corpus flatters the
/// bound in the other direction.
pub fn synthetic_project(root: &Path, modules: usize) -> Vec<String> {
    synthetic_variant(root, modules, 0)
}

/// [`synthetic_variant`] with every module drawing its constants from the *same*
/// point in [`Pool`].
///
/// One argument changes this generator's whole character, and it is worth being
/// explicit about which: modules that share a house style *and* share its
/// constants. That is what one team's codebase looks like from the inside — the
/// same `0.25`, the same rounding factor, restated in eighty files — and it is
/// the shape a coincidence bound has to survive, because a keyed address then
/// faces the same span many times over rather than many different ones.
pub fn synthetic_dense(root: &Path, modules: usize, variant: usize) -> Vec<String> {
    synthetic_draw(root, modules, variant, 0)
}

/// [`synthetic_project`] with a different seed for its constants.
///
/// Variant 0 is byte-for-byte the tree every measured table quotes, so the
/// variants are additive: §27's false-positive corpus needs a project that
/// *another* team wrote in the *same* idiom — same shapes, same boilerplate,
/// different constants — and a tree generated with a different seed is exactly
/// that, rather than a copy of the first. The shapes deliberately do not move:
/// an unrelated project that shares a framework's idioms is the case the
/// rename-tolerant radius exists to be careful about, and the shared `0` in
/// `TRIVIA_BODY` is what makes its spans collide with another project's address.
pub fn synthetic_variant(root: &Path, modules: usize, variant: usize) -> Vec<String> {
    synthetic_draw(root, modules, variant, 1)
}

/// The generator, with the pool's per-module stride exposed as `spread`.
///
/// `spread = 1` is the tree every measured table quotes. `spread = 0` starts
/// every module's pool at the same counter, so the same statement carries the
/// same constant in module 0 and module 70 — see [`synthetic_dense`].
fn synthetic_draw(root: &Path, modules: usize, variant: usize, spread: u64) -> Vec<String> {
    assert!(modules >= 8, "a synthetic tree smaller than 8 modules cannot express a 10% copy");
    let mut paths = Vec::new();
    for k in 0..modules {
        let mut rng = Lcg::new(0x5dee_cee6 + (k + variant * 97) as u64 * 0x10e3_92d2);
        let mut pool = Pool::new(spread * k as u64 * 4096 + variant as u64 * 1_000_003);
        let mut body = String::new();
        body.push_str(&format!(
            "// module {k}: pricing helpers. Written for the SWP-1 measurement suites.\n\
             'use strict';\n\n"
        ));
        body.push_str(&render(
            CLASS_SHAPES[k % CLASS_SHAPES.len()],
            &k.to_string(),
            &mut pool,
        ));
        if rng.below(2) == 0 {
            body.push_str(&render(
                CLASS_SHAPES[(k + 1) % CLASS_SHAPES.len()],
                &format!("{k}_b"),
                &mut pool,
            ));
        }
        // The first function of module `k` is shape `k`: with twelve modules and
        // eight shapes that puts every shape in the tree at least once, which is
        // what the `Transform` anchors below depend on. Random selection alone
        // would leave a shape out and its transform would measure nothing.
        let fns = (2 + rng.below(3)) as usize;
        let stride = (1 + rng.below(6)) as usize;
        for f in 0..fns {
            // A stride rather than a fresh draw: two independent draws from the
            // same pool can land on one shape twice in one module, and a module
            // that repeats itself is the thing this generator is trying to avoid.
            let shape = FN_SHAPES[(k + f * stride) % FN_SHAPES.len()];
            body.push_str(&render(shape, &format!("{k}_{f}"), &mut pool));
        }
        body.push_str(&render(TRIVIA_BODY, &format!("mod{k}"), &mut pool));
        body.push_str(&format!(
            "const RATES_{k} = {{ gold: {}, silver: {}, bronze: {} }};\n\nmodule.exports = \
             {{ RATES_{k} }};\n",
            pool.int(),
            pool.int(),
            pool.int()
        ));
        let name = format!("src/mod{k}.js");
        let written = write_files(root, &[(name.as_str(), body.as_str())]);
        assert_eq!(written.len(), 1);
        paths.push(name);
    }
    paths
}

/// Fill one shape's placeholders. `@ID@` is passed in because the caller knows
/// what makes this instance's names unique; everything else is drawn from the
/// pool, so the same shape in two modules never carries the same constants.
fn render(template: &str, id: &str, pool: &mut Pool) -> String {
    let mut out = String::with_capacity(template.len() + 32);
    let mut rest = template;
    while let Some(at) = rest.find('@') {
        out.push_str(&rest[..at]);
        let Some(end) = rest[at + 1..].find('@') else {
            out.push('@');
            rest = &rest[at + 1..];
            continue;
        };
        match &rest[at + 1..at + 1 + end] {
            "ID" => out.push_str(id),
            "INT" => out.push_str(&pool.int()),
            "SMALL" => out.push_str(&pool.small()),
            "FLOAT" => out.push_str(&pool.float()),
            "PCT" => out.push_str(&pool.pct()),
            "WORD" => out.push_str(&pool.word()),
            other => out.push_str(&format!("@{other}@")),
        }
        rest = &rest[at + 1 + end + 1..];
    }
    out.push_str(rest);
    out
}

/// The tree's literal supply: one counter per module, stepped so a value is
/// never handed out twice, and formatted in the four spellings the site
/// selector distinguishes — integer, small integer, sub-unit decimal, and a
/// decimal with an integer part.
struct Pool {
    next: u64,
}

impl Pool {
    fn new(seed: u64) -> Self {
        Pool { next: seed + 7 }
    }

    fn int(&mut self) -> String {
        self.next += 37;
        format!("{}", 1_000 + self.next)
    }

    fn small(&mut self) -> String {
        self.next += 11;
        format!("{}", 3 + (self.next % 90))
    }

    fn float(&mut self) -> String {
        self.next += 7;
        format!("0.{:03}", self.next % 900)
    }

    fn pct(&mut self) -> String {
        self.next += 23;
        format!("{}.{:02}", self.next % 80, 1 + self.next % 90)
    }

    fn word(&mut self) -> String {
        const WORDS: [&str; 8] = ["net", "gross", "listed", "final", "base", "capped", "quoted", "set"];
        self.next += 3;
        WORDS[(self.next % WORDS.len() as u64) as usize].to_string()
    }
}


/// The suites' own generator: 64-bit multiplicative LCG, no state shared
/// between modules, so one module's constants never depend on how many came
/// before it.
///
/// It is public because §43's random transform chains need the same property the
/// fixtures need: a failure has to be reproducible from the seed printed in the
/// test output, which a thread-racing `HashMap` iteration or a nanosecond clock
/// would not give.
pub struct Lcg {
    state: u64,
}

impl Lcg {
    pub fn new(seed: u64) -> Self {
        Lcg { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        // Numerical Recipes' constants: any well-known multiplier would do, and
        // naming this one is the point — a fixture that changes when the
        // generator is retuned invalidates every number measured from it.
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state >> 11
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// One of `n` choices, as an index.
    pub fn pick(&mut self, n: usize) -> usize {
        (self.below(n as u64)) as usize
    }
}

fn write_files(root: &Path, files: &[(&str, &str)]) -> Vec<String> {
    let mut paths = Vec::new();
    for (rel, body) in files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("cannot create fixture directory");
        }
        std::fs::write(&path, body).expect("cannot write fixture file");
        paths.push(rel.to_string());
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tmp::TempDir;

    #[test]
    fn fixtures_are_written_and_non_trivial() {
        let tmp = TempDir::new("fixtures");
        let js = javascript_project(tmp.path());
        assert!(js.len() >= 3);
        let body = tmp.read("src/color.js");
        // Enough literals that site selection has real work to do.
        let numeric = body.iter().filter(|b| b.is_ascii_digit()).count();
        assert!(numeric > 60, "fixture too small to exercise embedding");
        assert!(String::from_utf8_lossy(&body).contains("255"));
    }

    #[test]
    fn the_lookalike_shares_constants_but_not_code() {
        let tmp = TempDir::new("lookalike");
        let a = javascript_project(tmp.path());
        let body = String::from_utf8(tmp.read("src/color.js")).unwrap();
        let b = lookalike_project(tmp.path());
        let other = String::from_utf8(tmp.read("src/palette.js")).unwrap();
        assert!(a.len() > 1 && b.len() > 1);
        assert!(
            other.contains("255"),
            "the false-positive fixture must share constants"
        );
        assert_ne!(body, other);
        assert!(
            !body
                .lines()
                .any(|l| other.contains(l.trim()) && l.trim().len() > 30),
            "the lookalike must not contain whole lines of the original"
        );
    }

    /// §27's corpora have to be *unrelated*, or the false-positive suite that
    /// reads them is measuring a copy. A shared identifier is fine — these are
    /// sorting functions, they are called `sort` — a shared whole statement is
    /// not, because a statement is what a fragment is made of.
    #[test]
    fn every_corpus_is_unrelated_to_the_measurement_tree() {
        let host = TempDir::new("corpus-host");
        let measured: Vec<String> = synthetic_project(host.path(), 12)
            .iter()
            .flat_map(|name| {
                std::fs::read_to_string(host.child(name))
                    .unwrap()
                    .lines()
                    .map(str::trim)
                    .filter(|l| l.len() > 30)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            measured.len() > 100,
            "the host tree is too thin to test a corpus against: {}",
            measured.len()
        );

        for corpus in Corpus::ALL {
            let tmp = TempDir::new(&format!("corpus-{}", corpus.slug()));
            let written = corpus.write(tmp.path());
            assert!(!written.is_empty(), "{} wrote nothing", corpus.slug());
            for rel in &written {
                let body = std::fs::read_to_string(tmp.child(rel)).unwrap();
                assert!(
                    body.lines().count() >= 30,
                    "{} is a sketch, not a corpus: {} lines",
                    corpus.slug(),
                    body.lines().count()
                );
                assert!(
                    body.chars().any(|c| c.is_ascii_digit()),
                    "{} has no literals, so it cannot collide with a numeric site",
                    corpus.slug()
                );
                for line in body.lines().map(str::trim).filter(|l| l.len() > 30) {
                    assert!(
                        !measured.iter().any(|m| m == line),
                        "{} shares the statement {line:?} with the measurement tree",
                        corpus.slug()
                    );
                }
            }
        }
    }

    /// The generated corpus has to be *actually* self-similar, or the largest
    /// §27 case is not the largest case.
    ///
    /// Two things make a tree able to manufacture a confirmation out of volume:
    /// enough files that one keyed address has more candidate spans than the
    /// matcher holds on to, and the *same* literal-bearing statements in each of
    /// them. A fixture that merely looks like a code generator's output would
    /// satisfy neither, so this checks the property rather than the appearance —
    /// strip the three names the template substitutes and eighty bodies have to
    /// collapse to one.
    #[test]
    fn the_generated_corpus_is_one_template_restated_eighty_times() {
        let tmp = TempDir::new("corpus-generated");
        let written = Corpus::Generated.write(tmp.path());
        assert!(
            written.len() > 60,
            "§27's collision case wants a repository, not a package: {} file(s)",
            written.len()
        );
        let mut texts = Vec::new();
        for i in 0..SDK_MODULES {
            let head = SDK_HEAD[i / 10];
            let tail = SDK_TAIL[i % 10];
            let class = format!("{}{}", capitalize(head), capitalize(tail));
            let body =
                std::fs::read_to_string(tmp.child(&format!("src/generated/{head}_{tail}.js")))
                    .unwrap();
            texts.push(
                body.replace(&format!("{head}_{tail}"), "@NAME@")
                    .replace(&class, "@CLASS@")
                    .replace(&format!("/{head}/{tail}"), "@PATH@"),
            );
        }
        assert_eq!(
            texts.len(),
            SDK_MODULES,
            "the generator wrote {} modules, not {SDK_MODULES}: the fan-out and the \
             corpus have drifted apart",
            texts.len()
        );
        let first = &texts[0];
        assert!(
            first.contains("@NAME@") && first.contains("@CLASS@") && first.contains("@PATH@"),
            "the fold found none of the template's three substitutions to fold, so this \
             test is passing on a name it never replaced"
        );
        assert!(
            texts.iter().all(|t| t == first),
            "a generated module differs from the template's own text, so the corpus is not \
             one shape restated and §27's largest case is not being made"
        );
        assert!(
            first.lines().filter(|l| !l.trim().is_empty()).count() > 40,
            "the template is too thin to collide with much of anything"
        );
    }

    /// The three `color` fixtures must offer the same *numeric material*.
    ///
    /// Without this, a later cross-language result is ambiguous: if the Python
    /// fixture happened to have half as many literals as the JavaScript one, a
    /// detection gap would look like an adapter weakness when it is really a
    /// fixture accident. A token or two of difference is allowed, because the
    /// languages spell one conversion differently; a whole constant is not.
    #[test]
    fn all_three_languages_offer_the_same_literals() {
        let tmp = TempDir::new("parity");
        javascript_project(tmp.path());
        let js = significant_literals(&std::fs::read_to_string(tmp.child("src/color.js")).unwrap());
        typescript_project(tmp.path());
        let ts = significant_literals(&std::fs::read_to_string(tmp.child("src/color.ts")).unwrap());
        python_project(tmp.path());
        let py = significant_literals(&std::fs::read_to_string(tmp.child("src/color.py")).unwrap());

        assert!(
            !js.is_empty(),
            "the JavaScript fixture has no literals to embed"
        );
        assert_eq!(
            js, ts,
            "the TypeScript fixture drifted from the JavaScript one"
        );
        // Spelling, not substance: `x.toString(16)` carries a `16` that Python's
        // `format(v, "02x")` writes as `"02"` instead, so the sets differ by
        // exactly those two tokens and nothing else.
        let js_only: Vec<&String> = js.iter().filter(|v| !py.contains(*v)).collect();
        let py_only: Vec<&String> = py.iter().filter(|v| !js.contains(*v)).collect();
        assert!(
            js_only.len() + py_only.len() <= 2,
            "the Python fixture carries different numeric material than the JavaScript one: \
             only-in-js {js_only:?}, only-in-py {py_only:?}"
        );
        assert!(
            py.len() >= js.len() - 2,
            "the Python fixture is too sparse to compare: {:?} vs {:?}",
            py,
            js
        );
    }

    /// Numeric tokens worth watermarking: at least two digits or a fraction, so
    /// loop counters and `0`/`1` do not dominate the comparison.
    fn significant_literals(text: &str) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        let mut run = String::new();
        for ch in text.chars().chain(std::iter::once(' ')) {
            if ch.is_ascii_digit() || ch == '.' {
                run.push(ch);
                continue;
            }
            finish_run(&mut run, &mut out);
        }
        out
    }

    fn finish_run(run: &mut String, out: &mut std::collections::BTreeSet<String>) {
        let raw = std::mem::take(run);
        let trimmed = raw.trim_matches('.');
        if trimmed.len() < 2 {
            return;
        }
        if trimmed.parse::<f64>().is_ok() {
            out.insert(trimmed.to_string());
        }
    }

    /// The measurement suites compare one run of this tree with another, so the
    /// tree has to be one fixed thing: same bytes for the same module count, on
    /// this run and the next.
    #[test]
    fn the_synthetic_tree_is_the_same_bytes_every_time() {
        let a = TempDir::new("synthetic-a");
        let b = TempDir::new("synthetic-b");
        let names = synthetic_project(a.path(), 12);
        assert_eq!(names.len(), 12);
        synthetic_project(b.path(), 12);
        let mut totals = 0usize;
        for name in &names {
            let x = std::fs::read(a.child(name)).unwrap();
            let y = std::fs::read(b.child(name)).unwrap();
            assert_eq!(x, y, "{name} differs between two runs of the generator");
            totals += x.len();
        }
        // Big enough that 10% of the project is two files, and every file has
        // literals in it: an empty module would quietly shrink every denominator.
        assert!(totals > 8_000, "the synthetic tree is too small to measure: {totals} bytes");
        for name in &names {
            let body = std::fs::read_to_string(a.child(name)).unwrap();
            assert!(
                body.lines().any(|l| l.chars().any(|c| c.is_ascii_digit())),
                "{name} has no numeric material for a site to sit on"
            );
        }
        // Modules must not be copies of one another, or a partial copy of the
        // tree would be a copy of one module several times over.
        let mut first_lines = std::collections::BTreeSet::new();
        for name in &names {
            let body = std::fs::read_to_string(a.child(name)).unwrap();
            let fingerprint: String = body.chars().filter(|c| c.is_ascii_digit()).collect();
            assert!(first_lines.insert(fingerprint), "{name} repeats another module's constants");
        }
    }

    /// `Transform`'s rules match text, not intent, so the tree they are applied
    /// to has to contain that text. Without this test a transform that quietly
    /// stopped finding anything would report "the attack changed nothing" instead
    /// of "the fixture moved", which is the difference between a measurement and
    /// a tautology.
    #[test]
    fn the_synthetic_tree_holds_every_transform_anchor() {
        let tmp = TempDir::new("synthetic-anchors");
        let names = synthetic_project(tmp.path(), 12);
        let all: String = names
            .iter()
            .map(|n| std::fs::read_to_string(tmp.child(n)).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        for anchor in [
            "class Bucket_",
            "function duty_",
            "value * rate * 0.25",
            "sum += this.scale(",
            "return Math.round(sum * 100) / 100;",
            "let sum = 0;",
            "module.exports = ",
            "duty_0_0",
        ] {
            assert!(
                all.contains(anchor),
                "the generated tree no longer contains {anchor:?}, and a transform that \
                 matches it would measure nothing"
            );
        }
    }

    /// How self-similar the corpus is, which is the quantity the coincidence
    /// bound reads.
    ///
    /// A location id is a content address, so every statement that appears in
    /// twelve modules puts twelve candidate spans at *one* site's address, and a
    /// 4-bit tag then covers them all. One template repeated twelve times — which
    /// is what this generator used to emit — made every partial copy inconclusive,
    /// and the table looked like a weakness of the protocol when it was a property
    /// of the fixture. The probe column of the §24 table is the number that
    /// actually matters; this is the cheap guard that says why it moved.
    #[test]
    fn the_synthetic_tree_is_mostly_distinct_statements() {
        let tmp = TempDir::new("synthetic-diverse");
        let names = synthetic_project(tmp.path(), 12);
        let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for name in &names {
            let body = std::fs::read_to_string(tmp.child(name)).unwrap();
            for line in body.lines() {
                let trimmed = line.trim();
                // Only the lines a site can sit on: a statement with a literal in
                // it. `}` repeats by the dozen and addresses none of anything.
                if trimmed.len() < 12 || !trimmed.chars().any(|c| c.is_ascii_digit()) {
                    continue;
                }
                *counts.entry(trimmed.to_string()).or_default() += 1;
            }
        }
        let total: usize = counts.values().sum();
        let unique = counts.values().filter(|&&n| n == 1).count();
        let worst = counts
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(line, n)| (line.clone(), *n))
            .unwrap();
        assert!(
            !counts.is_empty(),
            "no literal-bearing statement of any length in the tree"
        );
        assert!(
            unique * 4 >= total * 3,
            "only {unique} of {total} literal-bearing statements appear once: a corpus this \
             repetitive measures the generator, not the protocol (most repeated: {worst:?})"
        );
        assert!(
            worst.1 <= names.len(),
            "a statement repeated {} times is in more modules than there are — the generator \
             emitted one template rather than a corpus: {worst:?}",
            worst.1
        );
    }
}
