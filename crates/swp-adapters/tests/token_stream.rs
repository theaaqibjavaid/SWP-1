//! The contract between an adapter and the core.
//!
//! Everything above `swp-adapters` trusts two things about a token stream: that a
//! token's `text` is the source at its `span`, and that spans are ordered and
//! disjoint. The canonicalizer slices by radius on that assumption, the embedding
//! splices edits by it, and the scanner recomputes location ids from it. Nothing
//! in a single adapter's own unit tests proves it holds for *every* input an
//! adapter can reach, so this suite states it as a property and runs it over a
//! corpus that covers the awkward corners: Python's composite string nodes,
//! template literals and a regex, an f-string, a TypeScript literal type, an
//! `async with` block, CRLF line endings, non-ASCII including emoji, and files
//! whose language no parser here claims at all.
//!
//! The second group of tests is the other half of the promise: the stream must be
//! stable under the transformations the protocol claims preserve semantics. L1 is
//! formatting-insensitive, L2 is rename-insensitive, L3 respells literals without
//! moving the structure — and each level must still *notice* a change it is not
//! supposed to tolerate, because a canonicalizer that collapses everything is
//! indistinguishable from one that is broken.

use std::path::Path;

use swp_adapters::{Analysis, GenericAdapter, Registry};
use swp_core::canon::{CanonLevel, TokKind};
use swp_core::limits::Limits;
use swp_core::site::TagWidth;

/// One entry in the corpus: a path, and the source it names.
struct Source {
    path: &'static str,
    body: &'static str,
}

/// Files an AST adapter should claim.
const PARSED: &[Source] = &[
    Source {
        path: "src/http.js",
        body: concat!(
            "import express from \"express\";\n",
            "const DEFAULTS = { timeout: 30000, retries: 4, host: \"localhost\" };\n",
            "// A comment the stream must not carry.\n",
            "/* Neither may this one. */\n",
            "export function serve(port = 8080) {\n",
            "  const app = express();\n",
            "  if (port > 1024) {\n",
            "    app.listen(port, () => console.log(\"up on \" + port));\n",
            "  }\n",
            "  return app;\n",
            "}\n",
        ),
    },
    Source {
        path: "src/template.js",
        body: concat!(
            "const label = `row ${index + 1} of ${total}`;\n",
            "const pattern = /^ab+c$/i;\n",
            "const nested = \"a \\\"quoted\\\" inner\";\n",
            "const unicode = \"naïve café — 日本語 🎯\";\n",
            "export const size = 0x1F400;\n",
        ),
    },
    Source {
        path: "src/typed.ts",
        body: concat!(
            "interface Config {\n",
            "  timeout: 30000;\n",
            "  retries: number;\n",
            "}\n",
            "export function make<T extends string>(name: T, n = 12): T | null {\n",
            "  const table: Record<string, number> = { alpha: 1, beta: 2 };\n",
            "  return name in table ? null : (name as unknown as T);\n",
            "}\n",
        ),
    },
    Source {
        path: "src/color.py",
        body: concat!(
            "\"\"\"Module documentation, which is a statement, not a value.\"\"\"\n",
            "import math\n",
            "\n",
            "LIMITS = {\"max\": 255, \"min\": 0}\n",
            "\n",
            "def clamp(value: int, bound: int = 255) -> int:\n",
            "    \"\"\"Explain the helper.\"\"\"\n",
            "    if value > bound:\n",
            "        return bound\n",
            "    return int(math.fabs(value))\n",
            "\n",
            "class Palette:\n",
            "    def __init__(self, name):\n",
            "        self.name = name\n",
            "        self.parts = [f\"{name}-{i}\" for i in range(3)]\n",
            "\n",
            "    def key(self) -> str:\n",
            "        return \"#\" + self.name + str(16)\n",
            "\n",
            "async def fetch(session, url=\"https://example.test/a?x=1&y=2\"):\n",
            "    async with session.get(url) as response:\n",
            "        data = await response.json()\n",
            "    return data or {}\n",
        ),
    },
    Source {
        path: "src/windows.js",
        body: "const a = 1;\r\n// comment\r\nfunction b() {\r\n  return \"text\";\r\n}\r\n",
    },
];

/// Files with no parser here: every one of them must land on the fallback.
const UNPARSED: &[Source] = &[
    Source {
        path: "src/main.rs",
        body: "fn main() {\n    let v = vec![1, 2, 3];\n    println!(\"{v:?}\");\n}\n",
    },
    Source {
        path: "pkg/app.go",
        body: "package main\n\nfunc main() {\n\tcount := 30000\n\tfmt.Println(count)\n}\n",
    },
    Source {
        path: "web/index.html",
        body: "<!doctype html>\n<html lang=\"en\"><body><p>255</p></body></html>\n",
    },
    Source {
        path: "Makefile",
        body: "all:\n\tgcc -O2 main.c -o main\n",
    },
];

fn analyze(path: &str, body: &str) -> Analysis {
    let registry = Registry::standard();
    registry
        .analyze(Path::new(path), body, &Limits::default())
        .unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The invariant the whole protocol rests on.
fn assert_stream_is_sound(body: &str, a: &Analysis, label: &str) {
    let mut previous_end = 0u32;
    let mut first = true;
    for token in &a.tokens {
        let span = token.span;
        assert!(
            span.end >= span.start,
            "{label}: span {:?} is reversed",
            span
        );
        assert!(
            !span.is_empty(),
            "{label}: {:?} produced an empty token",
            token.kind
        );
        assert!(
            span.start >= previous_end,
            "{label}: token {span:?} ({:?}) overlaps or precedes the one before it at {previous_end}",
            token.text
        );
        assert!(
            (span.end as usize) <= body.len(),
            "{label}: token span {span:?} runs past the end of the file"
        );
        // The one assertion the splicer cannot survive without.
        assert_eq!(
            &body[span.start as usize..span.end as usize],
            token.text,
            "{label}: token text is not the source at its span"
        );
        // A token must never start or end inside a UTF-8 sequence: the span is
        // used to slice `&str`, and a mid-code-point slice panics.
        assert!(
            body.is_char_boundary(span.start as usize) && body.is_char_boundary(span.end as usize),
            "{label}: token span {span:?} splits a code point"
        );
        if first {
            let leading = body[..span.start as usize].trim_start();
            assert!(
                leading.is_empty()
                    || leading.starts_with("//")
                    || leading.starts_with("/*")
                    || leading.starts_with("#"),
                "{label}: the stream does not begin at the first token of code"
            );
            first = false;
        }
        previous_end = span.end;
    }
    assert!(!a.tokens.is_empty(), "{label}: no tokens at all");
    // Comments are dropped on purpose, so the only thing allowed after the last
    // token is whitespace or a comment.
    let tail = body[previous_end as usize..].trim_start();
    assert!(
        tail.is_empty()
            || tail.starts_with("//")
            || tail.starts_with("/*")
            || tail.starts_with("#"),
        "{label}: code survives after the last token: {tail:?}"
    );
}

#[test]
fn every_adapter_produces_a_sound_token_stream() {
    for source in PARSED.iter().chain(UNPARSED) {
        let a = analyze(source.path, source.body);
        assert_stream_is_sound(source.body, &a, source.path);
    }
}

#[test]
fn a_parsed_file_carries_no_grammar_errors() {
    // Not a soundness claim but a corpus claim: if these fixtures stop parsing,
    // the tests below silently compare error recoveries.
    for source in PARSED {
        let a = analyze(source.path, source.body);
        assert_eq!(a.parse_errors, 0, "{} did not parse cleanly", source.path);
        assert_eq!(a.capabilities, swp_adapters::Capabilities::AST);
    }
}

#[test]
fn comments_and_their_contents_never_reach_the_stream() {
    let body = "const a = 1;\n// const b = 2;\n/* const c = 3; */\nconst d = 4;\n";
    for path in ["c.js", "c.py"] {
        let a = analyze(path, body);
        for token in &a.tokens {
            assert!(
                !token.text.contains("const b") && !token.text.contains("const c"),
                "{path}: comment text leaked into the stream as {:?}",
                token.text
            );
        }
    }
}

#[test]
fn each_level_is_insensitive_to_what_it_claims_and_no_more() {
    let original = "function describe(limit) {\n  const rows = 128000;\n  if (rows > limit) {\n    return \"over \" + limit;\n  }\n  return 0;\n}\n";
    // Reindented, comments added, braces moved, semicolon kept where it matters.
    let reformatted = "// describes a limit\nfunction describe(limit) {\n\n    const rows = 128000;   /* inline */\n    if (rows > limit) {\n        return \"over \" + limit;\n    }\n\n    return 0;\n}\n";
    // Same code, every local renamed.
    let renamed = "function describe(cap) {\n  const rows2 = 128000;\n  if (rows2 > cap) {\n    return \"over \" + cap;\n  }\n  return 0;\n}\n";
    // Same values, different spellings.
    let respelled = "function describe(limit) {\n  const rows = 0x1F400;\n  if (rows > limit) {\n    return 'over ' + limit;\n  }\n  return 0;\n}\n";

    let registry = Registry::standard();
    let adapter = registry.for_language("javascript");
    let canon = |body: &str, level: CanonLevel| {
        let a = adapter.analyze(body, &Limits::default()).unwrap();
        adapter
            .canonicalize(&a.tokens, level, None)
            .as_str()
            .to_string()
    };

    // L1: formatting changes nothing.
    assert_eq!(
        canon(original, CanonLevel::L1),
        canon(reformatted, CanonLevel::L1)
    );
    // ...and it does see a real change.
    assert_ne!(
        canon(original, CanonLevel::L1),
        canon(renamed, CanonLevel::L1)
    );
    // L2: neither a rename nor a reformat moves it.
    assert_eq!(
        canon(original, CanonLevel::L2),
        canon(renamed, CanonLevel::L2)
    );
    assert_eq!(
        canon(original, CanonLevel::L2),
        canon(reformatted, CanonLevel::L2)
    );
    // L3: a respelled literal is the same structure...
    assert_eq!(
        canon(original, CanonLevel::L3),
        canon(respelled, CanonLevel::L3)
    );
    // ...and only at L3. L1 and L2 keep spellings, because a scanner that read a
    // rewritten literal as the original would not be able to tell a watermark
    // from a coincidence.
    assert_ne!(
        canon(original, CanonLevel::L1),
        canon(respelled, CanonLevel::L1)
    );
    assert_ne!(
        canon(original, CanonLevel::L2),
        canon(respelled, CanonLevel::L2)
    );
    assert_ne!(
        canon(original, CanonLevel::L2),
        canon(original, CanonLevel::L3)
    );
}

#[test]
fn the_levels_are_strictest_first_on_a_python_file_too() {
    // The same claims in the other grammar, because a JS-only property test would
    // miss a language whose strings are composite nodes.
    let original = "def scale(value, factor):\n    limit = 255\n    if value > limit:\n        return str(limit) + \"!\"\n    return value * factor\n";
    let renamed = "def scale(amount, mult):\n    limit2 = 255\n    if amount > limit2:\n        return str(limit2) + \"!\"\n    return amount * mult\n";
    let respelled = "def scale(value, factor):\n    limit = 0xFF\n    if value > limit:\n        return str(limit) + '!'\n    return value * factor\n";

    let registry = Registry::standard();
    let adapter = registry.for_language("python");
    let canon = |body: &str, level: CanonLevel| {
        let a = adapter.analyze(body, &Limits::default()).unwrap();
        adapter
            .canonicalize(&a.tokens, level, None)
            .as_str()
            .to_string()
    };
    assert_eq!(
        canon(original, CanonLevel::L2),
        canon(renamed, CanonLevel::L2)
    );
    assert_eq!(
        canon(original, CanonLevel::L3),
        canon(respelled, CanonLevel::L3)
    );
    assert_ne!(
        canon(original, CanonLevel::L1),
        canon(respelled, CanonLevel::L1)
    );
    assert_ne!(
        canon(original, CanonLevel::L2),
        canon(original, CanonLevel::L3)
    );
}

#[test]
fn every_site_that_carries_a_width_renders_and_decodes_back() {
    // The claim `swp embed` makes is narrow: a *usable* site — one with a family
    // at the width the release chose — can carry every code at that width, and the
    // rendering means the same literal. Sites are recorded per position, not per
    // width, so a short string that has no family at 4 bits is simply not a
    // location at 4 bits and may still be one at 2.
    for width in [TagWidth::DEFAULT, TagWidth::new(2).unwrap()] {
        let mut tested = 0usize;
        for source in PARSED.iter().chain(UNPARSED) {
            let registry = Registry::standard();
            let adapter = registry
                .for_path(Path::new(source.path))
                .unwrap_or(&GenericAdapter);
            let a = adapter.analyze(source.body, &Limits::default()).unwrap();
            let usable = a.usable_sites(width, adapter.dialect());
            tested += usable.len();
            for (site, families) in usable {
                let text = site.source(source.body);
                assert!(
                    !text.is_empty(),
                    "{}: a site with no spelling cannot carry a tag",
                    source.path
                );
                for family in families {
                    for code in [0, 1, width.modulus() as u32 / 2, width.modulus() as u32 - 1] {
                        let rendering = site
                            .render(family, code, width, adapter.dialect())
                            .unwrap_or_else(|e| {
                                panic!(
                                    "{}: {} cannot carry {} at code {code}: {}",
                                    source.path,
                                    text,
                                    family.as_str(),
                                    e.message()
                                )
                            });
                        let decoded =
                            adapter
                                .extract(&rendering, family, width)
                                .unwrap_or_else(|| {
                                    panic!(
                                        "{}: {} did not decode as a {} form",
                                        source.path,
                                        rendering,
                                        family.as_str()
                                    )
                                });
                        assert_eq!(decoded.code(), code, "{}: wrong code back out", rendering);
                        assert_eq!(
                            decoded.canonical_value(),
                            expected_value(site),
                            "{}: {:?} of {} changed its value to {}",
                            source.path,
                            family,
                            text,
                            decoded.canonical_value()
                        );
                    }
                }
            }
        }
        // The corpus is small and most of its literals are small — `4`, `12`,
        // `255`, `"#"` — and a 4-bit tag needs a value big enough to split or a
        // string long enough to escape, so the count here is what honesty about
        // capacity costs. A file that offers nothing is not a failure; a corpus
        // that tests nothing is.
        assert!(
            tested >= 12,
            "the corpus rendered only {tested} sites at {} bits",
            width.bits()
        );
    }
}

fn expected_value(site: &swp_adapters::CandidateSite) -> String {
    match &site.value {
        swp_adapters::SiteValue::Integer(v) => v.to_string(),
        swp_adapters::SiteValue::Text(text) => text.inner.clone(),
    }
}

#[test]
fn a_sites_radii_hold_the_site_and_agree_with_the_query_api() {
    // `swp embed` keys a location id on the radius, and `swp scan` recomputes it
    // from a copy by asking the analysis for the radius around an offset; the two
    // answers must be the same value, or the id is unfindable rather than weak.
    // Statement and scope are the two innermost enclosing nodes of each kind, so
    // neither contains the other in general — a scope can sit inside a statement,
    // as an arrow function does inside the expression statement that calls it.
    for source in PARSED.iter().chain(UNPARSED) {
        let a = analyze(source.path, source.body);
        assert!(
            a.file.end >= a.file.start && a.file.len() == source.body.len(),
            "{}: the file radius is not the file",
            source.path
        );
        for site in &a.sites {
            for (kind, radius) in [
                ("statement", site.statement),
                ("scope", site.scope),
                ("file", a.file),
            ] {
                assert!(
                    radius.contains(site.span.start)
                        && radius.contains(site.span.end.saturating_sub(1)),
                    "{}: site at {:?} is outside its {kind} radius {:?}",
                    source.path,
                    site.span,
                    radius
                );
                assert!(
                    !a.tokens_in(radius).is_empty(),
                    "{}: the {kind} radius selects no tokens",
                    source.path
                );
            }
            assert_eq!(
                a.statement_span_at(site.span.start),
                site.statement,
                "{}: the site's statement radius is not what an offset lookup returns",
                source.path
            );
            assert_eq!(
                a.scope_span_at(site.span.start),
                site.scope,
                "{}: the site's scope radius is not what an offset lookup returns",
                source.path
            );
        }
    }
}

#[test]
fn analyzing_the_same_file_twice_gives_the_same_answer() {
    // Location ids are digests of canonical text, so a stream that wobbled
    // between two runs of the same binary would make a release unfindable.
    for source in PARSED.iter().chain(UNPARSED) {
        let a = analyze(source.path, source.body);
        let b = analyze(source.path, source.body);
        assert_eq!(
            a.tokens, b.tokens,
            "{}: token stream is not deterministic",
            source.path
        );
        assert_eq!(
            a.sites, b.sites,
            "{}: sites are not deterministic",
            source.path
        );
        assert_eq!(a.statement_spans, b.statement_spans);
        assert_eq!(a.scope_spans, b.scope_spans);
    }
}

#[test]
fn an_unsupported_language_lands_on_the_fallback_and_says_so() {
    let registry = Registry::standard();
    for source in UNPARSED {
        assert!(
            registry.for_path(Path::new(source.path)).is_none(),
            "{} was claimed by a parser, which contradicts the corpus",
            source.path
        );
        let a = analyze(source.path, source.body);
        assert_eq!(
            a.capabilities.kind,
            swp_adapters::AdapterKind::Lexical,
            "{}: analyzed as if a parser covered it",
            source.path
        );
        assert_eq!(a.language, "generic");
        assert!(
            !a.capabilities.reparse,
            "the fallback claimed it could re-parse its own output"
        );
        assert_eq!(
            a.capabilities.evidence,
            swp_adapters::EvidenceStrength::Token,
            "{}: the report would promise AST evidence for a lexical match",
            source.path
        );
    }
    // And the set of what *is* supported is enumerable, because that is the
    // sentence the CLI has to tell an operator whose tree is in another language.
    assert_eq!(
        registry.parsed_languages(),
        ["javascript", "typescript", "python"]
    );
}

#[test]
fn the_fallback_refuses_what_it_cannot_see() {
    // A lexical scanner cannot tell `100` after a colon from a JSON member value,
    // so the positions an AST adapter reasons about are refused here by rule.
    let body = concat!(
        "{\n",
        "  \"timeout\": 30000,\n",
        "  \"retries\": 4\n",
        "}\n",
        "const ms = 1200 ms;\n",
        "label:\n",
        "  x = 1\n",
        "const css = \"2px\";\n",
    );
    let a = analyze("config.json5", body);
    let sites: Vec<&str> = a.sites.iter().map(|s| s.source(body)).collect();
    assert!(
        sites.iter().all(|s| s.chars().all(|c| c.is_ascii_digit())),
        "{sites:?}: the fallback should only ever offer plain numbers"
    );
    let refused = a
        .refusals
        .iter()
        .filter(|r| r.kind == swp_adapters::RefusalKind::UnsafeContext)
        .count();
    assert!(refused >= 3, "hazards were not reported: {refused}");
}

#[test]
fn a_site_worth_having_survives_the_edit_that_would_move_it() {
    // The property `validate` enforces, stated from the outside: embedding a tag
    // into a real statement changes the file, but not the canonical text of the
    // radius around it once the site itself is hidden.
    let body =
        "function clamp(value) {\n  if (value > 255) {\n    return 255;\n  }\n  return value;\n}\n";
    let registry = Registry::standard();
    let adapter = registry.for_language("javascript");
    let a = adapter.analyze(body, &Limits::default()).unwrap();
    let width = TagWidth::DEFAULT;
    let site = a
        .site_at_offset(body.find("255").unwrap() as u32)
        .expect("255 is a site");
    let rendering = site
        .render(
            site.families(width, adapter.dialect())[0],
            7,
            width,
            adapter.dialect(),
        )
        .unwrap();
    let after = format!(
        "{}{rendering}{}",
        &body[..site.span.start as usize],
        &body[site.span.end as usize..]
    );
    let updated = adapter.analyze(&after, &Limits::default()).unwrap();
    let rendered_span =
        swp_core::canon::ByteSpan::new(site.span.start, site.span.start + rendering.len() as u32);
    let radius = updated.statement_span_at(rendered_span.start);
    for level in [CanonLevel::L1, CanonLevel::L2, CanonLevel::L3] {
        let before = adapter.canonicalize(a.tokens_in(site.statement), level, Some(site.span));
        let after_text =
            adapter.canonicalize(updated.tokens_in(radius), level, Some(rendered_span));
        assert_eq!(
            before.as_str(),
            after_text.as_str(),
            "{level:?} radius text moved when a site was watermarked: {} vs {}",
            before.as_str(),
            after_text.as_str()
        );
    }
    // And the stream outside the touched radius is untouched, which is what a
    // detector matching a *partial* copy depends on.
    let outside = |a: &Analysis, radius: swp_core::canon::ByteSpan| -> Vec<TokKind> {
        a.tokens
            .iter()
            .filter(|t| !radius.contains(t.span.start))
            .map(|t| t.kind)
            .collect()
    };
    assert_eq!(
        outside(&a, site.statement),
        outside(&updated, radius),
        "the stream outside the edited statement moved"
    );
}

/// `swp_core::radius::radius_digests` is the single definition of a site's four
/// address keys: `swp-embedding` writes them into a manifest and
/// `swp-detection` recomputes them from a candidate. It must agree, token for
/// token, with the radius selection the adapters' own embedding validation uses
/// — otherwise an embedding would prove one text and register another, and every
/// copy of a protected file would read as a tamper.
#[test]
fn the_radius_keys_use_the_same_text_the_adapters_validate() {
    use swp_core::radius::level_for;
    use swp_core::site::RadiusKind;

    let registry = Registry::standard();
    let mut checked = 0;
    for source in PARSED.iter().chain(UNPARSED.iter()) {
        let a = analyze(source.path, source.body);
        // By the language the analysis reported, which is how a detector picks
        // an adapter for a candidate whose extension it has never seen.
        let adapter = registry.for_language(&a.language);
        for site in &a.sites {
            let digests =
                swp_core::radius_digests(&a.tokens, site.statement, site.scope, site.span);
            for (i, kind) in RadiusKind::all().iter().enumerate() {
                let radius = site.radius(*kind);
                let text =
                    adapter.canonicalize(a.tokens_in(radius), level_for(*kind), Some(site.span));
                assert_eq!(
                    digests[i],
                    text.digest(),
                    "{}: the {} key differs between the two selections",
                    source.path,
                    kind.as_str()
                );
                checked += 1;
            }
            // Two slots can legitimately hold the same digest: where a site's
            // statement and scope spans are the same code, and where a radius
            // has no local name or odd literal spelling left in it once the site
            // is hidden, L1 and L3 are the same text. The four *keys* stay
            // distinct because the radius is inside the id derivation, which
            // `swp-manifest`'s keys tests pin.
        }
    }
    assert!(checked >= 32, "only {checked} keys compared");
}
