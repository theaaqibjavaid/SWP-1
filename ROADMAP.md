# Roadmap

Where SWP-1 is going, and — more usefully — what it is not going to become. The
rule this page follows is the rule the documentation follows: an item here is work
somebody intends to do, not an aspiration dressed as a feature. A released
capability is described in [README.md](README.md) and
[CHANGELOG.md](CHANGELOG.md), not here.

Protocol version v1 and report schema `SWP-1-report-v1` are both frozen: a
planned change that would make an old report unreadable, or a protected tree
unverifiable by a newer build, is marked as such below, because that kind of change
needs a version bump and a migration rather than a checkbox.

## Now

Work in the current cycle.

| item | why it matters | state |
| --- | --- | --- |
| Sealed-at-rest secrets on Linux and macOS | DPAPI is Windows-only, so a non-Windows store holds the root secret in a `0600` file. The guarantee differs by platform and the docs say so; the fix is a platform-appropriate key store | open, and the most consequential item here |
| Second and third platform secret backends | the same boundary from the other side: a store that can be moved between machines without exporting a plaintext secret | design |
| Adapter: C and C++ | the highest-asked language pair, and the hardest canonicalization here because of the preprocessor | scoping |
| Adapter: Java | real demand, and a grammar with clean literal spans | scoping |
| `swp diff` between two releases of one project | "what did protecting this release change, and did any site move" is asked in every adoption conversation | design |
| Windows ARM64 release artifact | the published matrix is `windows-x64`, `linux-x64`, `macos-x64` and `macos-aarch64`, and CI's lint and test jobs run on `macos-latest` — which is Apple Silicon — so an ARM Mac is built and exercised by configuration. Windows on ARM has no runner here at all, and it is the DPAPI sealing path that has never been executed on it | needs a runner, or a report from somebody who built there |

## Next

Scheduled after the current cycle, in no committed order.

* **Go and Rust adapters.** Rust's macro-shaped literals and Go's short variable
  declarations both need care, and neither is a port of an existing adapter.
* **A `--min-sites` gate for CI.** `swp protect --sites 12` refusing 21 candidates
  is normal; deciding when "normal" is "too few for this release" is a project
  policy that `verify` could enforce.
* **Site-count and bit-budget modelling.** The coincidence bound is honest and the
  ladder is stated, but the guidance for "how many sites does a tree of this size
  need" is currently a paragraph of judgement rather than a table.
* **Report signing.** A report is a document about a scan; today it is produced and
  stored, and there is no signature over it by the scanning party. Cheap to add,
  useful for the use case the tool exists for.
* **Structured output for `inspect`.** Text-first, `--format json` where it counts;
  a few views still have no JSON form.
* **Store layout v2** — the private store keeps plans, manifests and reports in one
  directory tree forever; compaction and export/import for archives of old releases
  is real work users ask about.

## Later

Worth doing, no cycle attached.

* Additional dialect families for the three shipped languages, driven by the
  corpora in the false-positive suite rather than by guesswork.
* A plugin surface for adapters, so a language can live outside this repository —
  attractive, and it has to be designed around the fact that a bad adapter can
  make a false accusation.
* Monorepo ergonomics: one store covering several languages and sub-roots, with
  per-package `targets`.
* `verify --baseline` against a stored report, so CI prints a delta rather than a
  verdict.
* Translations of the user-facing documentation.

## Not planned

These are decisions, and they are here so that a "why don't you just…" does not
have to be asked again. Each one is a claim the product would have to make in
order to offer the feature, and the claims are refused in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and
[docs/FAQ.md](docs/FAQ.md).

* **Detection after reimplementation.** Keying on literals cannot see code that
  shares no literals. Any feature that claimed otherwise would be a stronger claim
  than the protocol can support.
* **A cloud service, telemetry, or an update check.** There is no network code path
  in `swp`, which is why a scan can be run on a machine holding source that must
  not leave it. Adding phone-home would break the reason a large share of users
  have for the tool.
* **Making the watermark secret.** `swp inspect fragments` lists every site in a
  tree you control, and will keep doing so. The watermark is unobtrusive, not
  hidden, and obfuscating it would buy nothing against a determined remover while
  costing the auditability that makes the evidence usable.
* **A legal opinion.** A report is technical provenance evidence. SWP-1 will not
  advertise itself as proof of authorship or as a substitute for counsel, in the
  documentation or in a feature.
* **Enforcement hooks that block a build.** `verify` exits with a code and CI can
  treat it as fatal — that is the design. A mode that quarantines, rewrites, or
  refuses to let you compile your own source belongs to a different kind of tool.
* **Signature or crypto changes.** Hashes, MACs, Ed25519 and the OS CSPRNG come from
  the crates already in the dependency list. This project does not design
  primitives, and it does not swap them for novelty.

## How an item moves

A roadmap item is proposed as an issue, argued in the open, and taken up either by
a maintainer or by a contributor whose pull request does it. Sponsorship
prioritises the queue and does not skip it — see
[SPONSORS.md](SPONSORS.md#what-sponsorship-does-not-buy). A change to the protocol,
the report schema, the evidence ladder, the CLI surface or the dependency list is
discussed before it is written, for the reason in
[CONTRIBUTING.md](CONTRIBUTING.md).
