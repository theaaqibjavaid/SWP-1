# SWP-1 — Universal Source Provenance Watermark System

## MASTER DEVELOPMENT TASK

You are building a **standalone, reusable, language-independent source-code provenance watermarking system**.

Project name:

**SWP-1 — Source Watermark Protocol v1**

The system must be designed as an independent product that can be used with **any compatible software project**, regardless of who created the project or what application it belongs to.

Do not design this around:

- Code Guardian
- Mausam
- Nursify
- a specific Git repository
- a specific organization
- a specific programming language
- GitHub
- npm
- a particular framework

Those may eventually use SWP-1, but SWP-1 itself must remain independent.

---

# 1. PRIMARY OBJECTIVE

Build a system that allows a developer to:

1. Initialize SWP-1 for any project.
2. Generate a unique cryptographic provenance identity.
3. Embed a hidden/distributed watermark into source code.
4. Preserve normal application behavior.
5. Keep the root secret outside the source code.
6. Later scan another source project.
7. Detect evidence that the protected source was reused.
8. Detect partial reuse.
9. Detect reuse after ordinary refactoring.
10. Produce an explainable provenance report.
11. Preserve evidence for each protected release.
12. Work through a language-adapter architecture rather than being tied to one language.

The purpose is **provenance identification**, not DRM.

SWP-1 must NOT:

- block software execution
- phone home during normal application execution
- require a network connection to run protected applications
- secretly collect information from end users
- transmit source code to a remote server by default
- claim to provide legal ownership proof
- claim that a match mathematically proves copying

The tool provides **technical provenance evidence**.

---

# 2. FUNDAMENTAL ARCHITECTURE

The architecture must have two distinct layers:

```text
                    SWP-1
                       |
        ┌──────────────┴──────────────┐
        │                             │
 Universal Core                 Language Adapters
        │                             │
        │                    ┌────────┼────────┐
        │                    │        │        │
        │                   JS      Python    Rust
        │                    │        │        │
        └────────────────────┴────────┴────────┘
                       |
                 Provenance Engine
                       |
              CLI / API / Reports
```

The **protocol and cryptographic model must be language-independent**.

Language adapters are responsible only for source analysis and safe source-level embedding/detection.

---

# 3. DO NOT CONFUSE "UNIVERSAL" WITH "EVERYTHING AT ONCE"

The protocol must be universal.

The implementation must have an extensible language adapter system.

Do NOT make fake claims such as:

> "Works with every programming language."

Instead define:

```text
Universal protocol
+
supported language adapters
+
fallback detection mechanisms
```

If a language has no AST adapter, SWP-1 may still support weaker detection mechanisms where technically appropriate, but must clearly report the limitation.

---

# 4. REQUIRED COMPONENTS

Build the following major components:

```text
swp-core
swp-crypto
swp-identity
swp-manifest
swp-embedding
swp-detection
swp-evidence
swp-adapters
swp-cli
swp-test-suite
swp-documentation
```

These may be packages/modules rather than separate repositories.

Choose the implementation language based on what is technically appropriate for building a cross-language developer tool.

The final architecture must make future language adapters straightforward.

---

# 5. SWP-1 PROTOCOL

Define a formal protocol specification:

```text
SWP-1
```

Create:

```text
docs/SWP-1-SPEC.md
```

The specification must define:

- protocol version
- project identity
- watermark identity
- secret derivation
- fragment derivation
- embedding model
- canonicalization
- detection
- evidence model
- manifest
- release records
- versioning
- limitations
- security assumptions

Do not implement the protocol merely as undocumented code.

---

# 6. CRYPTOGRAPHIC IDENTITY

Use a cryptographically secure random generator to create the root secret.

Conceptually:

```text
root_secret = CSPRNG(256 bits)
```

The root secret must NEVER be embedded in:

- source code
- generated source
- public manifests
- compiled output where avoidable
- CLI output
- logs
- documentation
- test snapshots

The root secret belongs to the project owner.

---

# 7. PROJECT-SPECIFIC DERIVATION

Derive project-specific material from the root secret.

Conceptually:

```text
project_key =
    HMAC-SHA256(
        root_secret,
        "SWP-1/project/" + project_id
    )
```

Do not copy this exact formula blindly if your cryptographic review identifies a better standard construction, but maintain the same security properties.

Every derivation must have:

- domain separation
- protocol versioning
- deterministic derivation where appropriate

For example:

```text
SWP-1/project/
SWP-1/location/
SWP-1/release/
SWP-1/evidence/
```

Never reuse the same cryptographic purpose across domains.

---

# 8. WATERMARK FRAGMENTS

A watermark must not be a single hidden value.

Generate multiple independent fragments.

Conceptually:

```text
F1 = HMAC(project_key, location_1)
F2 = HMAC(project_key, location_2)
F3 = HMAC(project_key, location_3)
...
Fn = HMAC(project_key, location_n)
```

Each fragment should be associated with a location identifier.

The detector should be able to recognize a subset of the fragments.

This creates a distributed watermark.

---

# 9. WATERMARK CONSTELLATION

The system should represent the watermark as a constellation rather than one marker.

Example:

```text
                  W1
                /    \
              W2      W3
              |        |
              W4      W5
                \    /
                  W6
```

A project might contain 10–30 watermark locations depending on size and configuration.

Do NOT hard-code a universal number.

Determine sensible defaults experimentally.

Document:

- minimum recommended number
- normal number
- large-project number
- tradeoffs

---

# 10. SOURCE EMBEDDING

Watermark fragments must be embedded into legitimate source structures.

Do NOT rely primarily on:

```text
// WATERMARK: abc123
```

or:

```text
const WATERMARK_SECRET = "...";
```

Those are trivial to remove.

Instead, use semantics-preserving source transformations.

Possible transformation families include:

```text
constant decomposition
equivalent arithmetic
boolean normalization
equivalent expressions
safe representation changes
AST-equivalent structural forms
safe table representations
internal deterministic values
```

Only use transformations that can be demonstrated to preserve behavior.

---

# 11. ABSOLUTE RULE: NO BEHAVIORAL REGRESSION

A watermark must not change application behavior.

For every transformation:

1. Define the transformation.
2. Define preconditions.
3. Define postconditions.
4. Test semantic equivalence.
5. Test edge cases.
6. Reject unsafe contexts.

If the system cannot safely embed a watermark at a location:

```text
SKIP LOCATION
```

Do not force embedding.

---

# 12. LANGUAGE ADAPTER INTERFACE

Define a standard adapter interface.

Conceptually:

```text
LanguageAdapter

identify()
parse()
canonicalize()
analyze()
find_candidate_locations()
embed()
extract_features()
detect()
validate()
```

The exact interface may differ depending on implementation language.

The important point is that the core protocol must not know language-specific syntax.

---

# 13. INITIAL LANGUAGE SUPPORT

Implement a sensible initial set of language adapters.

At minimum, evaluate:

```text
JavaScript
TypeScript
Python
```

Then determine whether the architecture supports adding:

```text
Java
Go
Rust
C
C++
C#
PHP
Kotlin
Swift
```

without changing the SWP-1 protocol.

If implementing all of them is impractical for v1, implement the core architecture plus a smaller initial adapter set and provide a clear adapter-development specification.

Do not fake unsupported support.

---

# 14. LANGUAGE-AGNOSTIC FALLBACK

Design a fallback mechanism for source formats where a full AST adapter is unavailable.

Potential techniques:

```text
lexical normalization
token fingerprints
n-gram structural signatures
stable syntax features
exact canonical hashes
```

The fallback must report weaker evidence than a full semantic adapter.

Example:

```text
AST provenance evidence       STRONG
Token structural evidence     MODERATE
Exact textual evidence        STRONG for exact copies
Generic similarity             WEAK
```

Do not treat generic similarity as proof of provenance.

---

# 15. CANONICALIZATION

Implement multiple levels of canonicalization.

### Level 1

Formatting-insensitive.

Must tolerate:

- whitespace
- indentation
- comments where safe
- line ending differences

### Level 2

Identifier-insensitive.

Where the language adapter supports it:

```text
foo → variable_1
bar → variable_2
```

should not destroy structural matching.

### Level 3

AST structural normalization.

Represent equivalent structures in canonical form.

Document exactly what is normalized.

---

# 16. EXACT FINGERPRINT

Implement a release fingerprint for exact provenance.

Conceptually:

```text
canonical_project_representation
            ↓
SHA-256
            ↓
release fingerprint
```

This fingerprint is useful for:

- release records
- unchanged copies
- archive verification
- provenance history

It is NOT the resilient watermark.

---

# 17. RESILIENT WATERMARK

Implement the distributed watermark independently of the exact release fingerprint.

This allows:

```text
exact fingerprint
+
distributed watermark
+
structural evidence
```

to provide different types of evidence.

---

# 18. PRIVATE MANIFEST

Create a private manifest containing enough information to reproduce verification.

Example:

```json
{
  "protocol": "SWP-1",
  "version": 1,
  "project_id": "...",
  "release_id": "...",
  "source_revision": "...",
  "locations": [
    {
      "location_id": "...",
      "fragment_id": "..."
    }
  ]
}
```

Do not store raw secrets unless necessary.

Prefer derived information where possible.

The manifest must have:

```text
PUBLIC
PRIVATE
```

classification.

Document exactly which files can be safely committed.

---

# 19. RELEASE RECORD

Every protected release should be identifiable.

Record:

```text
project ID
release ID
SWP version
generator version
source revision
canonical fingerprint
watermark configuration
timestamp
```

The owner should be able to preserve this independently.

---

# 20. DETECTION ENGINE

Implement:

```bash
swp scan <path>
```

The scanner should accept:

```text
single source file
directory
source tree
archive
package
```

where supported.

The scanner must first determine what it is dealing with.

Example:

```text
Input
 ↓
Project/source detection
 ↓
Language detection
 ↓
Adapter selection
 ↓
Canonicalization
 ↓
Exact matching
 ↓
Structural matching
 ↓
Watermark detection
 ↓
Evidence aggregation
 ↓
Report
```

---

# 21. NEVER EXECUTE UNTRUSTED PROJECT CODE

A candidate project is untrusted input.

The scanner must NOT automatically:

```text
npm install
pip install
cargo build
make
run project
execute scripts
```

just to perform watermark analysis.

Prefer static analysis.

If execution is ever necessary for a specialized adapter, establish an explicit sandbox/security boundary and make it opt-in.

---

# 22. EVIDENCE ENGINE

Do not simply output:

```text
MATCH
```

Build an explainable evidence model.

Evidence categories should include:

```text
EXACT_SOURCE_MATCH
WATERMARK_FRAGMENT_MATCH
STRUCTURAL_MATCH
PARTIAL_WATERMARK_MATCH
CANONICAL_MATCH
TOKEN_MATCH
NEGATIVE_CONTROL
```

Each evidence item should include:

```text
type
location
source region
matching basis
strength
protocol version
```

---

# 23. EVIDENCE LEVELS

Use deterministic evidence levels unless you have a scientifically validated probabilistic model.

Recommended:

```text
NONE
WEAK
MODERATE
STRONG
VERY_STRONG
```

Example:

```text
Watermark fragments: 9/12
Structural regions: 27
Exact matches: 8

Evidence: VERY_STRONG
```

Explain exactly why.

Do NOT call this:

```text
97.2% probability of copying
```

unless you have a statistically defensible model.

---

# 24. PARTIAL COPY DETECTION

Mandatory.

Create controlled experiments:

```text
0%
10%
25%
50%
75%
90%
100%
```

where practical.

Determine empirically how detection behaves.

Do not invent thresholds.

Document observed results.

---

# 25. REFACTORING RESISTANCE

Test:

```text
variable rename
function rename
class rename
formatting
comment removal
file movement
function extraction
function inlining
expression rewriting
constant rewriting
import changes
dead-code removal
code reordering
partial copying
```

Measure which forms of modification preserve detection.

---

# 26. ADVERSARIAL WATERMARK REMOVAL

Assume the attacker knows SWP-1 exists.

Create an adversarial test suite.

Attempt:

```text
remove obvious watermark artifacts
identify repeated patterns
rewrite embedded expressions
remove selected locations
rewrite AST structures
normalize constants
rebuild copied modules
```

Document:

```text
what survives
what fails
what becomes weaker
```

Never claim the watermark is impossible to remove.

---

# 27. FALSE-POSITIVE TESTING

Create unrelated source projects containing:

```text
common algorithms
common framework patterns
common constants
common boilerplate
standard library usage
generated code
popular open-source structures
```

The detector must distinguish these from genuine watermark evidence.

This is one of the highest-priority test categories.

---

# 28. COLLISION TESTING

Generate many independent watermark identities.

Test that:

```text
Project A ≠ Project B
Project B ≠ Project C
...
```

Test multiple runs.

Test multiple machines/environments if practical.

Verify that watermark identifiers are generated with sufficient entropy.

---

# 29. SECRET-LEAK TESTING

Automated tests must verify that the root secret cannot be found in:

```text
source
build output
CLI logs
reports
errors
documentation
test snapshots
temporary files
```

where applicable.

Search generated artifacts automatically.

---

# 30. CRYPTOGRAPHIC REVIEW

Review:

- CSPRNG
- HMAC
- hash usage
- key derivation
- domain separation
- key length
- secret storage
- serialization
- manifest integrity

Do not invent cryptographic primitives.

Prefer well-established standard primitives.

---

# 31. MANIFEST INTEGRITY

The private manifest itself must be protected against accidental modification.

Consider a signed manifest.

For example:

```text
private manifest
      ↓
canonical serialization
      ↓
digital signature
      ↓
signed manifest
```

Use a modern standard signature scheme where appropriate.

The signing key must remain private.

The public verification key may be distributed with verification tooling where useful.

---

# 32. CLI DESIGN

Provide:

```bash
swp init
swp generate
swp protect
swp verify
swp scan
swp inspect
swp report
```

At minimum:

```bash
swp init
swp protect
swp verify
swp scan
```

Every command must provide:

```bash
--help
```

and useful exit codes.

---

# 33. JSON OUTPUT

Every major operation should support machine-readable output.

Example:

```bash
swp scan ./candidate --format json
```

Output should contain a versioned schema:

```json
{
  "schema": "SWP-1-report-v1",
  "protocol": "SWP-1",
  "result": "PROVENANCE_DETECTED",
  "evidence": []
}
```

Document the schema.

---

# 34. OFFLINE-FIRST DESIGN

SWP-1 should work offline.

The basic operations:

```text
generate
protect
verify
scan
```

must not require an external server.

No telemetry.

No mandatory cloud account.

No mandatory central database.

The owner may optionally build a private provenance registry later, but that must not be required by SWP-1.

---

# 35. UNIVERSAL PROJECT WORKFLOW

The final user workflow should be extremely simple.

For a new project:

```bash
swp init
```

Then:

```bash
swp protect
```

Then:

```bash
swp verify
```

The user should be told exactly:

```text
What was generated
What was modified
Where private data is stored
What must be backed up
What can be committed
What must never be committed
```

---

# 36. COMPLETE USER DOCUMENTATION

Create:

```text
README.md
docs/GETTING-STARTED.md
docs/USER-GUIDE.md
docs/SWP-1-SPEC.md
docs/INTEGRATION.md
docs/LANGUAGE-ADAPTERS.md
docs/SECURITY.md
docs/THREAT-MODEL.md
docs/CLI.md
docs/REPORTS.md
docs/TROUBLESHOOTING.md
docs/FAQ.md
docs/DEVELOPER-GUIDE.md
docs/VALIDATION.md
```

---

# 37. GETTING STARTED GUIDE

A completely new developer must be able to follow this from zero.

Include:

```text
Prerequisites
Installation
Initialization
Secret creation
Project configuration
Watermark generation
Verification
Scanning
Interpreting results
Backing up provenance information
```

Every step must contain exact commands.

No vague instructions.

---

# 38. UNIVERSAL INTEGRATION GUIDE

The integration guide must explain how SWP-1 is used in:

```text
JavaScript project
Python project
TypeScript project
generic source project
```

where supported.

Then explain how to add a new language adapter.

The guide must clearly separate:

```text
Protocol
Core engine
Language adapter
CLI
Project integration
```

---

# 39. LANGUAGE ADAPTER DEVELOPMENT GUIDE

Create a complete guide for developers implementing adapters.

Define:

```text
required interface
parser expectations
canonicalization requirements
safe embedding rules
feature extraction
detection rules
testing requirements
security requirements
```

A new developer should be able to create a new adapter without modifying the core protocol.

---

# 40. EXAMPLE PROJECTS

Create multiple test/example projects.

For example:

```text
examples/
├── javascript/
├── typescript/
├── python/
└── generic/
```

Each should demonstrate:

```bash
swp init
swp protect
swp verify
swp scan
```

Do not use fake output in documentation.

Documentation examples must be tested against the real implementation.

---

# 41. TEST DOCUMENTATION EXAMPLES

Every command shown in documentation must be validated.

Create automated documentation tests where practical.

A documentation example that no longer works must cause CI failure if feasible.

---

# 42. TEST MATRIX

Build a serious test matrix.

## Core

```text
identity generation
key derivation
fragment generation
manifest
serialization
versioning
```

## Embedding

```text
safe locations
unsafe locations
transformation correctness
idempotency
```

## Detection

```text
exact
partial
refactored
renamed
formatted
moved
```

## Security

```text
secret leakage
malicious source
malformed input
resource exhaustion
path traversal
```

## False positives

```text
common algorithms
common structures
unrelated projects
generated source
```

## CLI

```text
valid commands
invalid commands
exit codes
JSON
text
help
```

---

# 43. PROPERTY-BASED TESTING

Where practical, generate randomized transformations.

For example:

```text
original source
   ↓
random formatting
   ↓
random identifier rename
   ↓
safe expression rewrite
   ↓
comment removal
   ↓
scan
```

Run many iterations.

The goal is to find cases that hand-written tests miss.

---

# 44. PERFORMANCE TESTING

Benchmark:

```text
small project
medium project
large project
very large source tree
```

Measure:

```text
protection time
verification time
scan time
memory
AST parsing overhead
```

Set reasonable performance expectations.

Do not optimize prematurely.

---

# 45. RESOURCE-EXHAUSTION PROTECTION

The scanner must safely handle hostile input.

Test:

```text
huge files
deep syntax
many nested structures
zip bombs if archives are supported
millions of tiny files
malformed source
repeated parser failures
```

Implement appropriate limits.

---

# 46. PRIVACY

The scanner must not upload source code anywhere by default.

Document:

```text
what is processed
where it is processed
what is stored
what is logged
```

The default should be local processing.

---

# 47. VERSIONING

Version:

```text
SWP protocol
manifest schema
report schema
language adapters
CLI
```

A future incompatible protocol must not silently masquerade as SWP-1.

---

# 48. BACKWARD COMPATIBILITY

The detector should be able to identify the SWP version of an artifact where possible.

If an old watermark cannot be verified with the current engine:

```text
report unsupported protocol version
```

Do not silently return:

```text
NO MATCH
```

when the actual problem is:

```text
UNSUPPORTED VERSION
```

---

# 49. ERROR MODEL

Define explicit errors such as:

```text
UNSUPPORTED_LANGUAGE
INVALID_MANIFEST
INVALID_WATERMARK
SECRET_UNAVAILABLE
MALFORMED_SOURCE
PARSER_FAILURE
UNSAFE_EMBEDDING
PROTOCOL_VERSION_UNSUPPORTED
INSUFFICIENT_EVIDENCE
```

CLI messages must explain what the user should do next.

---

# 50. SECURITY THREAT MODEL

Document attacks including:

```text
casual copying
normal refactoring
intentional watermark removal
watermark discovery
manifest theft
secret theft
false-positive attacks
source poisoning
malicious repositories
parser exploitation
```

For each:

```text
Threat
Impact
Mitigation
Residual limitation
```

---

# 51. WHAT SWP-1 MUST NOT CLAIM

Documentation must explicitly state:

SWP-1 does not guarantee:

- legal ownership
- proof of authorship by itself
- detection after arbitrary rewriting
- detection after complete reimplementation
- immunity from deliberate watermark removal
- detection of every possible copy
- zero false positives

SWP-1 provides technical provenance evidence.

---

# 52. ADVERSARIAL VALIDATION

Before completion, behave as an attacker.

You must attempt to defeat the system.

Create a separate:

```text
tests/adversarial/
```

suite.

Try to:

```text
find watermark locations
remove them
rewrite them
restructure the source
preserve behavior while changing syntax
copy only core algorithms
combine fragments from projects
```

Document the results.

---

# 53. INDEPENDENT VALIDATION

After implementation:

1. Delete build artifacts.
2. Start from a clean environment.
3. Install SWP-1.
4. Create a brand-new sample project.
5. Protect it.
6. Verify it.
7. Create a second unrelated project.
8. Scan it.
9. Create a copied/refactored project.
10. Scan it.
11. Review the reports.

This proves that the system actually works outside its own test fixtures.

---

# 54. FINAL QUALITY GATE

Do not declare completion until all of these pass:

```text
[ ] Protocol implemented
[ ] Cryptographic design reviewed
[ ] Secret never embedded
[ ] Distributed watermark implemented
[ ] Exact fingerprint implemented
[ ] Canonicalization implemented
[ ] Language adapter architecture implemented
[ ] Initial adapters implemented
[ ] Fallback architecture documented
[ ] Detection implemented
[ ] Partial-copy detection tested
[ ] Refactoring tests passed
[ ] False-positive tests passed
[ ] Collision tests passed
[ ] Adversarial tests passed
[ ] Secret-leak tests passed
[ ] Malicious-input tests passed
[ ] CLI tested
[ ] JSON reports tested
[ ] Documentation examples tested
[ ] Integration guide complete
[ ] Security documentation complete
[ ] Threat model complete
[ ] Language-adapter guide complete
[ ] Performance benchmark completed
[ ] Existing tests pass
[ ] Clean-environment test passes
```

---

# 55. FINAL REPORT

When everything is complete, provide a detailed final report.

Use exactly this structure:

```text
SWP-1 DEVELOPMENT REPORT
========================

1. Architecture
2. Protocol
3. Cryptography
4. Secret management
5. Watermark generation
6. Embedding strategy
7. Canonicalization
8. Detection engine
9. Evidence engine
10. Language adapters
11. CLI
12. Manifest
13. Security model
14. Threat model
15. Test strategy
16. Adversarial testing
17. False-positive testing
18. Performance testing
19. Documentation
20. Known limitations
21. Future SWP-2 considerations
22. Files created
23. Files modified
24. Commands tested
25. Test results
26. Final status
```

For every claimed capability, provide evidence from tests.

Do not say:

```text
"Works perfectly."
```

Instead report:

```text
"Validated against X test cases with Y passes and Z failures."
```

---

# 56. MOST IMPORTANT CONSTRAINT

Do not turn SWP-1 into a repository-specific feature.

The final system must be something a developer can take and use on an entirely unrelated project.

The correct mental model is:

```text
               SWP-1
                  |
       ┌──────────┴──────────┐
       │                     │
   Universal Core       Language Adapters
       │                     │
       │              JS / TS / Python / ...
       │
       ▼
   Any compatible
   software project
```

A developer should be able to use SWP-1 today on Project A and tomorrow on a completely unrelated Project B without changing the core watermark protocol.

---

# 57. FINAL ACCEPTANCE SCENARIO

Prove the system using at least three independent projects:

```text
Project A — JavaScript/TypeScript
Project B — Python
Project C — unrelated project
```

Perform:

```text
A → protect
A → verify
B → protect
B → verify
C → scan against A
C → scan against B
```

Then create:

```text
A-copy
A-refactored
A-partial
A-watermark-damaged
```

and scan each.

The final report must demonstrate:

```text
A                    → detected as A
B                    → detected as B
C                    → not falsely identified as A/B
A-copy               → provenance detected
A-refactored         → provenance evidence evaluated
A-partial            → partial provenance evidence
A-watermark-damaged  → remaining evidence reported
```

Do not hard-code these expected results into the detector.

The tests must independently establish them.

---

# 58. DELIVERABLE STANDARD

The finished SWP-1 must be:

- standalone
- reusable
- language-independent at the protocol level
- cryptographically sound
- offline-first
- explainable
- testable
- extensible
- documented
- safe against untrusted source input
- honest about limitations

Do not optimize for the appearance of sophistication.

Optimize for **correctness, reproducibility, provenance evidence, security, maintainability, and clear user operation**.

Before finishing, read your own documentation as if you were a developer who has never seen SWP-1 before.

If any step requires guessing what the user should do, fix the documentation.