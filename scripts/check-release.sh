#!/bin/sh
# Check the things a release depends on that `cargo build` cannot see.
#
# A registry publish and a GitHub release are both built from this tree as it
# stands on a tag, with no maintainer looking over them. Everything below is a
# way that has broken a release before, or would break one quietly: a version
# stated twice and agreeing in only one place, a crate whose manifest will not
# package, a licence file that went missing, a binary artefact that slid into
# the sources.
#
# Usage: sh scripts/check-release.sh
#
# Offline by design: `--offline` is passed to every cargo command here, so a
# check that needs the network fails loudly rather than reaching out during a
# release. The one command that genuinely cannot run offline is `cargo publish`,
# and this script stops short of it — see the last line of its output.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }
note() { printf '        %s\n' "$1"; }

# The crates that go to the registry, in dependency order. `swp-test-suite` is
# deliberately absent: it is this project's own measurement harness, and it
# says so in its manifest.
PUBLISHABLE="swp-core swp-crypto swp-identity swp-manifest swp-adapters swp-embedding swp-detection swp-evidence swp-cli"
TOTAL=0
for c in $PUBLISHABLE; do TOTAL=$((TOTAL + 1)); done

printf '\n== the version is one version ==\n'
VERSION=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n 1)
if [ -z "$VERSION" ]; then
    bad "[workspace.package] has no version"
else
    ok "workspace version is $VERSION"
    # A path dependency that names no version packages into a manifest cargo
    # will not publish: the `path` is stripped for the registry, and with it
    # goes the only thing that said where the crate lives.
    for c in $PUBLISHABLE; do
        if grep -q "^${c} = { path = \"crates/${c}\", version = \"${VERSION}\" }" Cargo.toml; then
            ok "$c pinned at version \"$VERSION\" in [workspace.dependencies]"
        else
            bad "$c is not pinned to $VERSION in [workspace.dependencies]"
            note "fix: $c = { path = \"crates/$c\", version = \"$VERSION\" }"
        fi
    done
    # The lockfile is what a build actually resolves, so it has to agree too — and
    # it has to agree *about this package*. `version = "1.0.0"` appears in
    # Cargo.lock for third-party crates as well, so an unscoped grep for it is
    # satisfied by an unrelated dependency and proves nothing.
    for c in $PUBLISHABLE; do
        # No `exit` here: awk's exit runs END, which would print the answer twice
        # and make the comparison below fail on a lockfile that is perfectly right.
        lv=$(awk -v want="$c" '
            $0 == "[[package]]" { if (name == want && ver != "") found = ver; name = ""; ver = "" }
            /^name = /    { name = $3; gsub(/"/, "", name) }
            /^version = / { ver  = $3; gsub(/"/, "", ver) }
            END { if (name == want && ver != "") found = ver; print found }
        ' Cargo.lock)
        if [ "$lv" = "$VERSION" ]; then
            ok "Cargo.lock resolves $c at $VERSION"
        elif [ -z "$lv" ]; then
            bad "Cargo.lock has no package named $c"
        else
            bad "Cargo.lock resolves $c at \"$lv\", not $VERSION"
            note "fix: cargo update -p $c --precise $VERSION, or commit the lockfile"
        fi
    done
fi

printf '\n== the licence is present and stated ==\n'
for f in LICENSE NOTICE; do
    if [ -s "$f" ]; then ok "$f exists"; else bad "$f is missing or empty"; fi
done
if grep -q "Version 2.0, January 2004" LICENSE && grep -qi "Apache License, Version 2.0" LICENSE; then
    ok "LICENSE is the Apache-2.0 text"
else
    bad "LICENSE does not look like the Apache-2.0 text"
fi
if grep -q '^license = "Apache-2.0"$' Cargo.toml; then
    ok "the workspace declares Apache-2.0"
else
    bad "the workspace does not declare license = \"Apache-2.0\""
fi
for c in $PUBLISHABLE; do
    if grep -q '^license.workspace = true$' "crates/$c/Cargo.toml"; then
        ok "$c inherits its licence"
    else
        bad "$c does not inherit the workspace licence"
    fi
done

printf '\n== the published address, and the parties named in the legal pages ==\n'
# The address is read from the manifest, not written here, so this cannot drift
# into endorsing a URL the tree does not use. `release.yml` checks the same string
# against the repository a release actually runs in; offline, the most a check can
# say is that the address exists, is well-formed, and is not the placeholder this
# project was drafted with.
REPO=$(sed -n 's|^repository = "https://github\.[a-z]*/\([^/]*/[^/]*\)"$|\1|p' Cargo.toml | head -n1)
if [ -z "$REPO" ]; then
    bad "Cargo.toml has no github.com repository address"
elif printf '%s' "$REPO" | grep -qi "OWNER\|TODO\|example"; then
    bad "the repository address is still a placeholder: $REPO"
    note "a crate published from here carries that URL into the registry index"
else
    ok "published address: github.com/$REPO"
    note "confirm this is the tree you are releasing from; release.yml insists"
fi

# An unfilled field in a legal page reads as finished and is not. These are the
# bracketed labels those pages were drafted with, and one of them — a CLA that
# names no entity — is the difference between a grant and a receipt.
if grep -rln "\[legal entity name\]\|\[contact email\]\|\[name · \|fill in before release\|\[GitHub organisation owner\]\|github\.com/OWNER" \
    --exclude-dir=.git --exclude-dir=target --exclude-dir=.swp --exclude-dir=.github \
    --exclude=check-release.sh . 2>/dev/null; then
    bad "an unfilled field remains in the files above"
    note "SECURITY.md, CLA.md §9 and NOTICE name real parties now"
else
    ok "no unfilled legal or policy field in the tree"
fi

printf '\n== the sponsorship page names four levels, and one account ==\n'
# SPONSORS.md is the only place a tier is written down; GitHub's own sponsor-tier
# form is filled from it by hand. That leaves two ways for the promise to go wrong,
# and this checks both. First, the four levels have to be there and have to carry a
# price each — three monthly tiers plus the one-time level, which is a row and not a
# tier. The page writes them in one fixed shape, and a rewrite that breaks that
# shape yields fewer than four rows rather than a silent pass.
PAGE=$(
    sed -n 's/^### Tier \([0-9]\) — \(.*\) · \(\$[0-9]*\) a month.*/tier \1 \2 \3/p' SPONSORS.md
    sed -n 's/^### Supporter — \(\$[0-9]*\), once.*/supporter \1 once/p' SPONSORS.md
)
PAGE=$(printf '%s\n' "$PAGE" | sort)
ROWS=$(printf '%s\n' "$PAGE" | grep -c . || true)
if [ "$ROWS" -ne 4 ]; then
    bad "the sponsorship page states $ROWS level(s), not the four it promises"
    echo "$PAGE" | sed 's/^/        /'
    note "the page wants '### Tier 1 — Builder · \$10 a month' and"
    note "'### Supporter — \$25, once'; this check reads those two shapes"
else
    ok "three monthly tiers and the one-time level, each with a price"
    echo "$PAGE" | sed 's/^/        /'
fi
# Second, and the one that loses money rather than face: the account the page sends
# a sponsor to has to be the account GitHub pays. They are written in two files with
# no reason to agree, and a renamed or replaced account makes every link on the page
# a donation to somebody else.
PAYS=$(sed -n 's/^github: *\([^ ]*\) *$/\1/p' .github/FUNDING.yml | head -n1)
LINKS=$(sed -n 's|.*https://github\.com/sponsors/\([A-Za-z0-9-]*\).*|\1|p' SPONSORS.md | sort -u)
if [ -z "$PAYS" ]; then
    bad ".github/FUNDING.yml names no github: account"
elif [ "$LINKS" != "$PAYS" ]; then
    bad "the page sends sponsors somewhere other than the account that is paid"
    echo "FUNDING.yml pays:      $PAYS" | sed 's/^/        /'
    echo "SPONSORS.md links to:  ${LINKS:-nothing}" | sed 's/^/        /'
    note "every sponsor link on the page has to name the account that receives it"
else
    ok "the sponsor link on the page is the account that is paid: $PAYS"
fi

printf '\n== the sources contain no built artefacts ==\n'
TRACKED=$(git ls-files | grep -Ei '\.(pyc|pyo|o|a|so|dll|dylib|exe|class|wasm)$' || true)
if [ -z "$TRACKED" ]; then
    ok "no compiled artefacts are tracked"
else
    bad "tracked binary artefacts:"
    printf '        %s\n' $TRACKED
    note "the scanner does not walk __pycache__ or target/, so neither belongs here"
fi

printf '\n== every publishable manifest is valid, and the graph resolves ==\n'
# Two checks that are genuine offline, before the packaging loop that is not:
# `verify-project` says every manifest in the workspace parses and is a manifest
# cargo will accept, and `metadata --locked` says the dependency graph the
# lockfile describes is the one the manifests ask for — which is the failure a
# stale lockfile causes, and the one a publish would hit first.
if cargo verify-project --offline >/dev/null 2>&1; then
    ok "every manifest in the workspace parses"
else
    bad "cargo verify-project rejected a manifest"
    cargo verify-project --offline 2>&1 | sed 's/^/        /'
fi
# `|| true` because a non-zero status here is the finding, not an accident: under
# `set -e` the assignment alone would end the script before the branch below runs.
META=$(cargo metadata --format-version 1 --locked --offline 2>&1 >/dev/null) || true
if [ -z "$META" ]; then
    ok "Cargo.lock matches the manifests; the graph resolves offline"
elif printf '%s' "$META" | grep -q -- "--offline was specified"; then
    printf '  unvrf the graph — this machine has never downloaded a crate the lockfile\n'
    note "names. Not a defect in the tree: ci.yml, release.yml and publish.yml each"
    note "run \`cargo fetch --locked\` before calling this, and there the check is real."
else
    bad "the graph does not resolve against the committed lockfile"
    printf '%s\n' "$META" | head -n 3 | sed 's/^/        /'
    note "fix: cargo metadata --format-version 1 >/dev/null, then commit Cargo.lock"
fi

printf '\n== every publishable manifest packages ==\n'
# The leaf crate is the only one provable offline: the others depend on a sibling
# that is not in the index until it is published, and cargo is right to say so.
# So the sibling case is reported as what it is — unverified — rather than as a
# pass. A manifest error in one of those crates surfaces in `cargo metadata`
# above, which covers every one of them; what stays unproven here is the
# packaging step itself, and the count below says how many crates that is.
UNVERIFIED=0
for c in $PUBLISHABLE; do
    out=$(cargo package -p "$c" --no-verify --offline --allow-dirty 2>&1) || {
        case "$out" in
            *"no matching package named \`swp-"*)
                UNVERIFIED=$((UNVERIFIED + 1))
                printf '  unvrf %s — not packaged: it depends on a sibling that is not in\n' "$c"
                note "the index yet, which this run cannot reach. The publish packages it." ;;
            *)
                bad "$c does not package"
                printf '%s\n' "$out" | grep -A 3 'Caused by:' | sed 's/^/        /' ;;
        esac
        continue
    }
    ok "$c packages"
done
if [ "$UNVERIFIED" -gt 0 ]; then
    note "$UNVERIFIED of the $TOTAL crates were never packaged by this check."
    note "publish.yml's dry run is what packages them, in dependency order, with network."
fi

printf '\n'
if [ "$fail" -ne 0 ]; then
    printf 'check-release: not ready. Fix the FAIL lines above; they are the ones\n'
    printf 'a registry index and a release page would both show to the public.\n'
    exit 1
fi
printf 'check-release: ready, as far as an offline machine can tell.\n'
printf 'Remaining, in this order, from a machine that has the network:\n'
printf '  1. cargo login && cargo publish -p swp-core   … then each crate in the\n'
printf '     PUBLISHABLE order above. A publish cannot be undone, only yanked.\n'
printf '  2. git tag v%s && git push --tags        → release.yml builds it\n' "$VERSION"
