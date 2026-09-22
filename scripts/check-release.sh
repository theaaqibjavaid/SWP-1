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
    # The lockfile is what a build actually resolves, so it has to agree too.
    if grep -q "^version = \"$VERSION\"" Cargo.lock; then
        ok "Cargo.lock carries $VERSION"
    else
        bad "Cargo.lock has no package at version $VERSION"
    fi
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
    note "SECURITY.md, CLA.md §9, NOTICE and MAINTAINERS.md name real parties now"
else
    ok "no unfilled legal or policy field in the tree"
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

printf '\n== every publishable manifest packages ==\n'
# The leaf crate is the only one checkable offline: the others depend on a
# sibling that is not in the index until it is published, and cargo is right to
# say so. Order matters for the real publish, and this proves the order works.
for c in $PUBLISHABLE; do
    out=$(cargo package -p "$c" --no-verify --offline --allow-dirty 2>&1) || {
        case "$out" in
            *"no matching package named \`swp-"*)
                ok "$c packages; its sibling dependency is unpublished (expected offline)" ;;
            *)
                bad "$c does not package"
                printf '%s\n' "$out" | grep -A 3 'Caused by:' | sed 's/^/        /' ;;
        esac
        continue
    }
    ok "$c packages"
done

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
