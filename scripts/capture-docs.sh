#!/bin/sh
# Capture the transcripts the documentation quotes.
#
# Every block in README.md, docs/*.md and examples/*/README.md that is fenced as
# ```console was produced by this script, so a documented line is a line the
# product really printed. Volatile tokens — project ids, release ids, digests,
# timestamps, candidate paths — are left out of the quoted blocks rather than
# faked, and tests/docs/examples.rs re-runs each transcript and checks every line
# that survived.
#
# Usage: SWP=/path/to/swp.exe sh scripts/capture-docs.sh <outdir>
set -u

SWP="${SWP:-swp}"
OUT="${1:?usage: capture-docs.sh <outdir>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$OUT/work" "$OUT/text"

# run <name> <cwd> <command...> — one command's transcript, verbatim.
#
# The binary is written back as `swp`, the word a reader types: an absolute path
# to a build artifact on this machine is not part of the example.
run() {
    name="$1"
    cwd="$2"
    shift 2
    {
        printf '$ swp'
        for a in "$@"; do
            [ "$a" = "$SWP" ] && continue
            printf ' %s' "$a"
        done
        printf '\n'
    } >"$OUT/text/$name.txt"
    (cd "$cwd" && "$@" >"$OUT/text/$name.raw" 2>&1)
    status=$?
    cat "$OUT/text/$name.raw" >>"$OUT/text/$name.txt"
    rm -f "$OUT/text/$name.raw"
    # `swp scan`, `swp verify` and `swp report` print their own exit code as their
    # last line, so that a script can read it from a log. Every other command does
    # not, and the transcript has to record what happened for all of them the same
    # way.
    if ! tail -n 1 "$OUT/text/$name.txt" | grep -q "^exit $status\([^0-9]\|$\)"; then
        printf 'exit %s\n' "$status" >>"$OUT/text/$name.txt"
    fi
}

# An unprotected, unrelated tree: the "second project" every example scans.
rm -rf "$OUT/work/plain"
mkdir -p "$OUT/work/plain"
cp -r "$ROOT/examples/python/src" "$OUT/work/plain/"
cp "$ROOT/examples/python/pyproject.toml" "$OUT/work/plain/"

# A protected tree of a different project entirely, staged once and never quoted
# for its own sake. JavaScript scans it to show what a near miss looks like: real
# address collisions with none of the codes, in a tree that shares no source with
# the project doing the scanning.
rm -rf "$OUT/work/typescript-foreign"
mkdir -p "$OUT/work/typescript-foreign"
cp -r "$ROOT/examples/typescript" "$OUT/work/typescript-foreign/"
run foreign.init "$OUT/work/typescript-foreign" "$SWP" init
run foreign.protect "$OUT/work/typescript-foreign" "$SWP" protect --sites 12

# typescript and python run first so javascript can scan a *protected* foreign
# tree as well as an unprotected one.
for example in typescript python javascript generic; do
    work="$OUT/work/$example"
    rm -rf "$work"
    cp -r "$ROOT/examples/$example" "$work"
    run "$example.init" "$work" "$SWP" init
    run "$example.generate" "$work" "$SWP" generate
    # The dry run is captured against a clean tree, because that is the transcript a
    # reader sees before their first real protect. It writes nothing.
    run "$example.dry-run" "$work" "$SWP" protect --dry-run
    run "$example.protect" "$work" "$SWP" protect --sites 12
    run "$example.verify" "$work" "$SWP" verify
    run "$example.verify-json" "$work" "$SWP" verify --format json
    mkdir -p "$work/copy/src"
    cp "$work"/src/* "$work/copy/src/" 2>/dev/null
    run "$example.scan-copy" "$work" "$SWP" scan ./copy
    run "$example.scan-plain" "$work" "$SWP" scan ../plain
    run "$example.verify-plain" "$work" "$SWP" verify -p ../plain
    if [ "$example" = "javascript" ]; then
        run "$example.scan-foreign" "$work" "$SWP" scan ../typescript-foreign
    fi
    run "$example.inspect-releases" "$work" "$SWP" inspect releases
    # The store-side views need the release this run published, which is a fresh
    # id every time: read it off the filesystem rather than pasting one in.
    rel=$(ls "$work/.swp/public/releases" 2>/dev/null | head -n 1 | sed 's/\.json$//')
    if [ -n "$rel" ]; then
        run "$example.inspect-release" "$work" "$SWP" inspect release --release "$rel"
        run "$example.inspect-plan" "$work" "$SWP" inspect plan --release "$rel"
        run "$example.inspect-fragments" "$work" "$SWP" inspect fragments --release "$rel"
        run "$example.inspect-manifest" "$work" "$SWP" inspect manifest --release "$rel"
        run "$example.verify-save" "$work" "$SWP" verify --release "$rel" --save
        run "$example.report-list" "$work" "$SWP" report
        saved=$(ls "$work/.swp/private/reports" 2>/dev/null | head -n 1 | sed 's/\.json$//')
        run "$example.report-render" "$work" "$SWP" report "$saved"
    fi
    # The interface pages, last, because they read the tree the sequence above
    # left behind and must not be able to change what it measured.
    run "$example.version" "$work" "$SWP" --version
    run "$example.help" "$work" "$SWP" help
    run "$example.help-protect" "$work" "$SWP" help protect
    run "$example.help-scan" "$work" "$SWP" help scan
    run "$example.inspect-store" "$work" "$SWP" inspect store
    run "$example.inspect-identity" "$work" "$SWP" inspect identity
    run "$example.inspect-config" "$work" "$SWP" inspect config
    run "$example.scan-copy-json" "$work" "$SWP" scan ./copy --format json
    run "$example.scan-missing" "$work" "$SWP" scan ./nowhere
    run "$example.bad-flag" "$work" "$SWP" scan --formt json ./copy
    # The five experiments, last, because each leaves the tree in a state no page
    # above quotes: a limit small enough to stop a scan halfway, a protected file
    # emptied out from under a verify, a committed release record with one character
    # of its fingerprint changed, no root secret, and finally no config to open the
    # store with.
    # `-p .` names the store they stand in, which keeps their headers distinct
    # from the clean runs earlier in the sequence.
    cp "$work/.swp/config.toml" "$OUT/config.bak"
    sed 's/^max_file_bytes = .*/max_file_bytes = 900/' "$OUT/config.bak" > "$work/.swp/config.toml"
    run "$example.limit-scan" "$work" "$SWP" scan ./copy -p .
    cp "$OUT/config.bak" "$work/.swp/config.toml"
    # The scanned copy goes before this: verify reads the whole project tree, so
    # with copy/ still present every site lost from src/ is found in the copy,
    # reported as moved, and the verdict stays INTACT.
    rm -rf "$work/copy"
    # The last file under src/, deliberately emptied: a stub of a file is what a
    # partial removal looks like from the scanner's side.
    last=$(find "$work/src" -maxdepth 1 -type f 2>/dev/null | sort | tail -n 1)
    if [ -n "$last" ]; then
        : > "$last"
        run "$example.emptied-verify" "$work" "$SWP" verify -p .
    fi
    # One character of the committed release record's fingerprint: still valid
    # JSON, no longer the document this project signed.
    rec=$(find "$work/.swp/public/releases" -name '*.json' | sort | tail -n 1)
    if [ -n "$rec" ]; then
        cp "$rec" "$OUT/record.bak"
        # Written to a temp file and moved back, because `sed -i` takes an
        # argument only GNU's does: `sed -i 's/…/'` on macOS reads `'s/…/'` as
        # the backup suffix and refuses the script.
        if grep -q '"fingerprint": "0' "$rec"; then
            flip='s/"fingerprint": "0/"fingerprint": "1/'
        else
            flip='s/"fingerprint": "./"fingerprint": "0/'
        fi
        sed "$flip" "$rec" > "$rec.flipped" && mv "$rec.flipped" "$rec"
        # A tamper that silently did nothing would produce a transcript of an
        # ordinary `inspect releases` under a name that promises the opposite.
        if cmp -s "$rec" "$OUT/record.bak"; then
            printf 'capture-docs: %s was not changed; refusing to record a fake tamper\n' "$rec" >&2
            cp "$OUT/record.bak" "$rec"
            exit 1
        fi
        run "$example.tampered-releases" "$work" "$SWP" inspect releases -p .
        cp "$OUT/record.bak" "$rec"
    fi
    rm -f "$work/.swp/private/root.key"
    run "$example.nosecret-generate" "$work" "$SWP" generate -p .
    rm -f "$work/.swp/config.toml"
    run "$example.nostore-inspect" "$work" "$SWP" inspect store -p .
done

printf 'captured into %s/text\n' "$OUT"
