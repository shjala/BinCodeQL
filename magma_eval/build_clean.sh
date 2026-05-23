#!/bin/bash
# build_clean.sh <target> <variant>
#
# Build a magma target with bug patches applied but NO canary
# instrumentation linked in. The resulting binary contains the
# vulnerable code (or the patched code, depending on variant) but
# none of magma's bug-tracking strings or symbols, so an LLM
# analysing the binary has no shortcut to ground truth.
#
# target:  libtiff | libxml2
# variant: vuln    | patched
#
# Output:  $FARAH/<target>-<variant>/<utility-binary(ies)>
# Sources are cloned from existing local trees (no network).
# Nothing is installed system-wide.
set -euo pipefail

TARGET_NAME="${1:?usage: $0 <libtiff|libxml2> <vuln|patched>}"
VARIANT="${2:?usage: $0 <libtiff|libxml2> <vuln|patched>}"

case "$VARIANT" in vuln|patched) ;; *)
    echo "ERROR: variant must be 'vuln' or 'patched'" >&2; exit 2 ;;
esac

# ---- paths -----------------------------------------------------------
MAGMA_ROOT=/home/sanjay/san-home/research/tii/tii24/repos/magma
FARAH=/home/sanjay/san-home/research/tii/tii24/tmp/farah-magma
LOCAL_SRC_ROOT=/home/sanjay/san-home/research/tii/tii24/tmp

case "$TARGET_NAME" in
    libtiff)
        LOCAL_SRC="$LOCAL_SRC_ROOT/libtiff-magma"
        PINNED_COMMIT="c145a6c14978f73bb484c955eb9f84203efcb12e"
        ;;
    libxml2)
        LOCAL_SRC="$LOCAL_SRC_ROOT/libxml2-magma"
        PINNED_COMMIT="ec6e3efb06d7b15cf5a2328fabd3845acea4c815"
        ;;
    *)
        echo "ERROR: unknown target '$TARGET_NAME' (expected libtiff or libxml2)" >&2
        exit 2 ;;
esac

[ -d "$LOCAL_SRC/.git" ] || { echo "ERROR: local source not found at $LOCAL_SRC" >&2; exit 3; }

OUT_DIR="$FARAH/${TARGET_NAME}-${VARIANT}"
WORK_DIR="$FARAH/.work-${TARGET_NAME}-${VARIANT}"
TARGET="$WORK_DIR/target"

mkdir -p "$FARAH"
rm -rf "$OUT_DIR" "$WORK_DIR"
mkdir -p "$OUT_DIR" "$TARGET"

# ---- stage the magma target dir (provides patches/, src/) ------------
# We copy the magma target dir (patches + harness sources) but NOT
# repo/ — that comes from the local git clone below.
cp -r "$MAGMA_ROOT/targets/$TARGET_NAME"/. "$TARGET/"

# ---- clone source from local (fast, no network) ---------------------
echo "[*] Cloning $TARGET_NAME from $LOCAL_SRC ..."
git clone --quiet "$LOCAL_SRC" "$TARGET/repo"
git -C "$TARGET/repo" checkout --quiet "$PINNED_COMMIT"

# Sanity: ensure we landed on the pinned commit and the working tree
# is pristine (uncommitted patches in $LOCAL_SRC do NOT transfer via
# git clone, but assert anyway).
ACTUAL=$(git -C "$TARGET/repo" rev-parse HEAD)
[ "$ACTUAL" = "$PINNED_COMMIT" ] || {
    echo "ERROR: checkout landed on $ACTUAL, expected $PINNED_COMMIT" >&2
    exit 4
}
DIRTY=$(git -C "$TARGET/repo" status --porcelain | wc -l)
[ "$DIRTY" = "0" ] || {
    echo "ERROR: cloned repo is dirty (clone-from-local should never produce this)" >&2
    git -C "$TARGET/repo" status --short | head >&2
    exit 5
}

# ---- copy oss-fuzz harness sources required by magma's setup --------
# (libtiff/libxml2 patches reference them; copy any expected hooks)
[ -d "$TARGET/src" ] && {
    case "$TARGET_NAME" in
        libtiff)
            cp "$TARGET/src/tiff_read_rgba_fuzzer.cc" \
               "$TARGET/repo/contrib/oss-fuzz/" 2>/dev/null || true
            ;;
        libxml2)
            mkdir -p "$TARGET/repo/oss-fuzz" 2>/dev/null || true
            ;;
    esac
}

# ---- apply magma's patches (setup + all bug patches) ----------------
# The bug-call sites are inside #ifdef MAGMA_ENABLE_CANARIES blocks,
# so with that macro undefined the canary calls preprocess out.
echo "[*] Applying magma setup + bug patches ..."
export TARGET
"$MAGMA_ROOT/magma/apply_patches.sh" 2>&1 | tail -5

# ---- compile flags --------------------------------------------------
# Crucially:
#   * no -include canary.h
#   * no -DMAGMA_ENABLE_CANARIES  → call sites are preprocessed out
#   * -DMAGMA_ENABLE_FIXES iff variant=patched
#   * no -l:magma.o linkage (we're not using LIBS at all for utilities)
FIXES_FLAG=""
[ "$VARIANT" = "patched" ] && FIXES_FLAG="-DMAGMA_ENABLE_FIXES"

export CC=gcc
export CXX=g++
export CFLAGS="$FIXES_FLAG -g -O0 -fno-omit-frame-pointer"
export CXXFLAGS="$CFLAGS"
export LDFLAGS=""
unset LIBS  # ensure no magma.o sneaks in

echo "[*] Building $TARGET_NAME ($VARIANT) ..."
echo "    CFLAGS: $CFLAGS"

cd "$TARGET/repo"

case "$TARGET_NAME" in
    libtiff)
        ./autogen.sh > "$WORK_DIR/autogen.log" 2>&1
        ./configure --disable-shared \
                    --prefix="$TARGET/work" \
                    > "$WORK_DIR/configure.log" 2>&1
        make -j"$(nproc)" clean > /dev/null
        make -j"$(nproc)" > "$WORK_DIR/make.log" 2>&1
        make install > "$WORK_DIR/install.log" 2>&1

        for util in tiffcp tiffinfo tiffdump tiff2pdf; do
            [ -f "$TARGET/work/bin/$util" ] && cp "$TARGET/work/bin/$util" "$OUT_DIR/"
        done
        ;;

    libxml2)
        ./autogen.sh \
            --with-http=no --with-python=no --with-lzma=yes \
            --with-threads=no --disable-shared \
            > "$WORK_DIR/autogen.log" 2>&1
        make -j"$(nproc)" clean > /dev/null
        make -j"$(nproc)" all > "$WORK_DIR/make.log" 2>&1

        # Static link of xmllint to avoid runtime libxml2 dep
        cp xmllint "$OUT_DIR/"
        # Also keep xmlcatalog as a second analysis surface
        [ -f xmlcatalog ] && cp xmlcatalog "$OUT_DIR/"
        ;;
esac

# ---- sanity checks: NO canary leakage ------------------------------
echo ""
echo "[*] Sanity checks for $TARGET_NAME-$VARIANT"
fail=0
for B in "$OUT_DIR"/*; do
    [ -x "$B" ] && [ -f "$B" ] || continue
    bn=$(basename "$B")
    nm_hits=$(nm -a "$B" 2>/dev/null | grep -ciE "magma_(log|init|protect|faulty|and|or)" || true)
    str_hits=$(strings "$B" | grep -cE "MAGMA_BUG|magma_log|Monitor not running|/magma_shared|MAGMA_STORAGE" || true)
    bug_hits=$(strings "$B" | grep -cE "(TIF|XML|PNG|PDF|SSL|SQL|PHP|LUA)[0-9]{3}" || true)
    afl_hits=$(nm -a "$B" 2>/dev/null | grep -c "__afl_" || true)

    status="CLEAN"
    if [ "$nm_hits" -gt 0 ] || [ "$str_hits" -gt 0 ] || [ "$bug_hits" -gt 0 ] || [ "$afl_hits" -gt 0 ]; then
        status="LEAK"
        fail=1
    fi
    printf "    %-20s nm-magma=%-3d str-magma=%-3d bug-ids=%-3d afl=%-3d  %s\n" \
        "$bn" "$nm_hits" "$str_hits" "$bug_hits" "$afl_hits" "$status"
done

if [ "$fail" = "1" ]; then
    echo ""
    echo "    >>> LEAK detected; do not use these binaries for blind eval."
    exit 6
fi

# Cleanup intermediate build artefacts so $FARAH stays small.
# Keep build logs for debugging.
mkdir -p "$WORK_DIR/_logs_kept"
mv "$WORK_DIR"/*.log "$WORK_DIR/_logs_kept/" 2>/dev/null || true
rm -rf "$TARGET/repo" "$TARGET/work"

echo ""
echo "[+] DONE: $OUT_DIR"
ls -la "$OUT_DIR"
