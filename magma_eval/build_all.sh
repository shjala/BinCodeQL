#!/bin/bash
# build_all.sh — drive build_clean.sh across the planned (target, variant) set.
#
# Builds the four binaries needed for the magma evaluation:
#   libtiff vuln, libtiff patched, libxml2 vuln, libxml2 patched.
#
# Output:  /home/sanjay/san-home/research/tii/tii24/tmp/farah-magma/<target>-<variant>/
# Each row of the summary printed at the end reports CLEAN / LEAK / FAIL.
#
# Sequential by default to keep CPU manageable; flip PARALLEL=1 to run them
# concurrently if you have RAM and cores to spare.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILDER="$DIR/build_clean.sh"
LOG_DIR=/home/sanjay/san-home/research/tii/tii24/tmp/farah-magma/_build_logs
mkdir -p "$LOG_DIR"

PLAN=(
    "libtiff vuln"
    "libtiff patched"
    "libxml2 vuln"
    "libxml2 patched"
)

PARALLEL="${PARALLEL:-0}"

run_one() {
    local target="$1" variant="$2"
    local key="${target}-${variant}"
    local log="$LOG_DIR/$key.log"
    echo "[*] $key — log: $log"
    if "$BUILDER" "$target" "$variant" > "$log" 2>&1; then
        echo "    OK"
        return 0
    else
        echo "    FAIL (exit $?)"
        return 1
    fi
}

declare -A RESULTS
START=$(date +%s)

if [ "$PARALLEL" = "1" ]; then
    for entry in "${PLAN[@]}"; do
        read -r target variant <<<"$entry"
        ( run_one "$target" "$variant" && \
          echo "OK ${target}-${variant}" || \
          echo "FAIL ${target}-${variant}" ) &
    done
    wait
else
    for entry in "${PLAN[@]}"; do
        read -r target variant <<<"$entry"
        if run_one "$target" "$variant"; then
            RESULTS["${target}-${variant}"]="OK"
        else
            RESULTS["${target}-${variant}"]="FAIL"
        fi
    done
fi

ELAPSED=$(( $(date +%s) - START ))

echo ""
echo "============================================================"
echo "BUILD SUMMARY (elapsed: ${ELAPSED}s)"
echo "============================================================"
for entry in "${PLAN[@]}"; do
    read -r target variant <<<"$entry"
    key="${target}-${variant}"
    status="${RESULTS[$key]:-?}"
    printf "  %-25s %s\n" "$key" "$status"
done

# Final cross-binary leak audit so we have a single source of truth.
echo ""
echo "------------------------------------------------------------"
echo "FINAL LEAK AUDIT (across all built binaries)"
echo "------------------------------------------------------------"
FARAH=/home/sanjay/san-home/research/tii/tii24/tmp/farah-magma
clean_count=0
leak_count=0
for D in "$FARAH"/{libtiff,libxml2}-{vuln,patched}; do
    [ -d "$D" ] || continue
    for B in "$D"/*; do
        [ -x "$B" ] && [ -f "$B" ] || continue
        bn=$(basename "$D")/$(basename "$B")
        nm_hits=$(nm -a "$B" 2>/dev/null | grep -ciE "magma_(log|init|protect|faulty|and|or)" || true)
        str_hits=$(strings "$B" | grep -cE "MAGMA_BUG|magma_log|Monitor not running|/magma_shared|MAGMA_STORAGE" || true)
        bug_hits=$(strings "$B" | grep -cE "(TIF|XML|PNG|PDF|SSL|SQL|PHP|LUA)[0-9]{3}" || true)

        if [ "$nm_hits" = "0" ] && [ "$str_hits" = "0" ] && [ "$bug_hits" = "0" ]; then
            printf "  %-50s CLEAN\n" "$bn"
            clean_count=$((clean_count + 1))
        else
            printf "  %-50s LEAK (nm=%d str=%d bug=%d)\n" "$bn" "$nm_hits" "$str_hits" "$bug_hits"
            leak_count=$((leak_count + 1))
        fi
    done
done

echo ""
echo "Total: $clean_count clean, $leak_count leaked"
[ "$leak_count" = "0" ] || exit 1
