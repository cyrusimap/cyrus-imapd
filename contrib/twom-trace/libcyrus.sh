# libcyrus.sh - locate the libcyrus the running cyrus is actually using.
# Sourced by twom-capture, twom-rate, twom-hitmiss and dbbench-build.
#
# Deliberately does not assume any particular install layout: it asks the
# running processes rather than guessing at paths. LIB= overrides everything,
# which is also how the benchmark's private libtwom.so gets traced.

find_libcyrus() {
    if [ -n "${LIB:-}" ]; then
        [ -e "$LIB" ] || { echo "LIB=$LIB does not exist" >&2; return 1; }
        printf '%s\n' "$LIB"; return 0
    fi

    # Prefer a process that maps libcyrus itself.
    local p hit
    for p in /proc/[0-9]*; do
        hit=$(awk '$NF ~ /\/libcyrus\.so/ { print $NF; exit }' "$p/maps" 2>/dev/null)
        [ -n "$hit" ] && { printf '%s\n' "$hit"; return 0; }
    done

    # cyrus master only maps libcyrus_min, so fall back to its directory.
    local dir
    for p in /proc/[0-9]*; do
        hit=$(awk '$NF ~ /\/libcyrus[_.a-z]*\.so/ { print $NF; exit }' "$p/maps" 2>/dev/null)
        [ -n "$hit" ] || continue
        dir=${hit%/*}
        for cand in "$dir"/libcyrus.so.0 "$dir"/libcyrus.so; do
            [ -e "$cand" ] && { printf '%s\n' "$cand"; return 0; }
        done
    done

    echo "cannot find libcyrus in any running process; is cyrus running?" >&2
    echo "pass LIB=/path/to/libcyrus.so.0 to override." >&2
    return 1
}

check_twom_symbols() {
    local lib=$1
    nm "$lib" 2>/dev/null | grep -q ' twom_db_fetch$' && return 0
    echo "no twom symbols in $lib - stripped build, or too old for twom." >&2
    return 1
}
