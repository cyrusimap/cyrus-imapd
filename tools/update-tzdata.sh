#!/bin/sh
#
# Replace tzdata/ with a newer IANA time zone database release.
#
# The tzdata/ directory holds an unmodified IANA release.  Do not patch it:
# any Cyrus-specific behaviour belongs in the build rules or in vzic, not in
# the data.  "make" converts this data to VTIMEZONEs with vzic, then indexes
# the result with cyr_guesstz.
#
# Usage: tools/update-tzdata.sh <version>
#
# e.g. tools/update-tzdata.sh 2026d
#
# Releases are at https://www.iana.org/time-zones -- we want the data-only
# tarball (tzdataVERSION.tar.gz), not the code.

set -e

if [ $# -ne 1 ]; then
    echo "usage: $0 <version>" >&2
    exit 64
fi

version=$1
topdir=$(git rev-parse --show-toplevel)
tarball=tzdata$version.tar.gz
url=https://data.iana.org/time-zones/releases/$tarball

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "fetching $url"
curl -sSfL -o "$tmpdir/$tarball" "$url"

cd "$topdir"
git rm -r -q tzdata
mkdir tzdata
tar -C tzdata -x -f "$tmpdir/$tarball"

# Sanity check: the release should say what it is.
got=$(cat tzdata/version)
if [ "$got" != "$version" ]; then
    echo "expected tzdata/version to read $version, got $got" >&2
    exit 1
fi

git add tzdata

# A .gitignore rule can silently drop a file from "git add", so check that
# everything we extracted made it into the index.
ondisk=$(find tzdata -type f | wc -l)
staged=$(git ls-files tzdata | wc -l)
if [ "$ondisk" -ne "$staged" ]; then
    echo "git add staged $staged of the $ondisk files in tzdata:" >&2
    git status --short --ignored tzdata >&2
    exit 1
fi

echo
echo "tzdata updated to $version.  Now:"
echo "  git commit -m 'tzdata: update to IANA $version'"
echo "  make && make check"
