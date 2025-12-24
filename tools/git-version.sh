#!/bin/sh
# Generate a version string for cyrus-imapd
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# if we've come from a release package, ignore git entirely
test -s VERSION &&
    exec head -1 VERSION

# first try: based on annotated git tags (real releases)
version=$(git describe --dirty=-dirty --match 'cyrus-imapd-*' 2>/dev/null)
test -n "$version" &&
    version=$(echo "$version" | sed -e 's/^cyrus-imapd-//')

# second try: lightweight git tags
test -z "$version" &&
    version=$(git describe --dirty=-dirty --tags 2>/dev/null)

# third try: probably not a git repository
test -z "$version" &&
    version=unknown

echo $version
