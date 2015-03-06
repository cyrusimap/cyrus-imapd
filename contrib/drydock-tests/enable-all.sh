#!/bin/bash
#
# This script tests the fix applied in D7 / T26:
#
#   - https://git.cyrus.foundation/D7
#   - https://git.cyrus.foundation/T26

git clean -d -f -x || exit 2

if [ ! -z "${commit}" ]; then
    git checkout -f ${commit} || exit 2
fi

_autoreconf

./configure \
    --enable-autocreate \
    --enable-coverage \
    --enable-gssapi \
    --enable-http \
    --enable-idled \
    --enable-maintainer-mode \
    --enable-murder \
    --enable-nntp \
    --enable-replication \
    --enable-unit-tests \
    --with-ldap=/usr
    || exit 124

# Once normally
./configure --with-openssl=no || exit 4

make lex-fix
make -j4 || exit 5

make clean

# Once with -Werror
CFLAGS="-g -fPIC -W -Wall -Wextra -Werror"
export CFLAGS
./configure --with-openssl=no || exit 6

make lex-fix
make -j4 || exit 7

