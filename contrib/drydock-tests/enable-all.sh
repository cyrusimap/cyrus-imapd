#!/bin/bash
#
# This script tests the fix applied in D7 / T26:
#
#   - https://git.cyrus.foundation/D7
#   - https://git.cyrus.foundation/T26

. contrib/drydock-functions.sh

_git_clean

_git_checkout_commit

_autoreconf

./configure \
    --enable-calalarmd \
    --enable-coverage \
    --enable-gssapi \
    --enable-http \
    --enable-idled \
    --enable-maintainer-mode \
    --enable-murder \
    --enable-nntp \
    --enable-replication \
    --enable-unit-tests \
    --with-ldap=/usr || \
    exit 124

make lex-fix
make -j4 || :
make check || :

