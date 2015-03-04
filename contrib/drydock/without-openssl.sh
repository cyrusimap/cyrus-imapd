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

autoreconf -vi || exit 3

./configure --enable-maintainer-mode || exit 124

# Once normally
./configure --with-openssl=no || exit 4

# Work around a broken lex (??)
make sieve/sieve-lex.c && \
    sed -r -i \
        -e 's/int yyl;/yy_size_t yyl;/' \
        -e 's/\tint i;/\tyy_size_t i;/' \
        sieve/sieve-lex.c

make -j4 || exit 5

make clean

# Once with -Werror
CFLAGS="-g -fPIC -W -Wall -Wextra -Werror"
export CFLAGS
./configure --with-openssl=no || exit 6

# Work around a broken lex (??)
make sieve/sieve-lex.c && \
    sed -r -i \
        -e 's/int yyl;/yy_size_t yyl;/' \
        -e 's/\tint i;/\tyy_size_t i;/' \
        sieve/sieve-lex.c

make -j4 || exit 7

