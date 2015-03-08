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

./configure --enable-maintainer-mode || exit 124

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

