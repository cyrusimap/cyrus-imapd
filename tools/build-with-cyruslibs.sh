#!/bin/bash

set -e

echo "::group::configure cyrus-imapd"
: ${CYRUSLIBS:=cyruslibs}
: ${LIBSDIR:=/usr/local/$CYRUSLIBS}
: ${TARGET:=/usr/cyrus}
: ${CONFIGOPTS:="--enable-jmap --enable-http --enable-calalarmd --enable-unit-tests --enable-replication --enable-nntp --enable-murder --enable-idled --enable-xapian --enable-autocreate --enable-silent-rules --enable-debug-slowio"}
export LDFLAGS="-L$LIBSDIR/lib/x86_64-linux-gnu -L$LIBSDIR/lib -Wl,-rpath,$LIBSDIR/lib/x86_64-linux-gnu -Wl,-rpath,$LIBSDIR/lib"
export PKG_CONFIG_PATH="$LIBSDIR/lib/x86_64-linux-gnu/pkgconfig:$LIBSDIR/lib/pkgconfig:\$PKG_CONFIG_PATH"
export CFLAGS="-g -fPIC -W -Wall -Wextra -Werror -Wwrite-strings"
export CXXFLAGS="-g -fPIC -W -Wall -Wextra -Werror"
export PATH="$LIBSDIR/bin:$PATH"
autoreconf -v -i
echo "./configure --prefix=$TARGET $CONFIGOPTS XAPIAN_CONFIG=$LIBSDIR/bin/xapian-config-1.5"
./configure --prefix=$TARGET $CONFIGOPTS XAPIAN_CONFIG=$LIBSDIR/bin/xapian-config-1.5
make lex-fix
echo "::endgroup::"

echo "::group::make cyrus-imapd"
make -j 8
echo "::endgroup::"

echo "::group::check cyrus-imapd"
make -j 8 check
echo "::endgroup::"

echo "::group::install cyrus-imapd"
sudo make install
sudo make install-binsymlinks
sudo cp tools/mkimap /usr/cyrus/bin/mkimap
echo "::endgroup::"
