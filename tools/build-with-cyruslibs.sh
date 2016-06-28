#!/bin/bash

CYRUSLIBS=cyruslibs
PREFIX=/usr/local/$CYRUSLIBS
export LDFLAGS="-L$PREFIX/lib/x86_64-linux-gnu -L$PREFIX/lib -Wl,-rpath,$PREFIX/lib/x86_64-linux-gnu -Wl,-rpath,$PREFIX/lib"
export PKG_CONFIG_PATH="$PREFIX/lib/x86_64-linux-gnu/pkgconfig:$PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH"
export CFLAGS="-g -fPIC -W -Wall -Wextra"
autoreconf -v -i
./configure --prefix=/usr/cyrus --with-cyrus-prefix=/usr/cyrus --enable-http --enable-calalarmd --enable-unit-tests --enable-replication --enable-nntp --enable-murder --enable-idled --enable-xapian XAPIAN_CONFIG=$PREFIX/bin/xapian-config-1.3
make lex-fix
make -j 8
make -j 8 check
sudo make install
sudo make install-binsymlinks
sudo cp tools/mkimap /usr/cyrus/bin/mkimap

