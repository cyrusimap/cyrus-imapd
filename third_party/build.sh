#!/bin/bash

set -e

NAME=${1:-cyruslibs}
PREFIX=/usr/local/$NAME
MAKEOPTS="-j 8"

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH"
export LDFLAGS="-Wl,-rpath,$PREFIX/lib -Wl,-rpath,$PREFIX/lib/x86_64-linux-gnu"
export PATH=$PREFIX/bin:$PATH

git submodule init
git submodule update

(
  cd icu4c
  git clean -f -x -d
  cd source
  ./configure --enable-silent-rules --with-data-packaging=archive --prefix=$PREFIX
  make $MAKEOPTS
  sudo make install
)

(
  cd jansson
  git clean -f -x -d
  autoreconf -v -i
  ./configure --enable-silent-rules --prefix=$PREFIX
  make $MAKEOPTS
  sudo make install
)

(
  cd opendkim
  git clean -f -x -d
  autoreconf -v -i
  ./configure --enable-silent-rules --prefix=$PREFIX
  make $MAKEOPTS
  sudo make install
)

# XXX - can we find the platform?
(
  cd libical
  git clean -f -x -d
  mkdir build
  cd build
  cmake -DCMAKE_INSTALL_PREFIX=$PREFIX -DICU_BASE=$PREFIX \
        -DCMAKE_SKIP_RPATH=ON -DICAL_ALLOW_EMPTY_PROPERTIES=true ..
  make $MAKEOPTS
  sudo make install
)

(
  cd xapian
  git clean -f -x -d
  ./bootstrap
  ./configure --enable-silent-rules --prefix=$PREFIX
  make $MAKEOPTS
  sudo make install
)

