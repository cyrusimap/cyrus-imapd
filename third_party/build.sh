#!/bin/bash

set -e

NAME=${1:-cyruslibs}
ITEM=$2
PREFIX=/usr/local/$NAME
MAKEOPTS="-j 8"

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH"
export LDFLAGS="-Wl,-rpath,$PREFIX/lib -Wl,-rpath,$PREFIX/lib/x86_64-linux-gnu"
export PATH=$PREFIX/bin:$PATH

git submodule init
git submodule update

if [ ! $ITEM ] || [ $ITEM == re2 ] ; then
(
  cd re2
  git clean -f -x -d
  make -e prefix=$PREFIX $MAKEOPTS
  make -e prefix=$PREFIX $MAKEOPTS test
  sudo make -e prefix=$PREFIX $MAKEOPTS install
  make -e prefix=$PREFIX testinstall
  
)
fi

if [ ! $ITEM ] || [ $ITEM == cre2 ] ; then
(
  cd cre2
  git clean -f -x -d
  sh autogen.sh
  mkdir build
  cd build
  ../configure --enable-silent-rules --enable-maintainer-mode --prefix=$PREFIX
  make $MAKEOPTS
  make $MAKEOPTS check
  sudo make $MAKEOPTS install
  make $MAKEOPTS installcheck
)
fi

if [ ! $ITEM ] || [ $ITEM == icu ] ; then
(
  cd icu
  git clean -f -x -d
  cd icu4c/source
  mkdir -p data/out/tmp
  ./configure --enable-silent-rules --with-data-packaging=archive --prefix=$PREFIX
  make $MAKEOPTS
  sudo make install
)
fi

if [ $ITEM == zeroskip ] ; then
(
  cd zeroskip
  git clean -f -x -d
  autoreconf -v -i
  ./configure --prefix=$PREFIX
  make $MAKEOPTS
  sudo make install
)
fi

if [ ! $ITEM ] || [ $ITEM == jansson ] ; then
(
  cd jansson
  git clean -f -x -d
  autoreconf -v -i
  ./configure --enable-silent-rules --prefix=$PREFIX
  make $MAKEOPTS
  sudo make install
)
fi

# XXX - can we find the platform?
if [ ! $ITEM ] || [ $ITEM == libical ] ; then
(
  cd libical
  git clean -f -x -d
  mkdir build
  cd build
  cmake -DCMAKE_INSTALL_PREFIX=$PREFIX -DICU_ROOT=$PREFIX -DENABLE_GTK_DOC=OFF \
        -DUSE_BUILTIN_TZDATA=true \
        -DCMAKE_SKIP_RPATH=ON -DICAL_ALLOW_EMPTY_PROPERTIES=true ..
  make $MAKEOPTS
  sudo make install
)
fi

if [ ! $ITEM ] || [ $ITEM == vzic ] ; then
(
  cd vzic
  git clean -f -x -d
  TZID_PREFIX="" CREATE_SYMLINK=0 IGNORE_TOP_LEVEL_LINK=0 make
  sudo cp vzic $PREFIX/bin
)
fi

if [ ! $ITEM ] || [ $ITEM == timezones ] ; then
(
  cd cyrus-timezones
  git clean -f -x -d
  autoreconf -i
  PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$PREFIX/lib/pkgconfig ./configure --prefix=$PREFIX
  make $MAKEOPTS
  make check
  sudo make install
)
fi

if [ ! $ITEM ] || [ $ITEM == xapian ] ; then
(
  cd xapian
  git clean -f -x -d
  git checkout -B build  # needed so sub-checkouts can find their references
  ./bootstrap --download-tools=never
  ./configure --enable-silent-rules --prefix=$PREFIX
  cd xapian-core
  make $MAKEOPTS
  sudo make install
)
fi

if [ ! $ITEM ] || [ $ITEM == wslay ] ; then
(
  cd wslay
  git clean -f -x -d
  autoreconf -i
  automake
  autoconf
  ./configure --enable-silent-rules --prefix=$PREFIX
  make
  sudo make install
)
fi

if [ ! $ITEM ] || [ $ITEM == libchardet ] ; then
(
  cd libchardet
  git clean -f -x -d
  autoreconf -i
  automake
  autoconf
  ./configure --enable-silent-rules --prefix=$PREFIX
  make
  sudo make install $MAKEOPTS
)
fi

if [ ! $ITEM ] || [ $ITEM == cld2 ] ; then
(
  cd cld2
  git clean -f -x -d
  ./build.sh
  sudo ./install.sh --prefix=$PREFIX
)
fi
