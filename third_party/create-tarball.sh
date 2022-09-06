#!/bin/bash
set -eo pipefail

# figure out the tag we're building. there can be only one
tag=$(git tag --points-at HEAD 'cyruslibs-v*')
if [ $(echo $tag | wc -w) -ne 1 ] ; then
  echo "E: not exactly one cyruslibs-vXX tag at this HEAD"
  exit 1
fi

# remove any leftovers from previous runs
rm -f everything.tar
find . -name submodule.tar -delete
rm -f cyruslibs-v*.tar*

# create the root tarball
git archive --format=tar --output=everything.tar HEAD

# create tarball for each submodule and add it to the root tarball
TOPDIR=$(pwd) git submodule --quiet foreach --recursive 'git archive --format=tar --prefix=$displaypath/ --output=submodule.tar HEAD ; cd $TOPDIR ; tar --concatenate --file=everything.tar $displaypath/submodule.tar ; rm -f $displaypath/submodule.tar'

# compress it
xz -9v everything.tar

# and name it
mv -v everything.tar.xz $tag.tar.xz

exit 0
