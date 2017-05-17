#!/bin/bash
#
# Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any legal
#    details, please contact
#      Carnegie Mellon University
#      Center for Technology Transfer and Enterprise Creation
#      4615 Forbes Avenue
#      Suite 302
#      Pittsburgh, PA  15213
#      (412) 268-7393, fax: (412) 268-7395
#      innovation@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#
# Script to configure and build Cyrus from a new git checkout,
# and run some tests.  Designed to be used from the Jenkins CI
# server as a build script.
#

function fatal()
{
    echo "$0: $*" 1>&2
    exit 1
}

## Ensure $PATH is right
PATH=/usr/bin:/bin:/usr/sbin:/usr/local/bin:$PATH

echo "==================== CYRUS IMAPD ===================="

if [ -n "$JENKINS_HOME" -a -n "$BUILD_ID" -a -n "$WORKSPACE" ] ; then
    echo "Invoked from Jenkins"
    CYRUS_SRC="$WORKSPACE/imapd"
    CYRUS_INST="$WORKSPACE/inst"
    CASSANDANE_SRC="$WORKSPACE/cassandane"
    # We want new files to be group-writable
    # so that the Cassandane tests running
    # as user 'cyrus' can write them
    umask 002
else
    [ -n "$CYRUS_YES_I_KNOW_WHAT_IM_DOING" ] || \
        fatal "Do not run $0 manually, use autoreconf -vi ; ./configure ; make"
    echo "Invoked manually"
    echo "(assumed, as one of \$JENKINS_HOME \$BUILD_ID or \$WORKSPACE is missing)"
    BUILD_ID=build$(date +%Y%m%dT%H%M%S)
    WORKSPACE=$(cd .. ; /bin/pwd)
    CYRUS_SRC=$(/bin/pwd)
    CYRUS_INST=$(cd ../inst ; /bin/pwd)
    CASSANDANE_SRC=$(cd ../cassandane ; /bin/pwd)
fi

echo "Build ID is $BUILD_ID"
echo "Workspace is $WORKSPACE"
echo " -  Cyrus IMAPD source in $CYRUS_SRC"
echo " -  Temporary Cyrus IMAPD installation will be in $CYRUS_INST"
echo " -  Cassandane test suite expected in $CASSANDANE_SRC"

TGGCOV=$(which tggcov 2>/dev/null)
HISTCOV=$(which git-history-coverage 2>/dev/null)
if [ -n "$TGGCOV" -a -x "$TGGCOV" ]; then
    echo "Found coverage tools, enabling coverage"
    echo " -  tggcov: $TGGCOV"
    echo " -  git-history-coverage: $HISTCOV"
    COVERAGE=--enable-coverage
else
    echo "No coverage tools found, disabling coverage"
    echo "(ggcov may be downloaded from ggcov.sourceforge.net)"
fi



COPTIMISEFLAGS="-O0"
CONFIGURE_ARGS="\
    --prefix=/usr/cyrus \
    --with-cyrus-prefix=/usr/cyrus \
    --with-ldap \
    --with-openssl \
    --enable-sieve \
    --enable-idled \
    --enable-nntp \
    --enable-murder \
    --enable-replication \
    --enable-unit-tests \
    --enable-maintainer-mode \
    $COVERAGE \
    "

NCPUS=$(grep '^processor' /proc/cpuinfo | wc -l)
[ $NCPUS -ge 1 ] || fatal "Can't get number of CPUs"

[ -d "$CYRUS_SRC" ] || fatal "$CYRUS_SRC: no such directory"
cd "$CYRUS_SRC" || fatal "$CYRUS_SRC: cannot cd"
[ -d .git ] || fatal "$CYRUS_SRC: not a git repository"
nfiles=$(git ls-files|wc -l)
[ $nfiles -gt 0 ] || fatal "$CYRUS_SRC: cannot list git controlled files"

BRANCH=$(git branch | sed -n -e 's/^\*[ \t]\+//p')
[ -n "$BRANCH" ] || fatal "Can't get git branch"
[ "$BRANCH" != "(no branch)" ] || fatal "Not on any git branch"
COMMIT=$(git log --pretty='format:%h' HEAD^..HEAD|head -1)
[ -n "$COMMIT" ] || fatal "Can't get git top commit"
echo "Building on git branch $BRANCH, top commit $COMMIT"
CONFIGURE_ARGS="--with-extraident=$BRANCH-$COMMIT $CONFIGURE_ARGS"

set -x
git ls-files -o
git status


# do the whole autotools dance
[ -f Makefile ] && make maintainer-clean
autoreconf -i -f -v || fatal "Can't run autoreconf"
[ -f configure ] || fatal "autoconf did not produce a configure script"
CFLAGS="-g -W -Wall -Wextra" ./configure $CONFIGURE_ARGS || fatal "Cannot run configure"
[ -f config.status ] || fatal "configure did not produce a config.status script"
# Tweak makefiles for optimisation flags
perl -p -i.orig -e 's/^(CFLAGS\s*=\s*.*)\s+-O2/\1 '"$COPTIMISEFLAGS"'/' $mf $(find . -name Makefile)

# Finally the actual build
make -j$NCPUS all || fatal "Can't make all"

# Run CUnit based unit tests
# [ -n "$COVERAGE" ] && find . -name '*.gcda' -exec rm '{}' \;
make CUFORMAT=junit check || fatal "Can't make check"

# Do a temporary install for Cassandane
[ -d $CYRUS_INST.old ] && rm -rf $CYRUS_INST.old
[ -d $CYRUS_INST ] && mv -f $CYRUS_INST $CYRUS_INST.old
mkdir -p $CYRUS_INST || fatal "$CYRUS_INST: can't mkdir"
make DESTDIR=$CYRUS_INST install || fatal "Can't install"

exitcode=0

# Run Cassandane tests
if [ -d $CASSANDANE_SRC ]; then

## Not needed anymore, user cyrus is in group tomcat
#     if [ -n "$COVERAGE" ]; then
#       chmod 666 $(find . -type f -name '*.gcda')
#     fi

    # Shoot down any leftover processes - Cassandane sometimes
    # leaks these under mysterious circumstances.  Sadly this means
    # we cannot run two autobuilds in parallel, oh well :(
    # The -n is to prevent sudo going interactive.
    sudo -n /usr/bin/killall -u cyrus

    # TODO: factor this out into a shell function
    cd "$CASSANDANE_SRC" || fatal "$CASSANDANE_SRC: cannot cd"
    [ -d .git ] || fatal "$CASSANDANE_SRC: not a git repository"
    nfiles=$(git ls-files|wc -l)
    [ $nfiles -gt 0 ] || fatal "$CASSANDANE_SRC: cannot list git controlled files"

    git ls-files -o
    git status

    make || fatal "Can't make in cassandane/";

    # Build cassandane.ini
    sed -e 's|^##destdir =.*$|destdir = '$CYRUS_INST'|' \
        -e 's|^##pwcheck = .*$|pwcheck = sasldb|' \
        < cassandane.ini.example \
        > cassandane.ini

    rm -rf reports.old
    mv -f reports reports.old
    mkdir -m 0777 reports || fatal "Can't mkdir reports"

    ./testrunner.pl --cleanup -f xml -v > cass.errs 2>&1 || exitcode=1

    [ -x jenkins-xml-summary.pl ] && ./jenkins-xml-summary.pl ${BUILD_URL:+--build-url=$BUILD_URL}

    # Shoot down leftover processes again
    ps -u cyrus
    sudo -n /usr/bin/killall -u cyrus

    cd "$CYRUS_SRC"
fi

# Report on coverage
# [ -n "$COVERAGE" ] && $TGGCOV --report=summary_all -r .  2>/dev/null
[ -n "$COVERAGE" ] && $TGGCOV --report=cobertura -r . 2>/dev/null > coverage.xml

# The first line in this file is like
# Changes in branch origin/for-upstream, between $SHA and $SHA
if [ -n "$JENKINS_HOME" ] ; then
revlist=$(perl \
    -n \
    -e 's/^Changes .*between ([[:xdigit:]]{40}) and ([[:xdigit:]]{40})/\1..\2/; print; exit 0;' \
    $WORKSPACE/../builds/$BUILD_ID/changelog.xml \
    2>/dev/null)
[ -n "$revlist" ] && $HISTCOV $revlist 2>/dev/null
fi

exit $exitcode
