#!/bin/bash
# 
# This script applies the standard operating procedure to build a
# release tarball.

CFLAGS="-g -fPIC -W -Wall -Wextra -Werror"
export CFLAGS

# Figure out the branch so we can figure out the product series
for branch in `git branch --contains ${commit} | sed -e 's/  //g' -e 's/* //g'`; do
    git checkout ${branch}

    cbranch=$(git rev-parse --abbrev-ref HEAD)

    # Abbreviate the version number using the branch name
    if [ "${cbranch}" == "master" ]; then
        mmver="3.0"
    else
        mmver=${cbranch:-3}
    fi

    # $mmver is now 3.0 (master), 2.5, 2.4, etc.

    # Find the latest tag for the product series, if any
    tag=$(git tag -l | grep cyrus-imapd-${mmver}. | sort --version-sort | tail -n 1)

    if [ -z "${tag}" ]; then
        tag="3.0-dev"
        # This is the last known no-diff commit of the cyrus-imapd-2.5 branch-off point
        patchlevel=$(git log ${commit}..9fcf65cd249fa0d1f7f575f6de8fd0667bab32ec --pretty=oneline | wc -l)
        version="${tag}${patchlevel}"
    else
        patchlevel=$(git log ${commit}..${tag} --pretty=oneline | wc -l)
        version="${tag:-5}.${patchlevel}"
    fi

    # $version is now "3.0-dev45" or "2.5.0.16" or something
    if [ ! -z "$(git log ${commit}..HEAD 2>/dev/null)" ]; then
        git checkout ${commit}
    fi

    git clean -d -f -x

    autoreconf -vi || exit 123
    ./configure --enable-maintainer-mode || exit 124

    # Work around a broken lex (??)
    make sieve/sieve-lex.c && \
        perl -p -i -e "s/int yyl;/yy_size_t yyl;/" sieve/sieve-lex.c

    make -j4 || exit 125
    make dist || exit 126

    # Repack the tarball
    rm -rf cyrus-imapd-*.tar.bz2

    if [ ! -f "cyrus-imapd-${version}.tar.gz" ]; then
        tar zxvf cyrus-imapd-*.tar.gz
        rm -rf cyrus-imapd-*.tar.gz
        mv cyrus-imapd-*/ cyrus-imapd-${version}
    fi

    pushd cyrus-imapd-${version}/

    ./configure || exit 224
    make || exit 225

    popd

    for file in `git ls-files`; do
        if [ ! -f cyrus-imapd-${version}/$file ]; then
            echo "File cyrus-imapd-${version}/$file is missing"
        fi
    done
done
