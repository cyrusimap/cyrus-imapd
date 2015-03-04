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

function test_fail() {
    echo "test failed (expected $1 but got $2)"
    shift; shift
    echo "  configure options: $@"
    exit 1
}

function test_path() {
    sdir=$1
    udir=$2
    cdir=$3

    shift; shift; shift

    echo "============================================================="
    echo "Testing options: $@"
    echo "============================================================="
    ./configure "$@"

    eval "$(grep -E '^(service|user)dir=' config.log)"

    cyrus_path=$(grep 'define CYRUS_PATH' config.h | awk -F'"' '{print $2}')

    servicedir_config_h=$(grep 'define SERVICE_DIR' config.h | awk -F'"' '{print $2}')

    test "${servicedir_config_h}" == "${servicedir}" || test_fail $servicedir_config_h $servicedir $@

    test "${servicedir}" == "${sdir}" || test_fail $sdir $servicedir $@
    test "${userdir}" == "${udir}" || test_fail $udir $userdir $@
    test "${cyrus_path}" == "${cdir}" || test_fail $cdir $cyrus_path $@
}

test_path \
    "/usr/local/cyrus/bin" \
    "/usr/local/cyrus/bin" \
    "/usr/local/cyrus"

test_path \
    "/usr/cyrus/bin" \
    "/usr/cyrus/bin" \
    "/usr/cyrus" \
     --prefix=/usr

test_path \
    "/with/cyrus/prefix/bin" \
    "/with/cyrus/prefix/bin" \
    "/with/cyrus/prefix" \
    --with-cyrus-prefix=/with/cyrus/prefix

test_path \
    "/with/service/path" \
    "/with/service/path" \
    "/with/cyrus/prefix" \
    --with-cyrus-prefix=/with/cyrus/prefix \
    --with-service-path=/with/service/path

test_path \
    "/usr/local/bin" \
    "/usr/local/bin" \
    "/usr/local/cyrus" \
    --with-service-path=/usr/local/bin
