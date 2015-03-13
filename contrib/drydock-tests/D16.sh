#!/bin/bash
#
# This script tests the fix applied in D16 / T83:
#
#   - https://git.cyrus.foundation/D16
#   - https://git.cyrus.foundation/T83

. contrib/drydock-functions.sh

_git_clean

_git_checkout_commit

_autoreconf

function test_fail() {
    description=$1
    expected=$2
    got=$3

    echo "Test failed: expected $description '$expected', got '$got'"
    exit 1
}

function test_path() {
    expect_prefix=$1
    expect_exec_prefix=$2
    expect_bindir=$3
    expect_sbindir=$4
    expect_libexecdir=$5

    shift; shift; shift; shift; shift

    echo "============================================================="
    echo "Testing options: '$@'"
    echo "============================================================="
    _configure "$@"

    eval "$(grep -E '^(exec_|)prefix=' config.log)"
    eval "$(grep -E '^(bin|sbin|libexec)dir=' config.log)"

    test "${prefix}" == "${expect_prefix}" ||
	test_fail 'prefix' $expect_prefix $prefix
    test "${exec_prefix}" == "${expect_exec_prefix}" ||
	test_fail 'exec_prefix' $expect_exec_prefix $exec_prefix
    test "${bindir}" == "${expect_bindir}" ||
	test_fail 'bindir' $expect_bindir $bindir
    test "${sbindir}" == "${expect_sbindir}" ||
	test_fail 'sbindir' $expect_sbindir $sbindir
    test "${libexecdir}" == "${expect_libexecdir}" ||
	test_fail 'libexecdir' $expect_libexecdir $libexecdir
}

test_path \
    '/usr/local' \
    '${prefix}' \
    '${exec_prefix}/bin' \
    '${exec_prefix}/sbin' \
    '${exec_prefix}/libexec'

test_path \
    '/usr' \
    '${prefix}' \
    '${exec_prefix}/bin' \
    '${exec_prefix}/sbin' \
    '${exec_prefix}/libexec' \
     --prefix=/usr

test_path \
    '/usr' \
    '${prefix}' \
    '${exec_prefix}/bin' \
    '${exec_prefix}/sbin' \
    '/usr/lib' \
    --prefix=/usr \
    --libexecdir=/usr/lib

test_path \
    '/usr/local' \
    '${prefix}' \
    '/some/other/bindir' \
    '/some/other/sbindir' \
    '/some/other/libexecdir' \
    --prefix=/usr/local  \
    --bindir=/some/other/bindir \
    --sbindir=/some/other/sbindir \
    --libexecdir=/some/other/libexecdir

