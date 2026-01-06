#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# This script should be sourced from the command line or from within .bashrc

cyr_cd() {
    set -- `mbpath $@`
    if test $# -ne 0
    then
        cd "$@"
    fi
}
