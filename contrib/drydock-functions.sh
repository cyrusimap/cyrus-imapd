#!/bin/bash

function _autoreconf {
    # Escape libtoolize --copy from failing on el6
    autoreconf -vi || (libtoolize && autoreconf -vi)
}

function _configure {
    ./configure $@
}

function _git_clean {
    git clean -d -f -x
}

function _git_checkout_commit {
    if [ -z "${commit}" ]; then
        # TODO - check for a buildable
    else
        # If there is no other commits we don't need to check it out at all
        if [ ! -z "$(git log ${commit}..HEAD --pretty=oneline 2>/dev/null)" ]; then
            git checkout -f ${commit}
        fi
    fi
}

