#!/bin/bash

if [ -z "${uri}" ]; then
    uri=$1
fi

if [ -z "${commit}" ]; then
    commit=$2
    export commit
fi

for script in `find contrib/drydock-tests/ -type f -name "*.sh" | sort`; do
    if [ -x $script ]; then
        ./$script 2>&1 || exit $?
    else
        echo "Skipping $script"
    fi
done
