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
        echo "Running script $script"
        ./$script 2>&1; retval=$?
    else
        echo "Skipping $script"
    fi

    if [ ${retval} -ne 0 ]; then
        echo "Script ./$script FAILED"
        exit ${retval}
    fi
done
