#!/bin/bash

for script in `find contrib/drydock/ -type f -name "*.sh" | sort`; do
    ./$script || exit $?
done
