#!/bin/sh
#
# xversion.sh: extract the timestamp from the $Id: xversion.sh,v 1.1 2001/10/22 16:33:34 ken3 Exp $ string
# in every source file and use the most recent as the CVSDATE
#
# $Id: xversion.sh,v 1.1 2001/10/22 16:33:34 ken3 Exp $

DATEPAT=[1-2][0-9][0-9][0-9]/[0-1][0-9]/[0-3][0-9]
TIMEPAT=[0-2][0-9]:[0-5][0-9]:[0-5][0-9]

echo "/* Generated automatically by xversion.sh */" > xversion.h
echo >> xversion.h

echo -n "#define CVSDATE " >> xversion.h

find .. -name '*.[chly]' -print | \
	xargs egrep '\$Id: xversion.sh,v 1.1 2001/10/22 16:33:34 ken3 Exp $' | \
	awk ' # extract timestamp and surround with quotes
	match ($0, pattern) {
	    printf "\"%s\"\n", substr($0, RSTART, RLENGTH)
	}' pattern="$DATEPAT $TIMEPAT" | \
	sort | tail -1 >> xversion.h
